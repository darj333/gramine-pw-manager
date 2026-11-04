#!/usr/bin/env python3
"""Trial planner / runner / sanity-summary for the Argon2id-vs-EPC experiment.

Subcommands
  plan     build a seeded, randomized, interleaved trial list (plan.json)
  builds   print the distinct manifest builds the plan needs (shell script)
  meta     capture the environment (kernel, CPU, SGX devices, versions, ...)
  run      execute a plan, one fresh subprocess per trial, append JSONL
  summary  per-cell medians + cross-environment digest correctness check

Design rules (each one is a lesson from earlier phases of this project):
  * never discard a child's stderr (Phase 3b, Class 7): it is stored with
    every trial that wrote anything to it, and always for failures
  * every setting that changes a build is part of the logged plan
  * run order is randomized and interleaved across ALL cells and
    environments from a logged seed (Mytkowicz et al., ASPLOS 2009), so
    drift (thermal, neighbours, page cache) is not confounded with m or env
  * the grid is defined relative to the MEASURED EPC size, never in absolute
    MB, so RQ2 (does the knee coincide with EPC capacity?) is testable on
    whatever SKU was provisioned
"""
import argparse
import hashlib
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
VENV_PY = os.path.join(HERE, "venv", "bin", "python3")
BENCH_SCRIPT = os.path.join(HERE, "bench_kdf.py")

# Fractions of the measured EPC (E). The dense band around 1.0 is where the
# model predicts a knee (m* ~ E_eff); the low end is the cache/TLB regime.
DEFAULT_RATIOS = [0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 0.75,
                  0.9, 1.0, 1.1, 1.25, 1.5]
CONTROL_RATIOS = [0.1, 0.5, 1.0, 1.5]          # where t=1 / p=1 controls run
# Absolute parameter sets from the literature (RFC 9106, OWASP, Tippe & Berner)
REFERENCE_MIB = [4, 19, 64, 2048]

ENVS = ("native", "direct", "sgx-static", "sgx-edmm")


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def round_m_kib(m_kib, p):
    """Argon2 works in 4*p-block units; use values that are exact multiples
    so requested m == effective m."""
    unit = 4 * p
    return max(8 * p, int(math.ceil(m_kib / unit)) * unit)


def next_pow2_gib(mib):
    gib = max(1, math.ceil(mib / 1024))
    return 1 << (gib - 1).bit_length()


def enclave_size_for(m_kib, overhead_mib):
    """Static-mode enclave size: next power-of-two GiB >= m + overhead.
    Power-of-two is the historical SGX1 requirement; whether the pinned
    Gramine version still needs it is unverified. overhead_mib is a GUESS
    for interpreter + libs + thread stacks and must be calibrated on the VM;
    too small shows up as a failed trial (recorded, not hidden)."""
    return f"{next_pow2_gib(m_kib / 1024 + overhead_mib)}G"


# ----------------------------------------------------------------- plan ----
def cmd_plan(a):
    rng = random.Random(a.seed)
    envs = [e.strip() for e in a.envs.split(",")]
    for e in envs:
        if e not in ENVS:
            sys.exit(f"unknown env {e!r}; choose from {ENVS}")

    cells = []  # (m_kib, t, p, kind)
    for r in (float(x) for x in a.ratios.split(",")):
        cells.append((round_m_kib(r * a.epc_mib * 1024, a.p), a.t, a.p, f"ratio:{r}"))
    if a.include_reference:
        for mib in REFERENCE_MIB:
            if mib <= a.max_mib:
                cells.append((round_m_kib(mib * 1024, a.p), a.t, a.p, f"ref:{mib}MiB"))
    if a.controls:
        for r in CONTROL_RATIOS:
            # t=1 control still runs with p=a.p lanes, so round with a.p (a
            # multiple of 4*p blocks); rounding with p=1 left m_eff < m.
            m = round_m_kib(r * a.epc_mib * 1024, a.p)
            cells.append((m, 1, a.p, f"ctl-t1:{r}"))
            cells.append((round_m_kib(r * a.epc_mib * 1024, 1), a.t, 1, f"ctl-p1:{r}"))
    cells = [c for c in cells if c[0] / 1024 <= a.max_mib]
    # de-duplicate identical (m,t,p) from different sources, keep first label
    seen, uniq = set(), []
    for c in cells:
        if c[:3] not in seen:
            seen.add(c[:3]); uniq.append(c)
    cells = uniq

    trials = []
    for env in envs:
        for (m, t, p, kind) in cells:
            if env == "sgx-static":
                size = enclave_size_for(m, a.overhead_mib)
            elif env == "sgx-edmm":
                size = a.edmm_enclave_size
            else:
                size = None
            # large cells can take minutes per trial (and are predicted to be
            # slowest under SGX above the knee): optionally fewer repetitions
            big = a.large_reps is not None and m >= a.large_from * a.epc_mib * 1024
            for rep in range(a.large_reps if big else a.reps):
                trials.append({"env": env, "m_kib": m, "t": t, "p": p,
                               "kind": kind, "mode": "cold", "calls": 1,
                               "rep": rep, "enclave_size": size})
        # warm series: a few cells, many calls in one process
        for r in (float(x) for x in a.warm_ratios.split(",") if x):
            m = round_m_kib(r * a.epc_mib * 1024, a.p)
            if m / 1024 > a.max_mib:
                continue
            size = (enclave_size_for(m, a.overhead_mib) if env == "sgx-static"
                    else a.edmm_enclave_size if env == "sgx-edmm" else None)
            for rep in range(a.warm_procs):
                trials.append({"env": env, "m_kib": m, "t": a.t, "p": a.p,
                               "kind": f"warm:{r}", "mode": "warm",
                               "calls": a.warm_calls, "rep": rep,
                               "enclave_size": size})

    rng.shuffle(trials)  # global interleave across cells AND environments
    for i, tr in enumerate(trials):
        tr["id"] = i
    plan = {"created": utcnow(), "seed": a.seed, "epc_mib": a.epc_mib,
            # non-finite floats (the default --max-mib is inf) become null so the
            # plan is strict JSON that jq and other parsers accept
            "params": {k: (None if isinstance(v, float) and not math.isfinite(v) else v)
                       for k, v in vars(a).items() if k != "func"},
            "n_trials": len(trials), "trials": trials}
    with open(a.out, "w") as f:
        json.dump(plan, f, indent=1, allow_nan=False)
    dist = sorted({(t["env"], t["enclave_size"]) for t in trials}, key=str)
    print(f"{len(trials)} trials, {len(cells)} cells, seed={a.seed} -> {a.out}")
    print(f"distinct builds: {len(dist)}  (run: run_bench.py builds --plan {a.out})")


# --------------------------------------------------------------- builds ----
def tag_for(env, size):
    if env == "direct":
        return "direct"
    if env == "sgx-edmm":
        return f"edmm-{size}"
    return f"static-{size}"


def cmd_builds(a):
    plan = json.load(open(a.plan))
    seen = sorted({(t["env"], t["enclave_size"]) for t in plan["trials"]
                   if t["env"] in ("direct", "sgx-static", "sgx-edmm")}, key=str)
    lines = ["#!/bin/sh", "set -e",
             "# generated by run_bench.py builds -- review before running",
             "# Class 8: venv must be created with `pip install --no-compile`",
             f"make TAG=direct MAX_THREADS={a.max_threads}"]
    for env, size in seen:
        if env == "direct":
            continue
        edmm = "1" if env == "sgx-edmm" else "0"
        lines.append(f"make SGX=1 TAG={tag_for(env, size)} ENCLAVE_SIZE={size} "
                     f"EDMM={edmm} MAX_THREADS={a.max_threads}"
                     f"{' ENABLE_STATS=1' if a.stats else ''}")
    text = "\n".join(lines) + "\n"
    if a.out:
        open(a.out, "w").write(text); os.chmod(a.out, 0o755)
        print(f"wrote {a.out} ({len(seen)} distinct builds)")
    else:
        print(text)


# ----------------------------------------------------------------- meta ----
def _sh(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"cmd": " ".join(cmd), "rc": r.returncode,
                "stdout": r.stdout.strip()[-4000:], "stderr": r.stderr.strip()[-2000:]}
    except Exception as e:  # recorded, never swallowed silently
        return {"cmd": " ".join(cmd), "error": f"{type(e).__name__}: {e}"}


def _read(path, n=4000):
    try:
        return open(path).read(n).strip()
    except Exception as e:
        return f"unreadable: {type(e).__name__}"


def cmd_meta(a):
    meta = {
        "captured": utcnow(),
        "platform": platform.platform(),
        "uname": _sh(["uname", "-a"]),
        "lscpu": _sh(["lscpu"]),
        "meminfo_head": _read("/proc/meminfo", 600),
        "thp_enabled": _read("/sys/kernel/mm/transparent_hugepage/enabled"),
        "thp_defrag": _read("/sys/kernel/mm/transparent_hugepage/defrag"),
        "cpu_governor": _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "sgx_devices": {d: os.path.exists(d) for d in
                        ("/dev/sgx_enclave", "/dev/sgx_provision",
                         "/dev/sgx/enclave", "/dev/isgx")},
        "is_sgx_available": _sh(["is-sgx-available"]),
        "gramine_sgx_version": _sh(["gramine-sgx", "--version"]),
        "gramine_direct_version": _sh(["gramine-direct", "--version"]),
        "dpkg_gramine": _sh(["dpkg", "-l", "gramine"]),
        "venv_python": _sh([VENV_PY, "--version"]),
        "pip_freeze": _sh([VENV_PY, "-m", "pip", "freeze"]),
        "bench_kdf_sha256": hashlib.sha256(open(BENCH_SCRIPT, "rb").read()).hexdigest(),
        "manifests": {},
        "plan_sha256": None,
    }
    for fn in sorted(os.listdir(HERE)):
        if fn.startswith("bench-") and (fn.endswith(".manifest") or fn.endswith(".manifest.sgx")):
            meta["manifests"][fn] = hashlib.sha256(open(os.path.join(HERE, fn), "rb").read()).hexdigest()
    if a.plan and os.path.exists(a.plan):
        meta["plan_sha256"] = hashlib.sha256(open(a.plan, "rb").read()).hexdigest()
    json.dump(meta, open(a.out, "w"), indent=1)
    print(f"wrote {a.out}")


# ------------------------------------------------------------------ run ----
def build_command(trial, max_threads_unused=None):
    args = ["--m", str(trial["m_kib"]), "--t", str(trial["t"]),
            "--p", str(trial["p"]), "--reps", str(trial["calls"])]
    env = trial["env"]
    if env == "native":
        return [VENV_PY, BENCH_SCRIPT] + args
    tag = tag_for(env, trial["enclave_size"])
    runner = "gramine-direct" if env == "direct" else "gramine-sgx"
    # same argv convention as host_cli.py: <runner> <manifest-name> <script> args
    return [runner, f"bench-{tag}", "/bench_kdf.py"] + args


def run_one(trial, timeout):
    cmd = build_command(trial)
    rec = {"trial": trial, "cmd": cmd, "started": utcnow()}
    t0 = time.perf_counter_ns()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, text=True, cwd=HERE,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    except OSError as e:  # e.g. gramine-sgx not installed: record, don't crash the run
        rec.update(status="launch_failed", error=f"{type(e).__name__}: {e}",
                   wall_ns=time.perf_counter_ns() - t0)
        return rec
    try:
        out, err = proc.communicate(timeout=timeout)
        status = "ok" if proc.returncode == 0 else "error"
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()  # reap AND keep whatever it wrote
        status = "timeout"
    rec["wall_ns"] = time.perf_counter_ns() - t0
    rec["returncode"] = proc.returncode
    if err.strip() or status != "ok":
        rec["stderr"] = err[-6000:]
    if status == "ok":
        lines = [l for l in out.splitlines() if l.strip()]
        try:
            rec["result"] = json.loads(lines[-1])
            if len(lines) != 1:
                rec["stdout_extra_lines"] = len(lines) - 1  # contract violation, surfaced
        except Exception as e:
            status = "bad_output"
            rec["error"] = f"{type(e).__name__}: {e}"
            rec["stdout"] = out[-4000:]
    else:
        rec["stdout"] = out[-2000:]
    rec["status"] = status
    return rec


def cmd_run(a):
    plan = json.load(open(a.plan))
    done = {}
    if os.path.exists(a.out):
        for line in open(a.out):
            r = json.loads(line)
            done[r["trial"]["id"]] = r["status"]
    todo = [t for t in plan["trials"]
            if t["id"] not in done or (a.retry_failed and done[t["id"]] != "ok")]
    if a.envs:
        keep = set(a.envs.split(","))
        todo = [t for t in todo if t["env"] in keep]
    if a.limit:
        todo = todo[: a.limit]
    print(f"{len(todo)} trials to run ({len(done)} already recorded)", file=sys.stderr)
    with open(a.out, "a") as f:
        for i, tr in enumerate(todo):
            rec = run_one(tr, a.timeout)
            rec["order"] = len(done) + i
            f.write(json.dumps(rec) + "\n"); f.flush()
            if rec["status"] != "ok":
                print(f"[{tr['id']}] {tr['env']} m={tr['m_kib']} -> {rec['status']}: "
                      f"{(rec.get('stderr') or rec.get('error') or '')[-300:]!r}",
                      file=sys.stderr)
            if a.cooldown:
                time.sleep(a.cooldown)


# -------------------------------------------------------------- summary ----
def cmd_summary(a):
    rows = [json.loads(l) for l in open(a.results)]
    bad = [r for r in rows if r["status"] != "ok"]
    print(f"{len(rows)} records, {len(bad)} not ok "
          f"({', '.join(sorted({r['status'] for r in bad})) or '-'})")

    # correctness: one digest per (m,t,p) across ALL environments and trials
    digests = {}
    for r in rows:
        if r["status"] == "ok":
            k = (r["trial"]["m_kib"], r["trial"]["t"], r["trial"]["p"])
            digests.setdefault(k, set()).add(r["result"]["digest"])
            if not r["result"]["digest_consistent"]:
                digests[k].add("INCONSISTENT-WITHIN-PROCESS")
    mism = {k: v for k, v in digests.items() if len(v) != 1}
    print("digest check:", "PASS (all envs agree)" if not mism else f"FAIL {mism}")

    cells = {}
    for r in rows:
        if r["status"] != "ok" or r["trial"]["mode"] != "cold":
            continue
        t = r["trial"]
        cells.setdefault((t["env"], t["m_kib"], t["t"], t["p"]), []).append(
            (r["result"]["kdf_ns"][0] / 1e6, r["wall_ns"] / 1e6))
    print(f"{'env':<11}{'m_MiB':>9}{'t':>3}{'p':>3}{'n':>4}"
          f"{'kdf_med_ms':>12}{'kdf_MAD':>9}{'wall_med_ms':>13}")
    for k in sorted(cells, key=lambda k: (k[0], k[2], k[3], k[1])):
        kd = [x[0] for x in cells[k]]; wl = [x[1] for x in cells[k]]
        med = statistics.median(kd)
        mad = statistics.median(abs(x - med) for x in kd)
        print(f"{k[0]:<11}{k[1]/1024:>9.1f}{k[2]:>3}{k[3]:>3}{len(kd):>4}"
              f"{med:>12.1f}{mad:>9.1f}{statistics.median(wl):>13.1f}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plan"); p.set_defaults(func=cmd_plan)
    p.add_argument("--epc-mib", type=float, required=True,
                   help="MEASURED EPC size of this VM in MiB (not the datasheet value)")
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--reps", type=int, default=20, help="cold trials per (env, cell)")
    p.add_argument("--large-from", type=float, default=0.9,
                   help="cells with m >= this fraction of EPC use --large-reps")
    p.add_argument("--large-reps", type=int, default=None,
                   help="reduced cold repetitions for large cells (size it from "
                        "pilot variance, Kalibera & Jones 2013; default: same as --reps)")
    p.add_argument("--envs", default="native,direct,sgx-static,sgx-edmm")
    p.add_argument("--t", type=int, default=3)
    p.add_argument("--p", type=int, default=4)
    p.add_argument("--ratios", default=",".join(map(str, DEFAULT_RATIOS)))
    p.add_argument("--max-mib", type=float, default=float("inf"),
                   help="cap on m (MiB), e.g. host RAM minus headroom")
    p.add_argument("--include-reference", action="store_true",
                   help="add RFC 9106 / OWASP / common-deployment absolute points")
    p.add_argument("--controls", action="store_true", help="add t=1 and p=1 controls")
    p.add_argument("--warm-ratios", default="0.1,1.0", help="empty string disables")
    p.add_argument("--warm-calls", type=int, default=10)
    p.add_argument("--warm-procs", type=int, default=3)
    p.add_argument("--overhead-mib", type=float, default=512,
                   help="GUESSED non-KDF enclave memory; calibrate on the VM")
    p.add_argument("--edmm-enclave-size", default="default",
                   help='"default" omits sgx.enclave_size (Gramine default; verify)')
    p.add_argument("--out", default="plan.json")

    p = sub.add_parser("builds"); p.set_defaults(func=cmd_builds)
    p.add_argument("--plan", default="plan.json")
    p.add_argument("--max-threads", type=int, default=32,
                   help="same value in both SGX arms so they differ only in EDMM")
    p.add_argument("--stats", action="store_true", help="build with sgx.enable_stats")
    p.add_argument("--out")

    p = sub.add_parser("meta"); p.set_defaults(func=cmd_meta)
    p.add_argument("--plan"); p.add_argument("--out", default="meta.json")

    p = sub.add_parser("run"); p.set_defaults(func=cmd_run)
    p.add_argument("--plan", default="plan.json")
    p.add_argument("--out", default="results.jsonl")
    p.add_argument("--envs", help="comma list to restrict this invocation")
    p.add_argument("--limit", type=int)
    p.add_argument("--timeout", type=float, default=1800)
    p.add_argument("--cooldown", type=float, default=0.0)
    p.add_argument("--retry-failed", action="store_true")

    p = sub.add_parser("summary"); p.set_defaults(func=cmd_summary)
    p.add_argument("--results", default="results.jsonl")

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
