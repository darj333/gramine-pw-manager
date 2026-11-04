#!/usr/bin/env python3
"""Isolated Argon2id timing script for the EPC / memory-cost experiment.

Deliberately minimal: no vault, no attestation, no AES-GCM, no file I/O,
no stdin. Its only dependency is argon2-cffi, so the Gramine manifest for
it has no mutable files and a small trusted-file surface.

The KDF call is the same call shape as derive_key() in vault_crypto.py
(hash_secret_raw, Type.ID, hash_len=32), so the benchmark and the real
application exercise the same code path.

Contract with the driver (run_bench.py):
  * exactly ONE line of JSON on stdout, nothing else
  * diagnostics go to stderr; any failure exits non-zero
  * the password and salt are FIXED, so the digest is deterministic and
    must be identical across native / gramine-direct / gramine-sgx. The
    driver treats a digest mismatch as a correctness failure.

Timing: only the hash_secret_raw() call is timed in-process (perf_counter_ns).
Process start-up, interpreter import and Gramine/enclave load are NOT in
kdf_ns; the driver measures whole-process wall time separately, and import
cost is reported here as import_ns.

Under Gramine, clock reads may be served via an OCALL (not verified); the
cost is far below the millisecond scale of the measurements but should be
stated.
"""
import sys

sys.dont_write_bytecode = True  

import argparse
import json
import os
import time

PASSWORD = b"benchmark-password-not-a-secret"
SALT = bytes(range(16))  # fixed 16 bytes: deterministic output across runs/envs
HASH_LEN = 32


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--m", type=int, required=True, help="memory cost in KiB")
    ap.add_argument("--t", type=int, default=3, help="time cost (passes)")
    ap.add_argument("--p", type=int, default=4, help="parallelism (lanes/threads)")
    ap.add_argument("--reps", type=int, default=1,
                    help="KDF calls in THIS process (1 = cold, >1 = warm series)")
    return ap.parse_args(argv)


def read_vmhwm_kib():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmHWM:"): #virtual memory high-water mark
                    return int(line.split()[1])
    except Exception:
        pass
    return None


def read_maxrss_kib():
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # KiB on Linux - peak memory usage
    except Exception:
        return None


def dist_version(name):
    try:
        from importlib.metadata import version
        return version(name)
    except Exception as e:  # never let metadata lookup break a measurement
        return f"unknown ({type(e).__name__})"


def main(argv):
    a = parse_args(argv)
    if a.t < 1 or a.p < 1 or a.reps < 1:
        print("error: t, p and reps must be >= 1", file=sys.stderr)
        return 2
    if a.m < 8 * a.p:
        print(f"error: Argon2 requires m >= 8*p KiB (got m={a.m}, p={a.p})",
              file=sys.stderr)
        return 2

    t_imp0 = time.perf_counter_ns()
    from argon2.low_level import hash_secret_raw, Type
    import_ns = time.perf_counter_ns() - t_imp0

    kdf_ns, digests = [], []
    for _ in range(a.reps):
        t0 = time.perf_counter_ns()
        d = hash_secret_raw(
            secret=PASSWORD,
            salt=SALT,
            time_cost=a.t,
            memory_cost=a.m,
            parallelism=a.p,
            hash_len=HASH_LEN,
            type=Type.ID,
        )
        t1 = time.perf_counter_ns()
        kdf_ns.append(t1 - t0)
        digests.append(d.hex())

    # Argon2 rounds memory down to a multiple of 4*p blocks (4 sync points
    # per pass, p lanes); the working set is this value, not the raw m.
    m_eff = (a.m // (4 * a.p)) * 4 * a.p

    out = {
        "schema": 1,
        "m_kib": a.m,
        "m_effective_kib": m_eff,
        "t": a.t,
        "p": a.p,
        "reps": a.reps,
        "kdf_ns": kdf_ns,
        "digest": digests[0],
        "digest_consistent": len(set(digests)) == 1,
        "import_ns": import_ns,
        "maxrss_kib": read_maxrss_kib(),
        "vmhwm_kib": read_vmhwm_kib(),
        "python": sys.version.split()[0],
        "argon2_cffi": dist_version("argon2-cffi"),
        "argon2_cffi_bindings": dist_version("argon2-cffi-bindings"),
        "cpu_count": os.cpu_count(),
    }
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
