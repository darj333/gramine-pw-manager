"""
host_cli.py — host-side interactive menu for the password manager.

Design note: this script runs OUTSIDE Gramine, on the untrusted host side
of the architecture. It owns all user interaction (menu display, password
and secret prompts via getpass, which needs real terminal control that
Gramine's sandbox does not fully provide). It never touches the master
password's cryptographic use directly — it only collects it and sends it,
over an attested, session-key-encrypted channel (Phase 3b), into the
Gramine-wrapped vault_crypto.py subprocess, which performs all key
derivation and encryption/decryption.

This mirrors the project's intended trust boundary: host = UI + untrusted
vault storage, Gramine-wrapped process = key derivation + crypto only.

Phase 3b change (Contribution 3): the password used to be piped over
stdin in plaintext. It is now sent only after the enclave process has
produced an attestation quote that passes host_cli.py's verification
policy and an ECDH session key has been established — see attestation.py.
"""

import os
import subprocess
import getpass
import sys

import attestation

# Name of the built manifest (gramine-direct expects this without
# the .manifest extension), and the absolute in-sandbox path to the
# script, matching what vault.manifest.template declares.
GRAMINE_MANIFEST_NAME = "vault"
SANDBOXED_SCRIPT_PATH = "/vault_crypto.py"

# Configurable loader, per the Phase 4 plan (local gramine-direct now,
# gramine-sgx on Azure later, without editing this file). GRAMINE_LOADER=none
# bypasses Gramine entirely and runs vault_crypto.py directly with the
# system interpreter — useful for testing the attestation protocol logic
# itself in an environment without Gramine installed; the handshake and
# session-key code path is identical either way.
GRAMINE_LOADER = os.environ.get("GRAMINE_LOADER", "gramine-direct")


def _build_command(cmd: str, args: list[str]) -> list[str]:
    if GRAMINE_LOADER == "none":
        return [sys.executable, "vault_crypto.py", cmd] + args
    return [GRAMINE_LOADER, GRAMINE_MANIFEST_NAME, SANDBOXED_SCRIPT_PATH, cmd] + args


def run_vault_command(cmd: str, args: list[str], password: str, secret: str = None) -> str:
    """Invoke the Gramine-wrapped vault_crypto.py as a subprocess.

    Before any secret material is sent, performs the attested handshake:
    the enclave process must produce a quote that passes the verification
    policy (expected MRENCLAVE/MRSIGNER, nonce freshness, minimum TCB
    level — see attestation.py), after which an ECDH session key is
    established. The master password (and, for 'add', the secret) are
    then sent AES-GCM-encrypted under that session key, one JSON line
    per value, matching vault_crypto.py's get_secret_input() protocol.

    If verification fails for any reason, the password is never sent
    and the subprocess is killed immediately.

    Returns combined stdout+stderr as a string for the caller to display.
    """
    full_args = _build_command(cmd, args)

    proc = subprocess.Popen(
        full_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    try:
        session_key = attestation.perform_host_handshake(proc.stdin, proc.stdout)
    except (attestation.QuoteVerificationError, EOFError) as e:
        proc.kill()
        proc.wait()
        return (
            f"[attestation refused: {e}]\n"
            "The master password was NOT sent to the enclave process."
        )

    attestation.write_json_line(proc.stdin, attestation.session_encrypt(session_key, password))
    if secret is not None:
        attestation.write_json_line(proc.stdin, attestation.session_encrypt(session_key, secret))
    proc.stdin.close()
    proc.stdin = None  # tell communicate() below not to touch stdin again —
                        # it doesn't check whether we already closed it, and
                        # will otherwise raise ValueError trying to flush a
                        # closed file.

    stdout_data, stderr_data = proc.communicate()

    output = stdout_data
    if proc.returncode != 0:
        output += "\n[stderr]\n" + stderr_data
    return output.strip()


def show_menu():
    print("\n=== Password Manager ===")
    print("1) Add entry")
    print("2) Get entry")
    print("3) List entries")
    print("4) Delete entry")
    print("5) Quit")


def main():
    print("Confidential Password Manager (host CLI)")
    print(f"Running vault operations via {GRAMINE_LOADER}, with attested key exchange.\n")

    while True:
        show_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            name = input("Entry name: ").strip()
            password = getpass.getpass("Master password: ")
            secret = getpass.getpass("Secret value: ")
            output = run_vault_command("add", [name], password, secret)
            print(output)

        elif choice == "2":
            name = input("Entry name: ").strip()
            password = getpass.getpass("Master password: ")
            output = run_vault_command("get", [name], password)
            print(output)

        elif choice == "3":
            password = getpass.getpass("Master password: ")
            output = run_vault_command("list", [], password)
            print(output)

        elif choice == "4":
            name = input("Entry name: ").strip()
            password = getpass.getpass("Master password: ")
            output = run_vault_command("delete", [name], password)
            print(output)

        elif choice == "5":
            print("Goodbye.")
            sys.exit(0)

        else:
            print("Invalid choice, please pick 1-5.")


if __name__ == "__main__":
    main()
