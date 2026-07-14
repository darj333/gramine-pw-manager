import os
import sys
import json
import base64
import getpass
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import attestation
 
 
def derive_key(password: str, salt: bytes = None,
                time_cost=3, memory_cost=65536, parallelism=4):
    """Derive a 32-byte AES key from a master password using Argon2id.
 
    If salt is None, a fresh random salt is generated (new vault).
    Otherwise the provided salt is reused (existing vault), so the
    same password always re-derives the same key.
    """
    if salt is None:
        salt = os.urandom(16)
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,  # Argon2id
    )
    return key, salt
 
 
def encrypt_entry(key: bytes, plaintext: str) -> dict:
    """Encrypt a single secret value with AES-256-GCM.
 
    Returns a dict with base64-encoded nonce, ciphertext, and auth tag,
    ready to be stored directly in the vault JSON.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    # cryptography's AESGCM.encrypt() appends the 16-byte tag to the end
    ciphertext, tag = ct[:-16], ct[-16:]
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
    }
 
 
def decrypt_entry(key: bytes, entry: dict) -> str:
    """Decrypt a single vault entry back to its plaintext secret.
 
    Raises an exception (cryptography.exceptions.InvalidTag) if the
    wrong key is used or the ciphertext/tag has been tampered with.
    """
    nonce = base64.b64decode(entry["nonce"])
    ciphertext = base64.b64decode(entry["ciphertext"])
    tag = base64.b64decode(entry["tag"])
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return plaintext.decode()
 
 
def load_vault(path: str) -> dict:
    """Load the vault JSON file, or return an empty vault structure
    if it doesn't exist yet (first run)."""
    if not os.path.exists(path):
        return {"kdf": None, "entries": {}}
    with open(path, "r") as f:
        return json.load(f)
 
 
def save_vault(path: str, vault: dict):
    """Write the vault structure back to disk as JSON."""
    with open(path, "w") as f:
        json.dump(vault, f, indent=2)
 
 
def get_secret_input(prompt: str, session_key: bytes = None) -> str:
    """Read a sensitive value either from stdin (when piped in by a
    host-side process, e.g. host_cli.py) or interactively via getpass
    (when vault_crypto.py is run directly, for local debugging).
 
    Protocol when piped (Phase 3b+): one JSON line per call, containing
    a value AES-GCM-encrypted under the session_key established by
    perform_enclave_handshake(). session_key is None only when stdin is
    piped but no handshake was performed (shouldn't happen once
    host_cli.py is updated — kept as a fallback to plaintext lines so
    this function still degrades gracefully rather than throwing an
    unrelated error if it's ever called that way).
    """
    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if line == "":
            print("Error: expected input on stdin but got none.", file=sys.stderr)
            sys.exit(1)
        if session_key is not None:
            payload = json.loads(line)
            return attestation.session_decrypt(session_key, payload)
        return line.rstrip("\n")
    return getpass.getpass(prompt)
 
 
def main():
    # Defaults to "vault.json" in the current directory for normal runs.
    # Under Gramine, the sandbox only exposes paths explicitly declared
    # in the manifest's fs.mounts, so the manifest sets VAULT_PATH=/vault.json
    # to match where vault.json is actually mounted.
    vault_path = os.environ.get("VAULT_PATH", "vault.json")
    vault = load_vault(vault_path)

    session_key = None
    if not sys.stdin.isatty():
        # Host-driven invocation: attest this process's identity to the
        # host and establish a fresh session key BEFORE accepting any
        # secret input over this channel (Phase 3b / Contribution 3).
        # Direct/tty runs (local debugging) skip this — there is no host
        # process on the other end to attest to in that case.
        session_key = attestation.perform_enclave_handshake()

    password = get_secret_input("Master password: ", session_key)
 
    if vault["kdf"] is None:
        # First run: no salt/params stored yet, generate fresh ones
        key, salt = derive_key(password)
        vault["kdf"] = {
            "salt": base64.b64encode(salt).decode(),
            "algorithm": "argon2id",
            "time_cost": 3,
            "memory_cost": 65536,
            "parallelism": 4,
        }
        save_vault(vault_path, vault)
    else:
        # Existing vault: reuse stored salt/params so the same
        # password re-derives the same key
        salt = base64.b64decode(vault["kdf"]["salt"])
        key, _ = derive_key(
            password,
            salt,
            vault["kdf"]["time_cost"],
            vault["kdf"]["memory_cost"],
            vault["kdf"]["parallelism"],
        )
 
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
 
    if cmd == "add":
        if len(sys.argv) < 3:
            print("Usage: python3 vault_crypto.py add <name>")
            return
        name = sys.argv[2]
        secret = get_secret_input("Secret value: ", session_key)
        vault["entries"][name] = encrypt_entry(key, secret)
        save_vault(vault_path, vault)
        print(f"Added '{name}'.")
 
    elif cmd == "get":
        if len(sys.argv) < 3:
            print("Usage: python3 vault_crypto.py get <name>")
            return
        name = sys.argv[2]
        if name not in vault["entries"]:
            print(f"No entry named '{name}'.")
            return
        try:
            print(decrypt_entry(key, vault["entries"][name]))
        except Exception:
            print("Decryption failed — wrong master password or corrupted entry.")
 
    elif cmd == "list":
        names = vault["entries"].keys()
        print("\n".join(names) if names else "(empty vault)")
 
    elif cmd == "delete":
        if len(sys.argv) < 3:
            print("Usage: python3 vault_crypto.py delete <name>")
            return
        name = sys.argv[2]
        if name in vault["entries"]:
            del vault["entries"][name]
            save_vault(vault_path, vault)
            print(f"Deleted '{name}'.")
        else:
            print(f"No entry named '{name}'.")
 
    else:
        print(f"Unknown command: {cmd}")
        print("Available commands: add <name> | get <name> | list | delete <name>")
 
 
if __name__ == "__main__":
    main()
