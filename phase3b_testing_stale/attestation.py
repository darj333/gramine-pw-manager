"""
attestation.py — mocked DCAP-style attestation + ECDH channel (Phase 3b).

Shared by both host_cli.py (host side, verifier) and vault_crypto.py
(enclave side, prover). Used to attest the enclave process's identity and
establish a fresh, per-invocation session key BEFORE the master password
(and any secret value) crosses the host/enclave boundary, replacing the
Phase 3a plaintext stdin handoff.

--------------------------------------------------------------------------
SCOPE — read this before touching MOCK_MRENCLAVE / MOCK_MRSIGNER below
--------------------------------------------------------------------------
The "quote" produced here is a MOCK. It is not a real Intel DCAP quote,
is not signed by a real Quoting Enclave, and proves nothing about actual
SGX hardware. It exists so the *protocol logic* — handshake sequencing,
verification policy, ECDH key agreement, session-key-encrypted transport
— can be built and debugged entirely under gramine-direct, with zero
Azure dependency (per the project plan's Phase 3b scope).

Phase 4b replaces:
  - generate_mock_quote()   -> real DCAP quote retrieval on gramine-sgx
  - MOCK_MRENCLAVE/MRSIGNER -> real values from `gramine-sgx-sign` output
  - the mock_signature check -> real DCAP quote signature chain verification
The wire protocol and verify_quote() policy structure below are designed
to not need to change shape when that swap happens — only the source of
the quote's contents and the integrity check change.
"""

import os
import sys
import json
import time
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# --------------------------------------------------------------------------
# Enclave identity — placeholder values for Phase 3b's mocked quote.
# Both sides import this module, so both currently agree on these values
# by construction. In Phase 4b, the host's expected values come instead
# from the real `vault.manifest.sgx` / `vault.sig` build output, not from
# a constant shared with the enclave process itself (an enclave attesting
# to a value it defines itself would be meaningless in the real protocol —
# this only works here because Phase 3b is validating logic, not identity).
# --------------------------------------------------------------------------
MOCK_MRENCLAVE = "0" * 64
MOCK_MRSIGNER = "1" * 64
MOCK_ISV_SVN = 1
MOCK_TCB_LEVEL = "up_to_date"

QUOTE_FRESHNESS_SECONDS = 30  # max quote age the host will accept


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(data: str) -> bytes:
    return base64.b64decode(data)


# --------------------------------------------------------------------------
# Enclave side: mock quote generation
# --------------------------------------------------------------------------

def generate_mock_quote(nonce: bytes) -> dict:
    """Produce a mock attestation quote binding the given nonce.

    Field names deliberately mirror what a real DCAP report body carries
    (measurement fields + a freshness binding), so Chapter 5's discussion
    of "what changed in Phase 4b" can point at this structure directly.
    """
    quote = {
        "mrenclave": MOCK_MRENCLAVE,
        "mrsigner": MOCK_MRSIGNER,
        "isv_svn": MOCK_ISV_SVN,
        "tcb_level": MOCK_TCB_LEVEL,
        "nonce": _b64(nonce),
        "timestamp": time.time(),
    }
    # Mock "signature": binds the fields together so in-transit tampering
    # is at least detectable in the mock. This is NOT a real signature
    # chain back to Intel's root of trust — see module docstring.
    quote["mock_signature"] = hashlib.sha256(
        json.dumps(quote, sort_keys=True).encode()
    ).hexdigest()
    return quote


# --------------------------------------------------------------------------
# Host side: verification policy
# --------------------------------------------------------------------------

class QuoteVerificationError(Exception):
    """Raised when a quote fails the verification policy. The message
    states which specific check failed — this is itself evaluation data
    (see the negative-case tests in test_attestation.py)."""


def verify_quote(quote: dict, expected_nonce: bytes,
                  expected_mrenclave: str = MOCK_MRENCLAVE,
                  expected_mrsigner: str = MOCK_MRSIGNER,
                  max_age_seconds: float = QUOTE_FRESHNESS_SECONDS,
                  min_tcb_level: str = MOCK_TCB_LEVEL) -> None:
    """Verify a quote against the policy.

    Raises QuoteVerificationError with a specific reason on any failure.
    Returns None (silently) on success. Checks run in this order:
    integrity -> measurement (MRENCLAVE, MRSIGNER) -> nonce (replay) ->
    freshness (staleness) -> TCB level.
    """
    quote_copy = dict(quote)
    signature = quote_copy.pop("mock_signature", None)
    expected_sig = hashlib.sha256(
        json.dumps(quote_copy, sort_keys=True).encode()
    ).hexdigest()
    if signature != expected_sig:
        raise QuoteVerificationError("quote integrity check failed (signature mismatch)")

    if quote.get("mrenclave") != expected_mrenclave:
        raise QuoteVerificationError(
            f"MRENCLAVE mismatch: expected {expected_mrenclave}, got {quote.get('mrenclave')}"
        )
    if quote.get("mrsigner") != expected_mrsigner:
        raise QuoteVerificationError(
            f"MRSIGNER mismatch: expected {expected_mrsigner}, got {quote.get('mrsigner')}"
        )

    quote_nonce = _unb64(quote.get("nonce", ""))
    if quote_nonce != expected_nonce:
        raise QuoteVerificationError("nonce mismatch (possible replay attack)")

    age = time.time() - quote.get("timestamp", 0)
    if age > max_age_seconds:
        raise QuoteVerificationError(
            f"quote is stale ({age:.1f}s old, max allowed {max_age_seconds}s)"
        )
    if age < -5:  # small clock-skew allowance; reject quotes claiming to be from the future
        raise QuoteVerificationError("quote timestamp is in the future")

    if quote.get("tcb_level") != min_tcb_level:
        raise QuoteVerificationError(
            f"TCB level not acceptable: got {quote.get('tcb_level')!r}, "
            f"required {min_tcb_level!r}"
        )


# --------------------------------------------------------------------------
# ECDH handshake (both sides)
# --------------------------------------------------------------------------

def generate_ephemeral_keypair():
    """Fresh X25519 keypair for this single invocation. A new keypair
    every time (not a long-lived identity key) means a fresh session key
    on every subprocess invocation and nothing long-lived to compromise
    between runs — see Chapter 4's "Attested Channel Design" notes."""
    private_key = x25519.X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_to_str(public_key) -> str:
    return _b64(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def public_key_from_str(data: str):
    return x25519.X25519PublicKey.from_public_bytes(_unb64(data))


def derive_session_key(private_key, peer_public_key, context: bytes) -> bytes:
    """ECDH shared secret -> HKDF-SHA256 -> 32-byte AES-256 session key.
    `context` (the handshake nonce) binds the derivation to this specific
    handshake."""
    shared_secret = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"vault-session-key-v1:" + context,
    ).derive(shared_secret)


# --------------------------------------------------------------------------
# Session-key AEAD transport (both sides) — reuses AES-GCM, the same
# primitive already used for vault entries in vault_crypto.py, rather
# than introducing a second AEAD scheme into the project.
# --------------------------------------------------------------------------

def session_encrypt(session_key: bytes, plaintext: str) -> dict:
    nonce = os.urandom(12)
    ct = AESGCM(session_key).encrypt(nonce, plaintext.encode(), None)
    return {"nonce": _b64(nonce), "ciphertext": _b64(ct)}


def session_decrypt(session_key: bytes, payload: dict) -> str:
    nonce = _unb64(payload["nonce"])
    ciphertext = _unb64(payload["ciphertext"])
    return AESGCM(session_key).decrypt(nonce, ciphertext, None).decode()


# --------------------------------------------------------------------------
# Line-based JSON protocol helpers (both sides)
# --------------------------------------------------------------------------

def write_json_line(stream, obj: dict):
    stream.write(json.dumps(obj) + "\n")
    stream.flush()


def read_json_line(stream) -> dict:
    line = stream.readline()
    if line == "":
        raise EOFError("peer closed the connection during the attestation handshake")
    return json.loads(line)


# --------------------------------------------------------------------------
# Enclave-side handshake driver — called from vault_crypto.py
# --------------------------------------------------------------------------

def perform_enclave_handshake() -> bytes:
    """Enclave side of the attested handshake.

    Reads a nonce from the host over stdin, produces a mock attestation
    quote bound to that nonce plus an ephemeral ECDH public key, sends
    both to the host over stdout, reads back the host's ephemeral public
    key, and derives the session key. Returns the 32-byte session key
    used to decrypt subsequent secret input from the host.
    """
    hello = read_json_line(sys.stdin)
    if hello.get("type") != "hello":
        print("Error: expected handshake 'hello' message from host.", file=sys.stderr)
        sys.exit(1)
    nonce = _unb64(hello["nonce"])

    quote = generate_mock_quote(nonce)
    private_key, public_key = generate_ephemeral_keypair()
    write_json_line(sys.stdout, {
        "type": "attestation",
        "quote": quote,
        "enclave_pub": public_key_to_str(public_key),
    })

    handshake = read_json_line(sys.stdin)
    if handshake.get("type") != "handshake":
        print("Error: expected 'handshake' message from host.", file=sys.stderr)
        sys.exit(1)
    host_pub = public_key_from_str(handshake["host_pub"])

    return derive_session_key(private_key, host_pub, context=nonce)


# --------------------------------------------------------------------------
# Host-side handshake driver — called from host_cli.py
# --------------------------------------------------------------------------

def perform_host_handshake(enclave_stdin, enclave_stdout, *,
                            expected_mrenclave: str = MOCK_MRENCLAVE,
                            expected_mrsigner: str = MOCK_MRSIGNER,
                            max_age_seconds: float = QUOTE_FRESHNESS_SECONDS,
                            min_tcb_level: str = MOCK_TCB_LEVEL) -> bytes:
    """Host side of the attested handshake.

    Sends a fresh nonce to the enclave process, reads back its
    attestation quote and ephemeral public key, verifies the quote
    against the given policy (raises QuoteVerificationError and does
    NOT complete the key exchange on any failure), completes the ECDH
    exchange, and returns the derived session key.

    Callers MUST NOT send the password if this raises.
    """
    nonce = os.urandom(16)
    write_json_line(enclave_stdin, {"type": "hello", "nonce": _b64(nonce)})

    response = read_json_line(enclave_stdout)
    if response.get("type") != "attestation":
        raise QuoteVerificationError("enclave did not respond with an attestation message")

    verify_quote(
        response["quote"], expected_nonce=nonce,
        expected_mrenclave=expected_mrenclave,
        expected_mrsigner=expected_mrsigner,
        max_age_seconds=max_age_seconds,
        min_tcb_level=min_tcb_level,
    )

    enclave_pub = public_key_from_str(response["enclave_pub"])
    private_key, public_key = generate_ephemeral_keypair()
    write_json_line(enclave_stdin, {
        "type": "handshake",
        "host_pub": public_key_to_str(public_key),
    })

    return derive_session_key(private_key, enclave_pub, context=nonce)
