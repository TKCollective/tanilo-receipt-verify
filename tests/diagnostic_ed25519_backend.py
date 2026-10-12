#!/usr/bin/env python3
"""Diagnostic, not a test: what does the installed crypto backend accept?

Prints the cryptography and OpenSSL versions and, for each "Taming the many
EdDSAs" case (novifinancial/ed25519-speccheck) and for the identity-key
signature, whether the backend ACCEPTS it without the guard, and what the
guard answers. Exit code is always 0. Run: python tests/diagnostic_ed25519_backend.py
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import cryptography  # noqa: E402
from cryptography.hazmat.backends.openssl import backend  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from tanilo_receipt_verify import ed25519_guard as g  # noqa: E402
from tests.test_ed25519_small_order import TAMING, IDENTITY_KEY, IDENTITY_SIG  # noqa: E402


def backend_accepts(pbk: bytes, sig: bytes, msg: bytes) -> str:
    try:
        Ed25519PublicKey.from_public_bytes(pbk).verify(sig, msg)
        return "ACCEPT"
    except Exception as e:  # noqa: BLE001
        return "reject" if type(e).__name__ == "InvalidSignature" else f"raises {type(e).__name__}"


def main() -> int:
    print(f"cryptography {cryptography.__version__}; {backend.openssl_version_text()}; Python {sys.version.split()[0]}")
    for case, msg, pbk, sig, expected in TAMING:
        got = g.check_ed25519(bytes.fromhex(pbk), bytes.fromhex(sig)) or "accept"
        print(f"Taming case {case:2d}: backend {backend_accepts(bytes.fromhex(pbk), bytes.fromhex(sig), bytes.fromhex(msg)):6s} | guard {got.split(':')[0]} (expected {expected})")
    for m in (b"one message", b"a different message"):
        print(f"identity key, R = identity, S = 0, {m!r}: backend {backend_accepts(IDENTITY_KEY, IDENTITY_SIG, m):6s} | guard {g.check_ed25519(IDENTITY_KEY, IDENTITY_SIG).split(':')[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
