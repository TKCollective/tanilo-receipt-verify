#!/usr/bin/env python3
"""Builds tanilo-shaped.json: two JWS receipts in the form the Tanilo API issues (JWS JSON general
serialization, one signature, attached base64url payload), over the payload of the live AER-1 interop
receipt (tanilo-receipt-spec examples/interop/aer1/receipt.jws.json, signed 2026-10-08), each under a
FIXTURE key whose scalar is published here on purpose. Never a production key.

1. mixed-order-key: A = [a]B + T, where T is an order-8 point. The nonce is chosen so that k = SHA-512(R || A || M)
   mod L is divisible by 8; then [k]T is the identity and S = r + k*a satisfies the cofactorless equation
   [S]B = R + [k]A, so the cofactored one holds too. A plain RFC 8032 verifier accepts it.
2. mixed-order-r: the prime-order key [a]B, with R = [r]B + T and S = r + k*a. The cofactored equation holds and the
   cofactorless one does not.

Both equations are checked here directly. Uses only the point arithmetic of tanilo_receipt_verify 0.2.1
(decode_point, encode_point, point_add, point_mul), so it builds the same file before and after the mixed-order
checks. Deterministic: run it again and the output is byte-identical.

usage: python tests/fixtures/mixed-order/build_tanilo_shaped.py
"""
import base64
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent))
from tanilo_receipt_verify.ed25519_guard import L, IDENTITY, decode_point, encode_point, point_add, point_mul  # noqa: E402

# The payload string of the live AER-1 receipt, copied unchanged (its canonical_sha256 is
# sha256-ca2fb84597076f9c8fac2d957a05bf21a11bd741e519879ff09ba78fd2305325).
AER1_PAYLOAD_FILE = HERE / "aer1-payload.b64u.txt"
B = decode_point(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))[0]
T = decode_point(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"))[0]   # order 8
SCALAR_SEED = b"tanilo-receipt-verify fixture: mixed-order, 2026-10-14"
KID_MIXED = "fixture-mixed-order-key-2026-10-14"
KID_PRIME = "fixture-prime-order-key-2026-10-14"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def h(*parts: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little") % L


def protected(kid: str) -> str:
    hdr = {"alg": "EdDSA", "kid": kid, "typ": "application/vnd.verification.v0.3+composed+jws", "role": "evaluated"}
    return b64u(json.dumps(hdr, separators=(",", ":")).encode())


def equations(pub: bytes, sig: bytes, msg: bytes):
    """(cofactorless, cofactored) RFC 8032 5.1.7 results, computed directly."""
    A, R, S = decode_point(pub)[0], decode_point(sig[:32])[0], int.from_bytes(sig[32:], "little")
    k = h(sig[:32], pub, msg)
    lhs, rhs = point_mul(S, B), point_add(R, point_mul(k, A))
    return lhs == rhs, point_mul(8, lhs) == point_mul(8, rhs)


def build() -> dict:
    assert point_mul(8, T) == IDENTITY and point_mul(L, B) == IDENTITY
    payload = AER1_PAYLOAD_FILE.read_text().strip()
    a = h(SCALAR_SEED)
    a_pt = point_mul(a, B)
    pub_prime = encode_point(a_pt)
    pub_mixed = encode_point(point_add(a_pt, T))

    # 1. mixed-order key, signature valid under both equations
    ph1 = protected(KID_MIXED)
    msg1 = (ph1 + "." + payload).encode("ascii")
    for i in range(4096):
        r = h(SCALAR_SEED, b" nonce ", str(i).encode())
        R = encode_point(point_mul(r, B))
        k = h(R, pub_mixed, msg1)
        if k % 8 == 0:
            sig1 = R + ((r + k * a) % L).to_bytes(32, "little")
            break
    else:
        raise SystemExit("no nonce found")
    assert equations(pub_mixed, sig1, msg1) == (True, True)

    # 2. prime-order key, mixed-order R
    ph2 = protected(KID_PRIME)
    msg2 = (ph2 + "." + payload).encode("ascii")
    r = h(SCALAR_SEED, b" mixed R")
    R = encode_point(point_add(point_mul(r, B), T))
    k = h(R, pub_prime, msg2)
    sig2 = R + ((r + k * a) % L).to_bytes(32, "little")
    assert equations(pub_prime, sig2, msg2) == (False, True)

    jwks = {"https://fixture.invalid/.well-known/jwks.json": {"keys": [
        {"kty": "OKP", "crv": "Ed25519", "kid": KID_MIXED, "x": b64u(pub_mixed)},
        {"kty": "OKP", "crv": "Ed25519", "kid": KID_PRIME, "x": b64u(pub_prime)},
    ]}}
    return {
        "note": "Built by build_tanilo_shaped.py. Fixture keys only; the scalar is published in the builder on purpose.",
        "jwks_by_issuer": jwks,
        "receipts": {
            "mixed-order-key": {"equations": {"cofactorless": True, "cofactored": True},
                                "jws": {"payload": payload, "signatures": [{"protected": ph1, "signature": b64u(sig1)}]}},
            "mixed-order-r": {"equations": {"cofactorless": False, "cofactored": True},
                              "jws": {"payload": payload, "signatures": [{"protected": ph2, "signature": b64u(sig2)}]}},
        },
    }


if __name__ == "__main__":
    (HERE / "tanilo-shaped.json").write_text(json.dumps(build(), indent=1) + "\n")
    print("wrote", HERE / "tanilo-shaped.json")
