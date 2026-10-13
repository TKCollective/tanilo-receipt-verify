#!/usr/bin/env python3
"""Runs the installed tanilo-receipt-verify against the "Taming the many EdDSAs" cases 0-11 and the
identity-key forgery, and prints the results as JSON (results.md is the table made from them).

usage: python run_cases.py <tests/test_ed25519_small_order.py from the 0.2.1 sdist> <cases.txt>

The package under test is whatever is installed in the interpreter running this script. Nothing is
imported from a source checkout: the vectors are read from the test file as text.
"""
import base64, hashlib, json, re, sys

import cryptography
import tanilo_receipt_verify as trv
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from tanilo_receipt_verify import verify
from tanilo_receipt_verify.ed25519_guard import check_ed25519, decode_point, encode_point, point_mul, L

test_file, cases_file = sys.argv[1], sys.argv[2]

# Vectors: the nine in the package's own tests, read as text; cases 3, 4 and 5 from the published cases.txt.
src = open(test_file).read()
from_tests = {int(c): (m, p, s) for c, m, p, s, _ in re.findall(r'\((\d+), "([0-9a-f]{64})", "([0-9a-f]{64})", "([0-9a-f]{128})", "(\w+)"\)', src)}
lines = open(cases_file).read().split("\n")
published = {i: tuple(lines[1 + i * 3 + j][4:] for j in range(3)) for i in range(int(lines[0]))}
assert all(published[c] == v for c, v in from_tests.items()), "a vector in the tests differs from the published file"

NOTE = {0: "small A and R, S = 0", 1: "small A only", 2: "small R only", 3: "mixed-order A and R", 4: "mixed-order A and R", 5: "mixed-order A, R of order L",
        6: "S > L", 7: "S >> L", 8: "non-canonical R (small-order)", 9: "non-canonical R (small-order)", 10: "non-canonical A (small-order)", 11: "non-canonical A (small-order)"}

def backend_says(pbk, sig, msg):
    try:
        Ed25519PublicKey.from_public_bytes(pbk).verify(sig, msg); return "accepts"
    except InvalidSignature: return "rejects"
    except Exception as e: return "raises " + type(e).__name__

def two_steps(pbk, sig, msg):
    """What verify() does for one EdDSA signature: the guard, then the crypto library."""
    reason = check_ed25519(pbk, sig)
    if reason is not None: return "rejected", reason.split(":")[0], "guard"
    b = backend_says(pbk, sig, msg)
    return ("accepted", "", "library") if b == "accepts" else ("rejected", "(none: ordinary signature failure)", "library")

rows = []
for c in range(12):
    msg, pbk, sig = (bytes.fromhex(x) for x in published[c])
    outcome, code, by = two_steps(pbk, sig, msg)
    rows.append({"case": c, "what": NOTE[c], "vector_from": "package tests" if c in from_tests else "published cases.txt", "v021": outcome, "reason_code": code, "decided_by": by, "backend_alone": backend_says(pbk, sig, msg)})

# Through the public verify(): JWS envelopes, so the reason is read from the result a caller sees.
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def envelope(payload, kid, sig):
    return {"payload": b64u(json.dumps(payload, separators=(",", ":")).encode()), "signatures": [{"protected": b64u(json.dumps({"alg": "EdDSA", "kid": kid}, separators=(",", ":")).encode()), "signature": b64u(sig)}]}
def jwks(kid, raw): return {"https://issuer.example/jwks.json": {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64u(raw)}]}}
def signing_input(env): return (env["signatures"][0]["protected"] + "." + env["payload"]).encode("ascii")
def through_verify(env, keys):
    r = verify(env, jwks_by_issuer=keys); s = r.signers[0]
    return r.status, (s.get("reason") or "").split(":")[0]

identity = bytes([1]) + bytes(31); forged = identity + bytes(32)
api = []
for payload in ({"a": 1}, {"a": 2, "b": "a different message"}):
    env = envelope(payload, "k", forged); status, code = through_verify(env, jwks("k", identity))
    api.append({"input": f"identity key, R = identity, S = 0, payload {json.dumps(payload)}", "status": status, "reason_code": code, "backend_alone": backend_says(identity, forged, signing_input(env))})
# The published small-order key of cases 0/1 with a signature that satisfies the verification equation for a JWS signing input.
# S = 0 and R = k*A with k + h = 0 (mod 8), h = SHA-512(R || A || M): then S*B = R + h*A. A given message has such a k
# about two times in three, so successive payloads are tried until one does.
raw_a = bytes.fromhex(published[0][1]); a_pt, _ = decode_point(raw_a); sig = None
for n in range(64):
    payload = {"receipt": "shaped like ours", "n": n}; m = signing_input(envelope(payload, "k", bytes(64)))
    for k in range(8):
        r = encode_point(point_mul(k, a_pt)); h = int.from_bytes(hashlib.sha512(r + raw_a + m).digest(), "little") % L
        if (k + h) % 8 == 0: sig = r + bytes(32); break
    if sig is not None: break
env = envelope(payload, "k", sig); status, code = through_verify(env, jwks("k", raw_a))
api.append({"input": "the small-order key of cases 0/1 with an equation-valid signature for a JWS", "status": status, "reason_code": code, "backend_alone": backend_says(raw_a, sig, signing_input(env))})
ordinary = bytes.fromhex(published[2][1])   # the key of case 2: mixed-order, not small-order, passes the key checks
env = envelope({"a": 1}, "k", identity + (1).to_bytes(32, "little")); status, code = through_verify(env, jwks("k", ordinary))
api.append({"input": "a key that passes the key checks, signature with R = identity", "status": status, "reason_code": code, "backend_alone": backend_says(ordinary, identity + (1).to_bytes(32, "little"), signing_input(env))})
env = envelope({"a": 1}, "k", bytes.fromhex(published[3][2])[:32] + L.to_bytes(32, "little")); status, code = through_verify(env, jwks("k", ordinary))   # R of case 3 (not small-order), S = L
api.append({"input": "a key that passes the key checks, signature with S = L", "status": status, "reason_code": code, "backend_alone": "(not run)"})

env_line = f"tanilo-receipt-verify {trv.__version__}; cryptography {cryptography.__version__}; {backend.openssl_version_text()}; Python {sys.version.split()[0]}"
print(json.dumps({"environment": env_line, "cases": rows, "through_verify": api}, indent=1))
