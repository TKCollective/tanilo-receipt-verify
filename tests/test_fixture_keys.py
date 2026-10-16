"""Test and fixture keys are refused by default (0.2.4).

Why. Tanilo's published key set carried, until 2026-10-16, a key whose
private half is published on purpose in the spec repo (kid
ao-fixture-detached-rfc7797-2026-07-ed25519-0f8bf2a5, tanilo_status
"fixture"). A receipt anyone can sign with that key verified as "valid"
against the production key set in 0.2.3: the result named the kid in
`signers`, but a caller that reads only `status` was fooled. A key set
is a list of keys that may verify; a key that anyone can sign with must
not count, unless the caller asks for it.

Rule (0.2.4). A JWK whose `tanilo_status` is "fixture" or "test", or whose
kid is in `KNOWN_FIXTURE_KIDS`, is refused before its signature is
checked: the signer is recorded with `verified: False` and a reason
starting `fixture_key_refused`, an error names the kid, and the result
is `invalid`. `verify(..., allow_test_keys=True)` turns the refusal off
for callers that verify fixtures on purpose. Every other key is handled
exactly as before.
"""

import base64
import copy
import json
import pathlib
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tanilo_receipt_verify import verify  # noqa: E402
from tanilo_receipt_verify.verify import (  # noqa: E402
    FIXTURE_KEY_STATUSES,
    KNOWN_FIXTURE_KIDS,
    STATUS_INVALID,
    STATUS_VALID,
)

FIX = pathlib.Path(__file__).resolve().parent / "fixtures" / "aer1"
JWKS_URL = "https://tanilo.io/.well-known/jwks.json"
PUBLISHED_FIXTURE_KID = "ao-fixture-detached-rfc7797-2026-07-ed25519-0f8bf2a5"
PRODUCTION_KID = "tanilo-2026-10-ed25519-7d885da9"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@pytest.fixture
def aer1():
    """The live AER-1 receipt and the key set saved with it (which lists the
    published fixture key with tanilo_status "fixture", as the live set did)."""
    receipt = json.loads((FIX / "receipt.jws.json").read_text())
    jwks = json.loads((FIX / "jwks-tanilo-io-2026-10-08.json").read_text())
    assert any(k["kid"] == PUBLISHED_FIXTURE_KID and k.get("tanilo_status") == "fixture" for k in jwks["keys"])
    return receipt, jwks


def _resign(receipt, kid, private_key):
    """The receipt's own payload and header, re-signed under `kid` with `private_key`.
    This is exactly what anyone holding a published private key can do."""
    header = json.loads(b64d(receipt["signatures"][0]["protected"]))
    header["kid"] = kid
    protected = b64u(json.dumps(header, separators=(",", ":")).encode())
    sig = private_key.sign((protected + "." + receipt["payload"]).encode("ascii"))
    return {"payload": receipt["payload"], "signatures": [{"protected": protected, "signature": b64u(sig)}]}


def _jwk(kid, public_key, **extra):
    from cryptography.hazmat.primitives import serialization

    x = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64u(x), "alg": "EdDSA", "use": "sig", **extra}


@pytest.fixture
def test_key():
    """A fresh key, generated here, published in the key set as a fixture."""
    sk = Ed25519PrivateKey.generate()
    return sk, _jwk("fixture-generated-in-test-2026-10-16", sk.public_key(), tanilo_status="fixture")


def test_constants_name_the_published_fixture_key():
    assert PUBLISHED_FIXTURE_KID in KNOWN_FIXTURE_KIDS
    assert set(FIXTURE_KEY_STATUSES) == {"fixture", "test"}


def test_production_receipt_is_still_valid_with_the_fixture_key_in_the_key_set(aer1):
    receipt, jwks = aer1
    r = verify(receipt, jwks_by_issuer={JWKS_URL: jwks})
    assert r.status == STATUS_VALID and r.valid is True
    assert r.signers == [{"kid": PRODUCTION_KID, "issuer": JWKS_URL, "verified": True}]
    assert r.errors == []


def test_status_fixture_key_is_refused_by_default(aer1, test_key):
    receipt, jwks = aer1
    sk, jwk = test_key
    forged = _resign(receipt, jwk["kid"], sk)
    r = verify(forged, jwks_by_issuer={JWKS_URL: {"keys": jwks["keys"] + [jwk]}})
    assert r.status == STATUS_INVALID and r.valid is False
    assert len(r.signers) == 1
    s = r.signers[0]
    assert s["kid"] == jwk["kid"] and s["issuer"] == JWKS_URL and s["verified"] is False
    assert s["reason"] == ("fixture_key_refused: this key is marked tanilo_status='fixture' and is not accepted by default; "
                           "use allow_test_keys=True only for intentional fixture verification, not to establish production issuance")
    assert f"fixture key refused: kid={jwk['kid']} is marked or identified as a test key and is not accepted under the default policy" in r.errors
    assert r.canonical_sha256.startswith("sha256-")


def test_status_fixture_key_verifies_when_the_caller_allows_test_keys(aer1, test_key):
    receipt, jwks = aer1
    sk, jwk = test_key
    forged = _resign(receipt, jwk["kid"], sk)
    r = verify(forged, jwks_by_issuer={JWKS_URL: {"keys": jwks["keys"] + [jwk]}}, allow_test_keys=True)
    assert r.status == STATUS_VALID and r.valid is True
    assert r.signers == [{"kid": jwk["kid"], "issuer": JWKS_URL, "verified": True}]


def test_status_test_is_refused_too(aer1, test_key):
    receipt, jwks = aer1
    sk, jwk = test_key
    jwk = {**jwk, "tanilo_status": "test"}
    forged = _resign(receipt, jwk["kid"], sk)
    r = verify(forged, jwks_by_issuer={JWKS_URL: {"keys": [jwk]}})
    assert r.status == STATUS_INVALID
    assert r.signers[0]["reason"].startswith("fixture_key_refused: this key is marked tanilo_status='test'")


def test_known_fixture_kid_is_refused_even_without_a_status_member(aer1):
    """The published fixture key as a bare JWK (no tanilo_* members), as older
    key-set copies list it. Refused by kid, before any signature is checked:
    the reason is the refusal, not a signature failure."""
    receipt, jwks = aer1
    bare = {k: v for k, v in next(k for k in jwks["keys"] if k["kid"] == PUBLISHED_FIXTURE_KID).items() if not k.startswith("tanilo_")}
    assert "tanilo_status" not in bare
    header = json.loads(b64d(receipt["signatures"][0]["protected"]))
    header["kid"] = PUBLISHED_FIXTURE_KID
    protected = b64u(json.dumps(header, separators=(",", ":")).encode())
    env = {"payload": receipt["payload"], "signatures": [{"protected": protected, "signature": b64u(b"\0" * 64)}]}
    r = verify(env, jwks_by_issuer={JWKS_URL: {"keys": [bare]}})
    assert r.status == STATUS_INVALID
    assert r.signers[0]["verified"] is False
    assert r.signers[0]["reason"] == ("fixture_key_refused: this kid identifies a known fixture key whose private key is public; "
                                      "use allow_test_keys=True only for intentional fixture verification, not to establish production issuance")
    assert not any("signature verify failed" in e for e in r.errors)
    # With the flag, the signature is checked, and this one (all zeros) fails as an ordinary bad signature.
    r2 = verify(env, jwks_by_issuer={JWKS_URL: {"keys": [bare]}}, allow_test_keys=True)
    assert r2.status == STATUS_INVALID
    assert any(e.startswith("signature verify failed") for e in r2.errors)


def test_refusal_also_applies_with_jwks_is_complete(aer1, test_key):
    receipt, jwks = aer1
    sk, jwk = test_key
    forged = _resign(receipt, jwk["kid"], sk)
    r = verify(forged, jwks_by_issuer={JWKS_URL: {"keys": [jwk]}}, jwks_is_complete=True)
    assert r.status == STATUS_INVALID
    assert r.signers[0]["reason"].startswith("fixture_key_refused")
    assert not any("kid not found" in e for e in r.errors)


def test_a_composed_envelope_with_one_fixture_signer_is_invalid(aer1, test_key):
    """A real signature plus a fixture-key signature over the same payload:
    the fixture signer is refused (False), which outranks the valid one."""
    receipt, jwks = aer1
    sk, jwk = test_key
    forged = _resign(receipt, jwk["kid"], sk)
    env = copy.deepcopy(receipt)
    env["signatures"].append(forged["signatures"][0])
    r = verify(env, jwks_by_issuer={JWKS_URL: {"keys": jwks["keys"] + [jwk]}})
    assert r.status == STATUS_INVALID
    assert [s["verified"] for s in r.signers] == [True, False]


def test_allow_test_keys_does_not_change_any_other_result(aer1):
    receipt, jwks = aer1
    a = verify(receipt, jwks_by_issuer={JWKS_URL: jwks})
    b = verify(receipt, jwks_by_issuer={JWKS_URL: jwks}, allow_test_keys=True)
    assert (a.status, a.signers, a.errors, a.canonical_sha256) == (b.status, b.signers, b.errors, b.canonical_sha256)
    tampered = copy.deepcopy(receipt)
    tampered["payload"] = tampered["payload"][:-2] + ("AA" if not tampered["payload"].endswith("AA") else "BB")
    assert verify(tampered, jwks_by_issuer={JWKS_URL: jwks}, allow_test_keys=True).status == STATUS_INVALID
