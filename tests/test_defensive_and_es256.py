"""Regression suite for the 2026-09-23 review round.

Covers, one test each:

1. ES256 (P-256) signatures actually verify (not just "don't crash") --
   Section 5.1 of draft-krausz-verification-state-02 requires accepting
   both EdDSA and ES256; 0.1.0-class code only implemented EdDSA and
   reported any ES256 receipt as invalid ("unsupported alg").
2. decision_signer_ne_runtime records None (not False) when either issuer
   is simply absent -- the check never ran, so it isn't a failure.
3. A non-dict v_gate (a string, a number) no longer crashes verify() with
   an uncaught AttributeError.
4. A JWKS entry whose kid matches but whose key material is malformed
   (wrong-length Ed25519 x, or an unsupported kty/crv) no longer crashes
   verify() with an uncaught exception -- it resolves to verified=None,
   same treatment as a kid that was never found at all.
5. A garbled (non-base64url) signature string no longer crashes verify()
   -- it resolves to verified=False (a real, evaluated failure: a key WAS
   found, an actual check WAS attempted, and it did not produce a valid
   signature).
6. An algorithm this verifier doesn't implement (anything outside
   {EdDSA, ES256}) is reported as verified=None with a reason, never as
   an error / False finding against the receipt.

Every test in this file calls the public verify() entry point end to end
and asserts it RETURNS a VerifyResult rather than raising -- "the verifier
always answers" is the property under test, not just "no exception."
"""

import base64
import json
import pathlib
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tanilo_receipt_verify import verify  # noqa: E402
from tanilo_receipt_verify.verify import (  # noqa: E402
    STATUS_INDETERMINATE,
    STATUS_INVALID,
    STATUS_VALID,
)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_json(obj) -> str:
    return _b64u(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _minimal_payload(**overrides):
    payload = {
        "receipt_version": "0.3",
        "envelope_kind": "single",
        "subject": {"claim_hash": "sha256-" + "0" * 64},
    }
    payload.update(overrides)
    return payload


def _make_ed25519_signer(kid="test-ed25519-kid"):
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    raw_pub = pk.public_bytes_raw() if hasattr(pk, "public_bytes_raw") else pk.public_bytes(
        __import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        __import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
    )
    jwk = {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": _b64u(raw_pub)}

    def sign(protected_b64, payload_b64):
        signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
        return _b64u(sk.sign(signing_input))

    return jwk, sign


def _make_es256_signer(kid="test-es256-kid"):
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = sk.public_key()
    numbers = pk.public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    jwk = {"kty": "EC", "crv": "P-256", "kid": kid, "x": _b64u(x), "y": _b64u(y)}

    def sign(protected_b64, payload_b64):
        signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
        der_sig = sk.sign(signing_input, ECDSA(SHA256()))
        r, s = __import__("cryptography").hazmat.primitives.asymmetric.utils.decode_dss_signature(der_sig)
        return _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    return jwk, sign


def _build_envelope(payload, signers):
    """signers: list of (alg, jwk, sign_fn) -> returns (envelope, jwks_by_issuer)."""
    payload_b64 = _b64u_json(payload)
    signatures = []
    keys_by_issuer = {}
    for alg, jwk, sign_fn in signers:
        protected_b64 = _b64u_json({"alg": alg, "kid": jwk["kid"], "typ": "application/vnd.verification+jws"})
        sig_b64 = sign_fn(protected_b64, payload_b64)
        signatures.append({"protected": protected_b64, "signature": sig_b64})
        issuer_url = f"https://issuer-{jwk['kid']}.example/.well-known/jwks.json"
        keys_by_issuer[issuer_url] = {"keys": [jwk]}
    return {"payload": payload_b64, "signatures": signatures}, keys_by_issuer


# ── 1. ES256 actually verifies ──────────────────────────────────────────

def test_es256_signature_verifies_true():
    jwk, sign_fn = _make_es256_signer()
    envelope, jwks_by_issuer = _build_envelope(_minimal_payload(), [("ES256", jwk, sign_fn)])
    result = verify(envelope, jwks_by_issuer=jwks_by_issuer)
    assert result.status == STATUS_VALID, (
        f"ES256 receipt should verify as valid per Section 5.1 (MUST accept "
        f"ES256), got status={result.status} errors={result.errors}"
    )
    assert result.signers[0]["verified"] is True


def test_es256_tampered_signature_is_invalid_not_crash():
    jwk, sign_fn = _make_es256_signer()
    envelope, jwks_by_issuer = _build_envelope(_minimal_payload(), [("ES256", jwk, sign_fn)])
    # Flip a byte in the signature -- still valid base64url, still wrong length
    # is NOT the point here; this must fail cryptographic verification, not
    # crash.
    tampered = bytearray(base64.urlsafe_b64decode(envelope["signatures"][0]["signature"] + "=="))
    tampered[0] ^= 0xFF
    envelope["signatures"][0]["signature"] = base64.urlsafe_b64encode(bytes(tampered)).rstrip(b"=").decode("ascii")
    result = verify(envelope, jwks_by_issuer=jwks_by_issuer)
    assert result.status == STATUS_INVALID
    assert result.signers[0]["verified"] is False


def test_mixed_eddsa_and_es256_signers_both_verify():
    ed_jwk, ed_sign = _make_ed25519_signer("kid-ed")
    ec_jwk, ec_sign = _make_es256_signer("kid-ec")
    envelope, jwks_by_issuer = _build_envelope(
        _minimal_payload(), [("EdDSA", ed_jwk, ed_sign), ("ES256", ec_jwk, ec_sign)]
    )
    result = verify(envelope, jwks_by_issuer=jwks_by_issuer)
    assert result.status == STATUS_VALID
    verified_by_kid = {s["kid"]: s["verified"] for s in result.signers}
    assert verified_by_kid["kid-ed"] is True
    assert verified_by_kid["kid-ec"] is True


# ── 2. decision_signer_ne_runtime: missing issuer(s) -> None, not False ──

def test_decision_signer_ne_runtime_none_when_runtime_issuer_missing():
    jwk, sign_fn = _make_ed25519_signer()
    payload = _minimal_payload(
        decision_ref={
            "decision_ref_preimage_fields": ["issuer"],
            "issuer": "some-decision-issuer",
            "decision_ref": None,  # will be wrong on purpose; not the focus here
        },
        v_gate={},  # no "issuer" key at all -- runtime_issuer is None
    )
    # Fix decision_ref to actually recompute correctly so this check isn't
    # drowned out by an unrelated decision_ref_recomputes failure.
    from tanilo_receipt_verify.verify import recompute_decision_ref
    payload["decision_ref"]["decision_ref"] = recompute_decision_ref(payload["decision_ref"])

    envelope, jwks_by_issuer = _build_envelope(payload, [("EdDSA", jwk, sign_fn)])
    result = verify(envelope, jwks_by_issuer=jwks_by_issuer)
    assert result.checks["decision_signer_ne_runtime"] is None, (
        f"expected None (check could not run -- runtime issuer absent), got "
        f"{result.checks.get('decision_signer_ne_runtime')!r}"
    )
    assert not any("decision signer == runtime" in e for e in result.errors), (
        "an unevaluated check must never be added to errors"
    )


def test_decision_signer_ne_runtime_none_when_decision_issuer_missing():
    jwk, sign_fn = _make_ed25519_signer()
    payload = _minimal_payload(
        decision_ref={
            "decision_ref_preimage_fields": ["mapping_id"],
            "mapping_id": "x",
            "decision_ref": None,
            # no "issuer" key on the decision_ref slot itself
        },
        v_gate={"issuer": "runtime-issuer"},
    )
    from tanilo_receipt_verify.verify import recompute_decision_ref
    payload["decision_ref"]["decision_ref"] = recompute_decision_ref(payload["decision_ref"])

    envelope, jwks_by_issuer = _build_envelope(payload, [("EdDSA", jwk, sign_fn)])
    result = verify(envelope, jwks_by_issuer=jwks_by_issuer)
    assert result.checks["decision_signer_ne_runtime"] is None


# ── 3. v_gate as a non-dict must not crash ──────────────────────────────

@pytest.mark.parametrize("bad_v_gate", ["not-a-dict", 42, ["a", "list"], True])
def test_non_dict_v_gate_does_not_crash(bad_v_gate):
    jwk, sign_fn = _make_ed25519_signer()
    payload = _minimal_payload(
        decision_ref={
            "decision_ref_preimage_fields": ["mapping_id"],
            "mapping_id": "x",
            "issuer": "decision-issuer",
            "decision_ref": None,
        },
        v_gate=bad_v_gate,
    )
    from tanilo_receipt_verify.verify import recompute_decision_ref
    payload["decision_ref"]["decision_ref"] = recompute_decision_ref(payload["decision_ref"])

    envelope, jwks_by_issuer = _build_envelope(payload, [("EdDSA", jwk, sign_fn)])
    # Must return a result, not raise.
    result = verify(envelope, jwks_by_issuer=jwks_by_issuer)
    assert result.checks["decision_signer_ne_runtime"] is None, (
        "a non-dict v_gate means runtime_issuer cannot be read -- None, not a crash and not False"
    )


# ── 4. Malformed key material behind a matching kid must not crash ─────

def test_malformed_ed25519_key_length_does_not_crash():
    jwk, sign_fn = _make_ed25519_signer("bad-key-kid")
    envelope, jwks_by_issuer = _build_envelope(_minimal_payload(), [("EdDSA", jwk, sign_fn)])
    # Corrupt the JWK's x value to the wrong length after signing.
    issuer_url = list(jwks_by_issuer.keys())[0]
    jwks_by_issuer[issuer_url]["keys"][0]["x"] = _b64u(b"too-short")

    result = verify(envelope, jwks_by_issuer=jwks_by_issuer)
    assert result.status == STATUS_INDETERMINATE, (
        f"a matching kid with malformed key material must resolve to "
        f"indeterminate (verified=None), not crash and not a hard invalid; "
        f"got status={result.status}"
    )
    assert result.signers[0]["verified"] is None
    assert "reason" in result.signers[0]


def test_unsupported_kty_does_not_crash():
    jwk, sign_fn = _make_ed25519_signer("weird-key-kid")
    envelope, jwks_by_issuer = _build_envelope(_minimal_payload(), [("EdDSA", jwk, sign_fn)])
    issuer_url = list(jwks_by_issuer.keys())[0]
    jwks_by_issuer[issuer_url]["keys"][0] = {"kty": "RSA", "kid": jwk["kid"], "n": "abc", "e": "AQAB"}

    result = verify(envelope, jwks_by_issuer=jwks_by_issuer)
    assert result.status == STATUS_INDETERMINATE
    assert result.signers[0]["verified"] is None


# ── 5. Garbled signature text must not crash ────────────────────────────

def test_garbled_signature_text_does_not_crash():
    jwk, sign_fn = _make_ed25519_signer()
    envelope, jwks_by_issuer = _build_envelope(_minimal_payload(), [("EdDSA", jwk, sign_fn)])
    envelope["signatures"][0]["signature"] = "!!!not-valid-base64url-at-all!!!"

    result = verify(envelope, jwks_by_issuer=jwks_by_issuer)
    assert result.status == STATUS_INVALID, (
        f"a key WAS resolved and a check WAS attempted -- a garbled signature "
        f"string is a real, evaluated failure (False), not a crash and not "
        f"an unevaluated None; got status={result.status}"
    )
    assert result.signers[0]["verified"] is False


# ── 6. Unsupported algorithm -> None with reason, never an error/False ──

def test_unsupported_algorithm_is_none_not_error():
    jwk, sign_fn = _make_ed25519_signer()
    envelope, jwks_by_issuer = _build_envelope(_minimal_payload(), [("EdDSA", jwk, sign_fn)])
    # Rewrite the protected header to claim an algorithm we don't implement,
    # signature payload left as-is (irrelevant -- it must never be checked).
    protected = json.loads(base64.urlsafe_b64decode(envelope["signatures"][0]["protected"] + "=="))
    protected["alg"] = "HS256"
    envelope["signatures"][0]["protected"] = _b64u_json(protected)

    result = verify(envelope, jwks_by_issuer=jwks_by_issuer)
    assert result.status == STATUS_INDETERMINATE, (
        f"an algorithm this verifier doesn't implement is a verifier "
        f"limitation, not an invalid receipt; got status={result.status} "
        f"errors={result.errors}"
    )
    assert result.signers[0]["verified"] is None
    assert not any("unsupported alg" in e or "HS256" in e for e in result.errors), (
        "an unimplemented algorithm must never be recorded in errors"
    )
