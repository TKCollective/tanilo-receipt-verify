"""AC-11 regression suite: partial-JWKS on a multi-signer composed envelope.

The published `agentoracle-receipt-verify` 0.1.0 wheel treats an unresolved
signer's key (JWKS supplied for *some* but not *all* issuers on a multi-signer
envelope) as a genuine cryptographic failure: `verified: False`, which
`all_signatures_verified` then reads as a real failure and the adjudication
ranks above "unevaluated" -- collapsing a fully valid, partially-checkable
envelope to `status="invalid"`.

Confirmed empirically against the actual published wheel, not from memory:

    $ pip install agentoracle-receipt-verify==0.1.0
    >>> verify(two_signer_envelope, jwks_by_issuer={ao_issuer: ao_jwks_only})
    status: invalid
    valid: False
    errors: ['no JWK found for kid=at-fixture-v0.3-composed-2026-06']

This is the same failure class as the already-guarded no-JWKS-at-all case in
test_indeterminate_default.py, just triggered by a partial key set instead of
an empty one. This file is the missing regression test: it exercises the
partial-JWKS path directly rather than only the fully-omitted path, using a
real multi-signer fixture (`envelope-three-signer.json`, three genuine
Ed25519-signed signers: agentoracle.co, agenttrust.uk, presidio).

If this file's assertions are run against the 0.1.0 logic (unresolved kid ->
verified=False), test_partial_jwks_is_indeterminate_not_invalid and
test_unresolved_signer_is_not_in_errors both fail. Against the fixed
tanilo_receipt_verify.verify(), they pass. That is the regression this file
locks in.
"""

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tanilo_receipt_verify import verify  # noqa: E402
from tanilo_receipt_verify.verify import (  # noqa: E402
    STATUS_INDETERMINATE,
    STATUS_INVALID,
    STATUS_VALID,
)

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures" / "ac11"


def _load(name):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def three_signer_envelope():
    """Real production-shaped fixture: agentoracle.co, agenttrust.uk, presidio."""
    return _load("envelope-three-signer.json")


@pytest.fixture
def ao_jwks():
    return _load("jwks-agentoracle.json")


@pytest.fixture
def at_jwks():
    return _load("jwks-agenttrust.json")


@pytest.fixture
def presidio_jwks():
    return _load("jwks-presidio.json")


def _two_signer(envelope):
    jws = envelope.get("jws", envelope)
    return {"payload": jws["payload"], "signatures": jws["signatures"][:2]}


def _kid_of(sig_entry):
    import base64

    def b64d(s):
        pad = (-len(s)) % 4
        return base64.urlsafe_b64decode(s + "=" * pad)

    return json.loads(b64d(sig_entry["protected"]))["kid"]


# --------------------------------------------------------------------------
# THE REGRESSION GUARD for the partial-JWKS case. Confirmed to fail against
# the published 0.1.0 wheel; must pass here.
# --------------------------------------------------------------------------

def test_partial_jwks_is_indeterminate_not_invalid(three_signer_envelope, ao_jwks):
    """Envelope has 2 signers; only agentoracle.co's JWKS is supplied.

    0.1.0: status=invalid, valid=False, errors=['no JWK found for kid=...'].
    Fixed: status=indeterminate, valid=None, errors=[] (nothing failed --
    one signer just couldn't be checked).
    """
    two_signer = _two_signer(three_signer_envelope)
    result = verify(
        two_signer,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
    )

    assert result.status == STATUS_INDETERMINATE, (
        f"REGRESSION (AC-11 partial-JWKS case): expected indeterminate, got "
        f"{result.status}. This is the 0.1.0 bug: an unresolved signer's key "
        f"was scored as a cryptographic failure instead of an unevaluated check."
    )
    assert result.valid is None
    assert result.status != STATUS_INVALID


def test_unresolved_signer_is_not_in_errors(three_signer_envelope, ao_jwks):
    """A missing kid must never populate `errors` -- that field is reserved
    for checks that ran and failed, not checks that could not run."""
    two_signer = _two_signer(three_signer_envelope)
    result = verify(
        two_signer,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
    )
    assert result.errors == [], (
        "an unresolved kid must not be reported as an error; 0.1.0 put "
        "'no JWK found for kid=...' into errors, which the adjudication logic "
        "reads as a genuine failure"
    )


def test_partial_jwks_names_the_unresolved_kid(three_signer_envelope, ao_jwks):
    two_signer = _two_signer(three_signer_envelope)
    unresolved_kid = _kid_of(two_signer["signatures"][1])
    result = verify(
        two_signer,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
    )
    assert result.indeterminate_reason
    assert unresolved_kid in result.indeterminate_reason
    assert "not a failure" in result.indeterminate_reason.lower()


def test_partial_jwks_resolved_signer_still_reports_verified_true(
    three_signer_envelope, ao_jwks
):
    """The signer that WAS resolvable must still show verified=True -- the
    unresolved sibling must not drag a genuinely-checked-good signature down."""
    two_signer = _two_signer(three_signer_envelope)
    result = verify(
        two_signer,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
    )
    resolved = [s for s in result.signers if s["verified"] is not None]
    assert len(resolved) == 1
    assert resolved[0]["verified"] is True


# --------------------------------------------------------------------------
# The five other scenarios run by hand during the fix -- promoted to a
# permanent suite so they can't silently regress again.
# --------------------------------------------------------------------------

def test_all_omitted_on_multisigner_is_indeterminate(three_signer_envelope):
    """jwks_by_issuer entirely omitted on a 3-signer envelope: same as the
    existing single-signer regression guard, checked here on multi-signer."""
    result = verify(three_signer_envelope)
    assert result.status == STATUS_INDETERMINATE
    assert result.valid is None
    assert result.errors == []


def test_empty_dict_jwks_is_indeterminate(three_signer_envelope):
    """jwks_by_issuer={} (present but empty) must behave like omitted, not
    like 'here is key material and none of it matched' being scored as fail."""
    result = verify(three_signer_envelope, jwks_by_issuer={})
    assert result.status == STATUS_INDETERMINATE
    assert result.valid is None


def test_genuine_crypto_failure_with_key_present_is_invalid(
    three_signer_envelope, ao_jwks
):
    """A real signature failure (tampered bytes, key IS resolvable) must
    still return invalid -- the AC-11 fix must not soften an actual failure
    into indeterminate. This is the case the fix must not over-correct."""
    jws = three_signer_envelope.get("jws", three_signer_envelope)
    ao_sig = dict(jws["signatures"][0])
    ao_sig["signature"] = ao_sig["signature"][:-4] + "AAAA"  # corrupt it
    tampered_single = {"payload": jws["payload"], "signatures": [ao_sig]}

    result = verify(
        tampered_single,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
    )
    assert result.status == STATUS_INVALID
    assert result.valid is False
    assert result.errors


def test_mixed_failure_and_unresolved_stays_invalid(three_signer_envelope, ao_jwks):
    """One genuine failure + one unresolved key: failure must outrank
    unresolved. A real defect must never be masked by an unrelated gap in
    key material."""
    jws = three_signer_envelope.get("jws", three_signer_envelope)
    ao_sig = dict(jws["signatures"][0])
    ao_sig["signature"] = ao_sig["signature"][:-4] + "AAAA"
    presidio_sig = jws["signatures"][2]  # key not supplied below -> unresolved
    mixed = {"payload": jws["payload"], "signatures": [ao_sig, presidio_sig]}

    result = verify(
        mixed,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
    )
    assert result.status == STATUS_INVALID, (
        "a genuine signature failure must outrank an unresolved key, not be "
        "diluted by it"
    )
    assert result.valid is False
    assert result.errors


def test_fully_resolvable_single_signer_is_valid(three_signer_envelope, ao_jwks):
    """Belt and braces: the happy path (one signer, key present, signature
    genuinely valid) must still return valid -- guards against the fix
    over-correcting into permanent indeterminate."""
    jws = three_signer_envelope.get("jws", three_signer_envelope)
    single_ok = {"payload": jws["payload"], "signatures": [jws["signatures"][0]]}

    result = verify(
        single_ok,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
    )
    assert result.status == STATUS_VALID
    assert result.valid is True
    assert result.checks["all_signatures_verified"] is True


def test_all_three_signers_fully_resolvable_is_valid(
    three_signer_envelope, ao_jwks, at_jwks, presidio_jwks
):
    """Full production shape: three real signers, all three JWKS supplied,
    all three signatures genuinely verify."""
    result = verify(
        three_signer_envelope,
        jwks_by_issuer={
            "https://agentoracle.co/.well-known/jwks.json": ao_jwks,
            "https://agenttrust.uk/.well-known/jwks.json": at_jwks,
            "https://presidio.example/.well-known/jwks.json": presidio_jwks,
        },
    )
    assert result.status == STATUS_VALID
    assert result.valid is True
    assert len(result.signers) == 3
    assert all(s["verified"] is True for s in result.signers)
