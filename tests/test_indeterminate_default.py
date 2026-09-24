"""Reject-shaped tests for the no-key-material default path.

These exist to make one specific regression impossible: `verify()` returning a
truthy `valid` on a signed envelope whose signatures were never checked.

That bug shipped in 0.0.1. It was not caught by the existing suite because the
suite always supplied JWKS, exercising only the happy path. A caller following
the published README could `pip install`, call `verify(envelope)`, and receive
`valid=True` having verified nothing.

The failure is doubly harmful and asymmetric:

  - A skeptic sees `signers=[]` and concludes the verifier does not check
    signatures at all -- a credible one-click falsification of the project's
    central claim, produced by following our own instructions.
  - A supporter sees `valid=True` and publicly reports verifying a receipt they
    did not verify. An uncorrected false confirmation is indistinguishable from
    a false claim.

Design rule enforced here mirrors spec Sec 3.5: an unevaluated property is an
honest named state and MUST NOT be defaulted into either neighbor.
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

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


def _load(name):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def signed_envelope():
    """A genuine production envelope with real Ed25519 signatures."""
    return _load("signed_envelope.json")


@pytest.fixture
def jwks_map(signed_envelope):
    return _load("jwks_by_issuer.json")


# --------------------------------------------------------------------------
# THE REGRESSION GUARD. If only one test in this file survives, keep this one.
# --------------------------------------------------------------------------

def test_no_jwks_must_never_report_valid_true(signed_envelope):
    """The exact 0.0.1 bug. A signed envelope + no keys MUST NOT be `valid`."""
    result = verify(signed_envelope)

    assert result.valid is not True, (
        "REGRESSION: verify() reported valid=True on a signed envelope with "
        "zero signatures checked. Recompute-invariants alone do not bind a "
        "payload to an issuer."
    )
    assert result.status != STATUS_VALID


def test_no_jwks_is_indeterminate_not_invalid(signed_envelope):
    """Unchecked is not the same as failed. Do not default into the neighbor."""
    result = verify(signed_envelope)

    assert result.status == STATUS_INDETERMINATE
    assert result.valid is None, "valid must be None (tri-state), not False"
    assert result.errors == [], "nothing failed; there should be no errors"


def test_indeterminate_is_falsy_so_legacy_callers_fail_closed(signed_envelope):
    """`if result.valid:` written against 0.0.1 must now take the safe branch."""
    result = verify(signed_envelope)
    assert not result.valid


def test_indeterminate_reason_names_the_missing_input(signed_envelope):
    result = verify(signed_envelope)

    assert result.indeterminate_reason
    assert "jwks_by_issuer" in result.indeterminate_reason


def test_unchecked_signatures_are_none_never_false(signed_envelope):
    """`verified: False` would assert a disproof that never happened."""
    result = verify(signed_envelope)

    assert result.signers, "signers should still be enumerated so the caller sees what was skipped"
    for signer in result.signers:
        assert signer["verified"] is None, (
            "an unchecked signature must report None; False asserts a failed "
            "verification that was never attempted"
        )

    assert result.checks.get("all_signatures_verified") is None
    assert "all_signatures_verified" in result.checks, (
        "the key must be present-and-None rather than absent, so callers "
        "inspecting checks see the unevaluated state explicitly"
    )


def test_canonical_hash_still_computed_when_indeterminate(signed_envelope):
    """Indeterminate is not an error path; useful output is still produced."""
    result = verify(signed_envelope)

    assert result.canonical_sha256.startswith("sha256-")
    assert result.checks.get("canonical_recomputes") is True


# --------------------------------------------------------------------------
# The happy path must be unchanged -- guards against over-correction.
# --------------------------------------------------------------------------

def test_with_jwks_still_returns_valid(signed_envelope, jwks_map):
    result = verify(signed_envelope, jwks_map)

    assert result.status == STATUS_VALID
    assert result.valid is True
    assert result.checks["all_signatures_verified"] is True
    assert result.signers and all(s["verified"] is True for s in result.signers)
    assert result.indeterminate_reason is None


def test_tampered_payload_with_jwks_is_invalid_not_indeterminate(signed_envelope, jwks_map):
    """A real signature failure must still be `invalid`, never softened."""
    import base64
    import copy

    tampered = copy.deepcopy(signed_envelope)
    jws = tampered.get("jws", tampered)

    raw = base64.urlsafe_b64decode(jws["payload"] + "=" * ((-len(jws["payload"])) % 4))
    payload = json.loads(raw)
    payload["_tampered"] = True
    jws["payload"] = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )

    result = verify(tampered, jwks_map)

    assert result.status == STATUS_INVALID
    assert result.valid is False
    assert result.errors


def test_tampered_payload_without_jwks_is_still_not_valid(signed_envelope):
    """Belt and braces: tampering plus no keys must not slip through as valid."""
    import base64
    import copy

    tampered = copy.deepcopy(signed_envelope)
    jws = tampered.get("jws", tampered)
    raw = base64.urlsafe_b64decode(jws["payload"] + "=" * ((-len(jws["payload"])) % 4))
    payload = json.loads(raw)
    payload["_tampered"] = True
    jws["payload"] = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )

    result = verify(tampered)
    assert result.valid is not True
