"""jwks_is_complete: the two meanings of a missing key.

`jwks_by_issuer` on its own is ambiguous about what a missing kid means:
"this is every key I hold" (the caller's key set may simply be partial), or
"this is my complete trust list" (a kid not in it is a deliberate refusal).
This verifier cannot tell those apart on its own -- the caller has to say
which, via `jwks_is_complete`.

Converged on in the tsc#4 thread (2026-09-24): robertolocatelli81-dev's
`keys_are_complete` and babyblueviper1's `--referenced-set-is-complete` are
the same split under different names, applied to different artifacts
(a JWKS key set there; a referenced-proof set here). Credit to both --
this file exercises the same two vectors they described:

    unknown kid, key set NOT declared complete  -> unevaluated (indeterminate)
    unknown kid, key set declared complete      -> policy refusal (invalid)

The default (jwks_is_complete=False) must reproduce test_ac11_partial_jwks.py
exactly -- this file only adds the True-flag behavior and confirms the
False-flag default is unchanged by the new parameter existing at all.
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
    return _load("envelope-three-signer.json")


@pytest.fixture
def ao_jwks():
    return _load("jwks-agentoracle.json")


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
# Vector 1 — unresolved kid, jwks_is_complete NOT set (default False).
# Must be byte-for-byte the existing AC-11 partial-JWKS behavior.
# --------------------------------------------------------------------------

def test_unresolved_kid_default_is_still_indeterminate(three_signer_envelope, ao_jwks):
    """Default behavior is unchanged by the new parameter existing: an
    unresolved kid with jwks_is_complete left at its default (False) is
    still an unevaluated check, not a refusal."""
    two_signer = _two_signer(three_signer_envelope)
    result = verify(
        two_signer,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
    )
    assert result.status == STATUS_INDETERMINATE
    assert result.valid is None
    assert result.errors == []


def test_unresolved_kid_explicit_false_matches_default(three_signer_envelope, ao_jwks):
    """Passing jwks_is_complete=False explicitly must match the implicit
    default exactly -- the flag adds a new True path, it does not change
    what False means."""
    two_signer = _two_signer(three_signer_envelope)
    default_result = verify(
        two_signer,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
    )
    explicit_result = verify(
        two_signer,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
        jwks_is_complete=False,
    )
    assert explicit_result.status == default_result.status == STATUS_INDETERMINATE
    assert explicit_result.valid is default_result.valid is None
    assert explicit_result.errors == default_result.errors == []


# --------------------------------------------------------------------------
# Vector 2 — unresolved kid, jwks_is_complete=True.
# The declared-complete case: a missing key is now a policy refusal.
# --------------------------------------------------------------------------

def test_unresolved_kid_declared_complete_is_policy_refusal(
    three_signer_envelope, ao_jwks
):
    """Same input as the indeterminate case above, but the caller declares
    jwks_by_issuer complete. The unresolved kid is now a refusal: invalid,
    verified=False, and named in .errors."""
    two_signer = _two_signer(three_signer_envelope)
    unresolved_kid = _kid_of(two_signer["signatures"][1])

    result = verify(
        two_signer,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
        jwks_is_complete=True,
    )

    assert result.status == STATUS_INVALID, (
        "jwks_is_complete=True must turn an unresolved kid into a policy "
        f"refusal (invalid), got {result.status}"
    )
    assert result.valid is False
    assert result.errors, "the refusal must be named in .errors"
    assert any(unresolved_kid in e for e in result.errors), (
        f"expected the unresolved kid {unresolved_kid!r} named in an error, "
        f"got {result.errors}"
    )

    unresolved_signer = next(s for s in result.signers if s["kid"] == unresolved_kid)
    assert unresolved_signer["verified"] is False, (
        "declared-complete unresolved kid must report verified=False, not "
        "None -- that is the whole point of the flag"
    )


def test_declared_complete_does_not_affect_resolved_signer(
    three_signer_envelope, ao_jwks
):
    """The signer that WAS resolvable and genuinely verified must still
    report verified=True under jwks_is_complete=True -- the flag changes
    what a *missing* key means, not what a *found and checked* signature
    means."""
    two_signer = _two_signer(three_signer_envelope)
    result = verify(
        two_signer,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
        jwks_is_complete=True,
    )
    resolved = next(
        s for s in result.signers if s["issuer"] != "unresolved"
    )
    assert resolved["verified"] is True


def test_declared_complete_no_jwks_at_all_refuses_every_signer(
    three_signer_envelope,
):
    """jwks_is_complete=True with jwks_by_issuer entirely omitted: the
    caller has declared they trust no issuer at all. Every signer's kid is
    unresolved and every one is a refusal -- not the indeterminate result
    the omitted-JWKS case gets by default."""
    result = verify(three_signer_envelope, jwks_is_complete=True)
    assert result.status == STATUS_INVALID
    assert result.valid is False
    assert len(result.errors) == 3
    assert all(s["verified"] is False for s in result.signers)


def test_declared_complete_does_not_soften_a_genuine_crypto_failure(
    three_signer_envelope, ao_jwks
):
    """jwks_is_complete must never turn a real signature failure into
    anything other than invalid -- it only changes the missing-key case."""
    jws = three_signer_envelope.get("jws", three_signer_envelope)
    ao_sig = dict(jws["signatures"][0])
    ao_sig["signature"] = ao_sig["signature"][:-4] + "AAAA"  # corrupt it
    tampered_single = {"payload": jws["payload"], "signatures": [ao_sig]}

    result = verify(
        tampered_single,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
        jwks_is_complete=True,
    )
    assert result.status == STATUS_INVALID
    assert result.valid is False


def test_declared_complete_fully_resolvable_is_still_valid(
    three_signer_envelope, ao_jwks
):
    """The happy path is unaffected by the flag: every kid resolves, every
    signature genuinely verifies, jwks_is_complete=True changes nothing
    because there is no missing key to have an opinion about."""
    jws = three_signer_envelope.get("jws", three_signer_envelope)
    single_ok = {"payload": jws["payload"], "signatures": [jws["signatures"][0]]}

    result = verify(
        single_ok,
        jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
        jwks_is_complete=True,
    )
    assert result.status == STATUS_VALID
    assert result.valid is True
