"""verify() must never raise -- 0.1.1, per stillmarcus24's report (tsc#4, 2026-09-24).

He threw 30 malformed envelopes at 0.1.0 and got a traceback on 22 of them. His
point cuts to the spec, not just the code: an exception is not one of
draft-krausz-verification-state-02's four states (Section 3). A caller that
catches a traceback cannot distinguish `contradicted` from `instrument_failure`
-- so a verifier that raises has silently opted out of the vocabulary it
implements.

This file is the malformed-input corpus that must never raise, in either the
no-jwks or with-jwks configuration, and never softens into anything other than
`invalid` or `indeterminate`.

A companion negative control (`test_negative_control_0_1_0_still_raises`)
targets 0.1.0's actual pre-fix logic shape -- see its docstring -- and asserts
it DOES still raise, so this suite proves the fix rather than a corpus that
happened to pass either way.
"""

import json
import sys
import pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tanilo_receipt_verify import verify  # noqa: E402
from tanilo_receipt_verify.verify import STATUS_INVALID, STATUS_INDETERMINATE  # noqa: E402

FAKE_JWKS = {"https://example.com/.well-known/jwks.json": {"keys": []}}

# -- malformed envelope-level shapes -----------------------------------------
MALFORMED_ENVELOPES = [
    pytest.param([1, 2, 3], id="envelope-is-list"),
    pytest.param("not-an-envelope", id="envelope-is-string"),
    pytest.param(42, id="envelope-is-int"),
    pytest.param(3.14, id="envelope-is-float"),
    pytest.param(None, id="envelope-is-none"),
    pytest.param(True, id="envelope-is-bool"),
    pytest.param(set([1, 2]), id="envelope-is-set"),
    pytest.param({"jws": [1, 2, 3]}, id="jws-is-list"),
    pytest.param({"jws": "not-a-dict"}, id="jws-is-string"),
    pytest.param({"jws": 5}, id="jws-is-int"),
    pytest.param({"jws": None}, id="jws-is-none-explicit"),
    pytest.param({"jws": True}, id="jws-is-bool"),
]

# -- malformed `payload` shapes (envelope otherwise well-formed) -------------
MALFORMED_PAYLOADS = [
    pytest.param({"payload": 5, "signatures": [{"protected": "", "signature": ""}]}, id="payload-is-int"),
    pytest.param({"payload": [1, 2], "signatures": [{"protected": "", "signature": ""}]}, id="payload-is-list"),
    pytest.param({"payload": {"a": 1}, "signatures": [{"protected": "", "signature": ""}]}, id="payload-is-dict"),
    pytest.param({"payload": True, "signatures": [{"protected": "", "signature": ""}]}, id="payload-is-bool"),
]

# -- malformed `signatures` shapes (payload otherwise well-formed) -----------
MALFORMED_SIGNATURES = [
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": "not-a-list"}, id="signatures-is-string"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": 5}, id="signatures-is-int"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": {"a": 1}}, id="signatures-is-dict"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": True}, id="signatures-is-bool"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": None}, id="signatures-is-none"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": ["not-a-dict"]}, id="signatures-list-of-string"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": [42]}, id="signatures-list-of-int"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": [None]}, id="signatures-list-of-none"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": [[1, 2]]}, id="signatures-list-of-list"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": [True]}, id="signatures-list-of-bool"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": [{"protected": 5, "signature": "x"}]}, id="protected-is-int"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": [{"protected": [1], "signature": "x"}]}, id="protected-is-list"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": [{"protected": "x", "signature": 5}]}, id="signature-is-int"),
    pytest.param({"payload": "eyJhIjoxfQ", "signatures": [{}]}, id="signature-entry-missing-both-keys"),
]

ALL_MALFORMED = MALFORMED_ENVELOPES + MALFORMED_PAYLOADS + MALFORMED_SIGNATURES

assert len(ALL_MALFORMED) >= 30, f"corpus has {len(ALL_MALFORMED)} cases, need at least 30"


@pytest.mark.parametrize("envelope", ALL_MALFORMED)
def test_never_raises_no_jwks(envelope):
    """Every malformed shape returns a VerifyResult -- never raises -- when
    called with no jwks_by_issuer (0.1.0's crash mode on 22/30 of these)."""
    result = verify(envelope)  # must not raise
    assert result.status in (STATUS_INVALID, STATUS_INDETERMINATE)
    assert result.valid is not True


@pytest.mark.parametrize("envelope", ALL_MALFORMED)
def test_never_raises_with_jwks(envelope):
    """Same corpus, called with jwks_by_issuer supplied -- the configuration
    that made 363-364's unguarded sig_entry.get() crash in 0.1.0."""
    result = verify(envelope, jwks_by_issuer=FAKE_JWKS)  # must not raise
    assert result.status in (STATUS_INVALID, STATUS_INDETERMINATE)
    assert result.valid is not True


@pytest.mark.parametrize("envelope", ALL_MALFORMED)
def test_never_raises_jwks_is_complete(envelope):
    """Same corpus again with jwks_is_complete=True, the newest branch --
    must not raise or accidentally report valid."""
    result = verify(envelope, jwks_by_issuer=FAKE_JWKS, jwks_is_complete=True)  # must not raise
    assert result.status in (STATUS_INVALID, STATUS_INDETERMINATE)
    assert result.valid is not True


def test_envelope_not_dict_reports_specific_error():
    """A non-dict envelope is a definite, checkable fact -- invalid with a
    specific error, not a vague catch-all."""
    result = verify([1, 2, 3])
    assert result.status == STATUS_INVALID
    assert result.errors
    assert "dict" in result.errors[0] or "object" in result.errors[0]


def test_malformed_signatures_reports_specific_error():
    result = verify({"payload": "eyJhIjoxfQ", "signatures": ["not-a-dict"]})
    assert result.status == STATUS_INVALID
    assert result.errors
    assert "signatures" in result.errors[0]


@pytest.mark.parametrize("scalar", [
    pytest.param(5, id="int"),
    pytest.param(True, id="bool"),
    pytest.param(3.14, id="float"),
    pytest.param("not-a-list", id="string"),
])
@pytest.mark.parametrize("jwks_arg", [
    pytest.param(None, id="no-jwks"),
    pytest.param(FAKE_JWKS, id="with-jwks"),
])
@pytest.mark.parametrize("jic", [False, True], ids=["jic-false", "jic-true"])
def test_non_iterable_signatures_caught_before_the_loop(scalar, jwks_arg, jic):
    """A `signatures` value that isn't even iterable (an int, a bool, a
    float, a bare string) crashes the *pre-0.1.1* code before either
    try/except in the signature loop ever runs, on both branches (with and
    without jwks_by_issuer) -- the `for sig_entry in signatures:` line
    itself raises TypeError for a non-iterable, regardless of what's inside
    the loop body. This is the case Claude caught in review: an earlier
    version of this fix's notes claimed the `else:` branch (no
    jwks_by_issuer) was already safe against malformed `signatures` based on
    testing list-of-non-dict entries only, which iterate fine and never
    reach this failure mode. A bare scalar does not iterate at all and hits
    the crash one line earlier, in the `for` statement itself -- outside
    every try/except in the function, on either branch. stillmarcus24's
    original three-call-site report was correct; the correction was to this
    package's own re-testing of it, not to his finding.

    The structural gate added in 0.1.1 must catch this on both branches,
    with jwks_is_complete either setting, before any of that code runs.
    """
    result = verify({"payload": "eyJhIjoxfQ", "signatures": scalar}, jwks_by_issuer=jwks_arg, jwks_is_complete=jic)
    assert result.status == STATUS_INVALID
    assert result.errors
    assert "signatures" in result.errors[0]


def test_negative_control_non_iterable_signatures_raises_on_pre_0_1_1_shape():
    """Reproduces the exact defect Claude's review caught: on the pre-0.1.1
    else-branch shape, a non-iterable `signatures` value raises at the `for`
    statement itself, before its inner try/except ever runs -- regardless
    of jwks_by_issuer."""
    def _pre_0_1_1_else_branch_loop(signatures):
        for sig_entry in signatures:  # raises here for a non-iterable, not in the try below
            try:
                sig_entry.get("protected", "")
            except Exception:
                pass

    with pytest.raises(TypeError):
        _pre_0_1_1_else_branch_loop(5)


def test_unexpected_internal_error_reports_instrument_failure(monkeypatch):
    """An exception that survives past structural validation (something truly
    unanticipated deeper in _verify_core) must still come back as
    indeterminate with an instrument_failure-prefixed reason, never raise.

    Patches _verify_core via verify.__globals__ rather than a fresh
    `import tanilo_receipt_verify.verify` -- the package's __init__ rebinds
    the `verify` name at package scope to the function, so a submodule alias
    obtained after that import can resolve to the function object instead of
    the module. __globals__ is unambiguous: it is the exact namespace the
    `verify` function itself looks up `_verify_core` in when called.
    """

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated unexpected internal failure")

    monkeypatch.setitem(verify.__globals__, "_verify_core", _boom)

    result = verify({"payload": "eyJhIjoxfQ", "signatures": [{"protected": "", "signature": ""}]})
    assert result.status == STATUS_INDETERMINATE
    assert result.valid is None
    assert result.indeterminate_reason is not None
    assert result.indeterminate_reason.startswith("instrument_failure:")
    assert "RuntimeError" in result.indeterminate_reason


# -----------------------------------------------------------------------
# Negative control: reproduce 0.1.0's actual crash shape directly, so this
# suite demonstrates the fix rather than a corpus that happened to pass
# either way. This reimplements only the three unguarded call sites
# stillmarcus24 named (verify.py:291-293, :363-364, :500 against the
# 0.1.0-equivalent pre-fix source), not the whole module -- it is a targeted
# reproduction, not a copy of the shipped fix.
# -----------------------------------------------------------------------

def _pre_0_1_1_verify_entry_shape(envelope):
    """Reproduces exactly the unguarded pattern 0.1.0 (and 0.1.0-equivalent
    pre-fix tanilo-receipt-verify) used at the top of verify(): no isinstance
    guard before calling .get() on the envelope, then on its jws value."""
    jws = envelope.get("jws") if "jws" in envelope else envelope
    payload_b64 = jws.get("payload")
    signatures = jws.get("signatures", [])
    return payload_b64, signatures


def _pre_0_1_1_sig_entry_shape(sig_entry):
    """Reproduces the unguarded pattern at verify.py:363-364: sig_entry.get()
    called with no isinstance check first."""
    protected_b64 = sig_entry.get("protected", "")
    sig_b64 = sig_entry.get("signature", "")
    return protected_b64, sig_b64


@pytest.mark.parametrize("envelope", [
    pytest.param([1, 2, 3], id="envelope-is-list"),
    pytest.param("not-an-envelope", id="envelope-is-string"),
    pytest.param(None, id="envelope-is-none"),
])
def test_negative_control_pre_0_1_1_entry_shape_raises(envelope):
    """Demonstrates the defect this suite fixes: the pre-0.1.1 entry-point
    pattern (stillmarcus24's :291-293) really does raise on these inputs."""
    with pytest.raises((AttributeError, TypeError)):
        _pre_0_1_1_verify_entry_shape(envelope)


@pytest.mark.parametrize("sig_entry", [
    pytest.param("not-a-dict", id="sig-entry-is-string"),
    pytest.param(42, id="sig-entry-is-int"),
    pytest.param(None, id="sig-entry-is-none"),
    pytest.param([1, 2], id="sig-entry-is-list"),
])
def test_negative_control_pre_0_1_1_sig_entry_shape_raises(sig_entry):
    """Demonstrates the defect at stillmarcus24's :363-364: the unguarded
    sig_entry.get() really does raise on a non-dict signature entry."""
    with pytest.raises(AttributeError):
        _pre_0_1_1_sig_entry_shape(sig_entry)


def test_negative_control_current_verify_does_not_raise_on_same_inputs():
    """Same inputs the negative controls above prove crash the pre-0.1.1
    shape -- the shipped verify() must return a result for every one."""
    for envelope in ([1, 2, 3], "not-an-envelope", None):
        result = verify(envelope)
        assert result.status in (STATUS_INVALID, STATUS_INDETERMINATE)
    for sig_entry in ("not-a-dict", 42, None, [1, 2]):
        result = verify({"payload": "eyJhIjoxfQ", "signatures": [sig_entry]})
        assert result.status in (STATUS_INVALID, STATUS_INDETERMINATE)
