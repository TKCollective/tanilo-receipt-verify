"""Regression suite: Marcus Still's (stillmarcus24) malformed-input vectors.

Source: babyblueviper1/preaction-governance-conformance, pull request #7,
commit ac90da4e1d35fe7f840add20544cc33d123a4ff9 (merged as 1f7cf09),
corpus/phase1/stillmarcus24-malformed-input/. CC0 1.0. Contributed to
x402-foundation/tsc#4 Phase 1. The fixture files are a byte-identical copy;
see tests/fixtures/stillmarcus24-malformed-input/NOTICE.md.

The corpus tests the instrument, not the receipt: a conforming verifier returns
one of the four states for any input, including malformed input, and never
raises. This file checks, for each of the 15 vectors:

1. verify() returns and does not raise, with and without a key set and with
   jwks_is_complete=True;
2. the status is one of the states the corpus's expected.json allows;
3. the status equals the author's as-run reference for 0.1.1, so a later
   release cannot silently change what these inputs produce.

It also pins the fixture files' SHA-256 to the source commit, so an edited copy
fails loudly instead of testing something else.
"""

import hashlib
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tanilo_receipt_verify import verify  # noqa: E402

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures" / "stillmarcus24-malformed-input"
SOURCE_SHA256 = {
    "vectors.json": "1f5e847d7b15207acf9e474d259c4449489626e4acbaf4a219fcb1dc6ae10193",
    "expected.json": "e901bd3f0e9102b5da07342c03f75085a1d11651f4752251c6e0424cf2a964f1",
    "results-tanilo-0.1.1.json": "30250ff29685122a81e482f43a241bd9bf420d32c53a79dd1e193a6ee4c31d49",
    "LICENSE": "c4b7b6e96d25d2b922994e88f953d0b72d432595657f711fba9bd59a99b0dc3b",
}

VECTORS = json.loads((FIXTURES / "vectors.json").read_text())
EXPECTED = json.loads((FIXTURES / "expected.json").read_text())
REFERENCE = json.loads((FIXTURES / "results-tanilo-0.1.1.json").read_text())["results"]

CONFIGS = [
    pytest.param({}, id="no-jwks"),
    pytest.param({"jwks_by_issuer": {"https://example.com/.well-known/jwks.json": {"keys": []}}}, id="with-jwks"),
    pytest.param({"jwks_by_issuer": {"https://example.com/.well-known/jwks.json": {"keys": []}}, "jwks_is_complete": True}, id="declared-complete"),
]


@pytest.mark.parametrize("name", sorted(SOURCE_SHA256))
def test_fixture_bytes_match_source_commit(name):
    assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == SOURCE_SHA256[name]


def test_corpus_has_fifteen_vectors_each_with_an_expectation():
    assert len(VECTORS) == 15
    assert set(VECTORS) == set(EXPECTED) == set(REFERENCE)


@pytest.mark.parametrize("config", CONFIGS)
@pytest.mark.parametrize("name", list(VECTORS))
def test_vector_returns_an_allowed_state_and_never_raises(name, config):
    try:
        result = verify(VECTORS[name], **config)
    except BaseException as exc:  # noqa: BLE001 -- the property under test
        pytest.fail(f"{name} raised {type(exc).__name__}: {exc}")
    assert EXPECTED[name]["must_not_raise"] is True
    assert result.status in EXPECTED[name]["must_return_one_of"]


@pytest.mark.parametrize("name", list(VECTORS))
def test_vector_status_unchanged_from_0_1_1_reference(name):
    assert verify(VECTORS[name]).status == REFERENCE[name]["status"]
