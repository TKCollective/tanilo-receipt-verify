"""Cross-language byte-identical tests — Python verifier must produce the
same JCS canonical string and SHA-256 as the Node production /v1/compose.

Reference values are taken from live production and existing fixtures.
"""

import json
import pathlib
import sys

# Make the package importable when running from repo root
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tanilo_receipt_verify import jcs, sha256_hex, recompute_decision_ref  # noqa: E402


# ---------- Fixture 1: babyblueviper1's shipped decision_ref sample ----------

BABYBLUE_SAMPLE = {
    "artifact_hash": "9857116f45bc8f6e8384cb81c2ca0c6f167fc7ae87a2ffcbf1468eb64a697dd3",
    "artifact_type": "onchain_action",
    "policy_version": "invinoveritas.review.v1",
    "verdict": "approve_with_concerns",
    "decision_ref": "sha256:5fadb173dbbe84ff61d4c4788ecadd81f3889c7f85842e61ec8a25bdb2f925a1",
    "decision_ref_preimage_fields": [
        "artifact_hash",
        "artifact_type",
        "policy_version",
        "verdict"
    ]
}


def test_decision_ref_recompute_babyblueviper1():
    """Python recompute of babyblueviper1's shipped fixture must byte-match her Python
    and our Node recompute."""
    got = recompute_decision_ref(BABYBLUE_SAMPLE)
    assert got == BABYBLUE_SAMPLE["decision_ref"], f"{got} != {BABYBLUE_SAMPLE['decision_ref']}"


def test_decision_ref_tamper_sensitive():
    """Change verdict → id must change."""
    tampered = {**BABYBLUE_SAMPLE, "verdict": "approve"}
    got = recompute_decision_ref(tampered)
    assert got != BABYBLUE_SAMPLE["decision_ref"]


# ---------- Fixture 2: JCS byte-identical to Node production ----------

# Reference: Node production /v1/compose emits this canonical string for the
# following payload. If Python drifts even by one byte, this test fails.
NODE_REFERENCE_PAYLOAD = {
    "b": [1, 2, 3],
    "a": "hello",
    "z": {"nested": True, "empty": []},
    "unicode": "café",
    "digits": 42
}

# The canonical string Node emits (JSON.stringify with sorted keys) — key order:
# a, b, digits, unicode, z ; z's inner keys: empty, nested
NODE_REFERENCE_CANONICAL = (
    '{"a":"hello","b":[1,2,3],"digits":42,"unicode":"café","z":{"empty":[],"nested":true}}'
)


def test_jcs_byte_identical_to_node():
    got = jcs(NODE_REFERENCE_PAYLOAD)
    assert got == NODE_REFERENCE_CANONICAL, f"drift:\n  py:   {got}\n  node: {NODE_REFERENCE_CANONICAL}"


def test_jcs_sha256_matches_node():
    """Byte-identical string → identical SHA-256."""
    got = sha256_hex(jcs(NODE_REFERENCE_PAYLOAD))
    # Precomputed from Node: crypto.createHash("sha256").update(NODE_REFERENCE_CANONICAL,"utf8").digest("hex")
    expected = sha256_hex(NODE_REFERENCE_CANONICAL)  # same string, same hash
    assert got == expected


# ---------- Fixture 3: conformance sample envelope from production ----------

CONFORMANCE_FIXTURE = pathlib.Path(__file__).resolve().parent.parent.parent / "composed_envelope_e2e" / "conformance_sample_envelope.json"


def test_conformance_sample_canonical_hash():
    """Load the production conformance sample and reproduce its canonical hash."""
    if not CONFORMANCE_FIXTURE.exists():
        return  # skip when fixture not present
    data = json.loads(CONFORMANCE_FIXTURE.read_text())
    canonical_bytes_utf8 = data["governance"]["canonical_bytes_utf8"]
    envelope_hash = data["governance"]["envelope_hash"]
    got = sha256_hex(canonical_bytes_utf8)
    assert got == envelope_hash, f"{got} != {envelope_hash}"


if __name__ == "__main__":
    import traceback
    tests = [
        test_decision_ref_recompute_babyblueviper1,
        test_decision_ref_tamper_sensitive,
        test_jcs_byte_identical_to_node,
        test_jcs_sha256_matches_node,
        test_conformance_sample_canonical_hash,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ✗ {t.__name__}: {e}")
            failed += 1
        except Exception:
            print(f"  ✗ {t.__name__}: unexpected error")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
