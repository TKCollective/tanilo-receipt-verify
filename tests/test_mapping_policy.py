"""mapping_policy is informative: it never raises and never changes verify()'s status."""
import base64, json
from tanilo_receipt_verify import mapping_policy, verify

OLD = "sha256-0a78263976790df6e76cd9f3f441bf5a3b5c3a82e346b5aca43e49626881d7b0"
NEW = "sha256-52842536d5c8444b6add8e8cb7e8987aa3fcc0bf40cc7ac266ddc1744f0711ce"

def env(v_gate, timestamp="2026-10-01T00:00:00.000Z"):
    payload = {"v_gate": v_gate, "timestamp": timestamp, "envelope_kind": "verification.v0.3+composed"}
    b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return {"jws": {"payload": b64, "signatures": [{"protected": "e30", "signature": "AA"}]}}

def test_known_before_cutover():
    r = mapping_policy(env({"mapping_id": "agentoracle-v0.3-2026-05-30", "mapping_hash": OLD, "signed_at": "2026-10-01T12:00:00.000Z"}))
    assert r.status == "known" and r.known_as == "agentoracle-v0.3-2026-05-30"

def test_known_after_cutover_new_document():
    r = mapping_policy(env({"mapping_id": "tanilo-v0.3-2026-10-13", "mapping_hash": NEW, "signed_at": "2026-10-13T00:00:00.000Z"}))
    assert r.status == "known" and r.known_as == "tanilo-v0.3-2026-10-13"

def test_legacy_after_cutover_is_reported_not_rejected():
    r = mapping_policy(env({"mapping_id": "agentoracle-v0.3-2026-05-30", "mapping_hash": OLD, "signed_at": "2026-10-13T00:00:01.000Z"}))
    assert r.status == "legacy_after_cutover" and r.notes

def test_legacy_at_cutover_minus_one_ms_is_known():
    r = mapping_policy(env({"mapping_id": "agentoracle-v0.3-2026-05-30", "mapping_hash": OLD, "signed_at": "2026-10-12T23:59:59.999Z"}))
    assert r.status == "known"

def test_unknown_hash_and_id_mismatch():
    assert mapping_policy(env({"mapping_id": "x", "mapping_hash": "sha256-" + "0" * 64})).status == "unknown"
    assert mapping_policy(env({"mapping_id": "tanilo-v0.3-2026-10-13", "mapping_hash": OLD})).status == "unknown"

def test_absent_and_garbage_never_raise():
    assert mapping_policy(env({})).status == "absent"
    assert mapping_policy({"jws": {"payload": "!!!"}}).status == "absent"
    assert mapping_policy(None).status == "absent"
    assert mapping_policy(env({"mapping_id": 5, "mapping_hash": None})).status == "absent"

def test_cutover_can_be_disabled_and_policy_is_separate_from_verify():
    e = env({"mapping_id": "agentoracle-v0.3-2026-05-30", "mapping_hash": OLD, "signed_at": "2026-12-01T00:00:00.000Z"})
    assert mapping_policy(e, cutover_at=None).status == "known"
    assert verify(e).status in ("invalid", "indeterminate")   # verify() is untouched by the helper
