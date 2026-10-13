"""mapping_policy is informative: it never raises and never changes verify()'s status."""
import base64, json
from tanilo_receipt_verify import mapping_policy, verify

OLD = "sha256-0a78263976790df6e76cd9f3f441bf5a3b5c3a82e346b5aca43e49626881d7b0"
NEW = "sha256-52842536d5c8444b6add8e8cb7e8987aa3fcc0bf40cc7ac266ddc1744f0711ce"

def env(v_gate, timestamp="2026-10-01T00:00:00.000Z"):
    payload = {"v_gate": v_gate, "envelope_kind": "verification.v0.3+composed"}
    if timestamp is not None:
        payload["timestamp"] = timestamp
    b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return {"jws": {"payload": b64, "signatures": [{"protected": "e30", "signature": "AA"}]}}

def test_known_before_cutover():
    r = mapping_policy(env({"mapping_id": "agentoracle-v0.3-2026-05-30", "mapping_hash": OLD, "signed_at": "2026-10-01T12:00:00.000Z"}))
    assert r.status == "known" and r.known_as == "agentoracle-v0.3-2026-05-30"

def test_known_after_cutover_new_document():
    r = mapping_policy(env({"mapping_id": "tanilo-v0.3-2026-10-13", "mapping_hash": NEW, "signed_at": "2026-10-13T00:00:00.000Z"}))
    assert r.status == "known" and r.known_as == "tanilo-v0.3-2026-10-13"

def test_legacy_after_cutover_is_reported_not_rejected():
    r = mapping_policy(env({"mapping_id": "agentoracle-v0.3-2026-05-30", "mapping_hash": OLD, "signed_at": "2026-10-13T00:07:23.000Z"}))
    assert r.status == "legacy_after_cutover" and r.notes

def test_legacy_at_cutover_minus_one_ms_is_known():
    r = mapping_policy(env({"mapping_id": "agentoracle-v0.3-2026-05-30", "mapping_hash": OLD, "signed_at": "2026-10-13T00:07:22.430Z"}))
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

# 0.2.1 audit (Claude's half, 2026-10-12): the cutover comparison must be on parsed
# instants, not strings; "…00:00:00.500Z" >= "…00:00:00Z" is False as text ('.' < 'Z').
LEGACY = {"mapping_id": "agentoracle-v0.3-2026-05-30", "mapping_hash": OLD}

def test_cutover_boundary_exactly_at_the_instant_is_legacy_after_cutover():
    r = mapping_policy(env({**LEGACY, "signed_at": "2026-10-13T00:00:00.000Z"}), cutover_at="2026-10-13T00:00:00Z")
    assert r.status == "legacy_after_cutover"
    r = mapping_policy(env({**LEGACY, "signed_at": "2026-10-13T00:00:00Z"}), cutover_at="2026-10-13T00:00:00.000Z")
    assert r.status == "legacy_after_cutover"

def test_cutover_boundary_half_a_second_after_is_legacy_after_cutover():
    r = mapping_policy(env({**LEGACY, "signed_at": "2026-10-13T00:00:00.500Z"}), cutover_at="2026-10-13T00:00:00Z")
    assert r.status == "legacy_after_cutover", r

def test_cutover_boundary_one_millisecond_before_is_known():
    r = mapping_policy(env({**LEGACY, "signed_at": "2026-10-12T23:59:59.999Z"}), cutover_at="2026-10-13T00:00:00Z")
    assert r.status == "known"
    r = mapping_policy(env({**LEGACY, "signed_at": "2026-10-12T23:59:59.999Z"}), cutover_at="2026-10-13T00:00:00.000Z")
    assert r.status == "known"

# Astra's audit half (2026-10-12): when the time rule applies and signed_at cannot be
# evaluated, the result is "unknown" (time policy not evaluated), not "known".
def test_legacy_id_with_unparseable_signed_at_is_unknown():
    for signed_at in ("2026-10-13T00:00:00+00:00", "not a time", "2026-12-01T00:00:00.1234Z"):
        r = mapping_policy(env({**LEGACY, "signed_at": signed_at}), cutover_at="2026-10-13T00:00:00Z")
        assert r.status == "unknown", (signed_at, r)
        assert any("time policy not evaluated" in n for n in r.notes), r.notes

def test_legacy_id_with_missing_signed_at_is_unknown():
    r = mapping_policy(env(LEGACY, timestamp=None), cutover_at="2026-10-13T00:00:00Z")
    assert r.status == "unknown" and r.signed_at is None
    assert any("time policy not evaluated" in n and "missing" in n for n in r.notes), r.notes

def test_non_legacy_id_with_unparseable_signed_at_stays_known():
    r = mapping_policy(env({"mapping_id": "tanilo-v0.3-2026-10-13", "mapping_hash": NEW, "signed_at": "not a time"}), cutover_at="2026-10-13T00:00:00Z")
    assert r.status == "known"

def test_strict_payload_decoding():
    good = env({**LEGACY, "signed_at": "2026-10-01T12:00:00.000Z"})
    assert mapping_policy(good).status == "known"
    bad = {"jws": {"payload": "!!!!" + good["jws"]["payload"], "signatures": []}}
    r = mapping_policy(bad)
    assert r.status == "absent" and r.notes and r.status != "known"
    # duplicate member names are rejected, not last-wins
    import base64 as _b
    dup = '{"v_gate": {"mapping_id": "x", "mapping_hash": "%s"}, "v_gate": {"mapping_id": "%s", "mapping_hash": "%s"}}' % (NEW, "agentoracle-v0.3-2026-05-30", OLD)
    e = {"jws": {"payload": _b.urlsafe_b64encode(dup.encode()).decode().rstrip("="), "signatures": []}}
    r = mapping_policy(e)
    assert r.status == "absent" and any("duplicate" in n for n in r.notes), r
    # standard base64 characters are outside the base64url grammar
    assert mapping_policy({"jws": {"payload": "eyJ+Lw=="}}).status == "absent"

def test_bad_configuration_is_unknown_never_a_raise():
    e = env({**LEGACY, "signed_at": "2026-10-01T12:00:00.000Z"})
    for kwargs in ({"legacy_mapping_ids": None}, {"legacy_mapping_ids": "agentoracle-v0.3-2026-05-30"}, {"known_mappings": []},
                   {"known_mappings": {"a": 1}}, {"cutover_at": 1}, {"cutover_at": "soon"}):
        r = mapping_policy(e, **kwargs)
        assert r.status == "unknown", (kwargs, r)
        assert any("configuration error" in n for n in r.notes), (kwargs, r.notes)


# Astra's final check (2026-10-12)
def test_legacy_mapping_ids_generator_is_read_once_and_a_raising_generator_is_a_configuration_error():
    e = env({**LEGACY, "signed_at": "2026-12-01T00:00:00.000Z"})
    def good():
        yield "agentoracle-v0.3-2026-05-30"
    assert mapping_policy(e, legacy_mapping_ids=good()).status == "legacy_after_cutover"
    def raises():
        yield "agentoracle-v0.3-2026-05-30"
        raise ValueError("boom")
    r = mapping_policy(e, legacy_mapping_ids=raises())
    assert r.status == "unknown" and "configuration error: legacy_mapping_ids could not be read" in r.notes

def test_non_finite_json_numbers_are_rejected():
    import base64 as _b
    for const in ("NaN", "Infinity", "-Infinity"):
        raw = '{"v_gate": {"mapping_id": "agentoracle-v0.3-2026-05-30", "mapping_hash": "%s"}, "x": %s}' % (OLD, const)
        e = {"jws": {"payload": _b.urlsafe_b64encode(raw.encode()).decode().rstrip("="), "signatures": []}}
        r = mapping_policy(e)
        assert r.status == "absent", (const, r)

def test_non_ascii_digits_in_a_timestamp_are_unparseable():
    # Fullwidth and Arabic-Indic digits match Python's \\d but are not ASCII; the instant must not parse.
    r = mapping_policy(env({**LEGACY, "signed_at": "\uff12\uff10\uff12\uff16-10-13T00:00:00Z"}), cutover_at="2026-10-13T00:00:00Z")
    assert r.status == "unknown" and any("time policy not evaluated" in n for n in r.notes), r
    r2 = mapping_policy(env({**LEGACY, "signed_at": "2026-12-01T00:00:00Z"}), cutover_at="2026-10-1\u0663T00:00:00Z")
    assert r2.status == "unknown" and any("configuration error" in n for n in r2.notes), r2


# The recorded cutover (2026-10-13): the deployment serving tanilo-v0.3-2026-10-13 first answered on
# api.tanilo.io at 00:07:22.431Z; the previous deployment's last observed answer was at 00:07:21.433Z.
# The planned 00:00:00Z was seven minutes early: the previous deployment was still signing legacy-id
# receipts after it, and those must not be flagged.
def test_default_cutover_is_the_recorded_instant():
    from tanilo_receipt_verify import TANILO_MAPPING_CUTOVER_AT
    assert TANILO_MAPPING_CUTOVER_AT == "2026-10-13T00:07:22.431Z"

def test_a_real_legacy_receipt_signed_before_the_recorded_cutover_is_known():
    # signed_at of a receipt issued by the previous deployment during the cutover
    # (canonical_sha256 sha256-0af0da413c46d66279b5187537cdff5ab93212848887e527aba07949ff411682)
    r = mapping_policy(env({**LEGACY, "signed_at": "2026-10-13T00:06:15.742Z"}))
    assert r.status == "known", r
    # the previous deployment's last observed answer
    assert mapping_policy(env({**LEGACY, "signed_at": "2026-10-13T00:07:21.433Z"})).status == "known"

def test_legacy_id_at_and_after_the_recorded_cutover_is_legacy_after_cutover():
    assert mapping_policy(env({**LEGACY, "signed_at": "2026-10-13T00:07:22.431Z"})).status == "legacy_after_cutover"
    assert mapping_policy(env({**LEGACY, "signed_at": "2026-10-13T00:07:23Z"})).status == "legacy_after_cutover"

def test_the_first_new_receipts_after_the_cutover_are_known():
    # signed_at of the first receipts requested from the new deployment
    # (canonical_sha256 sha256-d34cf28933fbe56915cb011ac67c4e30806481c51a651be74df4f2f448b992c7)
    for signed_at in ("2026-10-13T00:07:32.520Z", "2026-10-13T00:13:01.434Z"):
        r = mapping_policy(env({"mapping_id": "tanilo-v0.3-2026-10-13", "mapping_hash": NEW, "signed_at": signed_at}))
        assert r.status == "known" and r.known_as == "tanilo-v0.3-2026-10-13"
