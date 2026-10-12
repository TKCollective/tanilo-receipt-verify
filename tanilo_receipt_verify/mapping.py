"""Informative mapping-document policy helper (added in 0.2.1).

A receipt's ``v_gate.mapping_id`` and ``v_gate.mapping_hash`` name the published
mapping document that governed its ``v_recommendation``. This helper reports those
members and, when the caller supplies the mapping documents it knows (hash -> id) and
the issuer's cutover rule, says whether the receipt's binding is one it recognises and
whether a legacy identifier appears on a receipt signed after the cutover.

It is policy, never validity: it inspects the payload only, raises nothing, and does not
change ``verify()``'s status. A receipt with an unrecognised or legacy mapping is a fact
for the relying party to act on, not an invalid signature.

mapping_policy() inspects unverified payload claims. A known result means only
that the supplied mapping identifier and hash match the configured registry;
it does not authenticate the receipt, issuer, signing time or mapping
application. Verify the same envelope separately using authenticated trust
material.

Tanilo's published documents (both published and byte for byte unchanged since publication):

- ``agentoracle-v0.3-2026-05-30``,
  sha256 ``0a78263976790df6e76cd9f3f441bf5a3b5c3a82e346b5aca43e49626881d7b0``,
  receipts signed before the cutover on 13 October 2026 (UTC), byte for byte unchanged;
- ``tanilo-v0.3-2026-10-13``,
  sha256 ``52842536d5c8444b6add8e8cb7e8987aa3fcc0bf40cc7ac266ddc1744f0711ce``,
  receipts signed after it. Same rules; only ``mapping_id``, ``issuer``,
  ``resolution`` and ``published`` differ. Rely on ``mapping_id`` and ``mapping_hash``
  rather than the signing date to tell receipts apart; the time rule below is a
  relying-party policy, not a validity check. ``TANILO_MAPPING_CUTOVER_AT`` is
  a configured policy threshold, planned for 2026-10-13T00:00:00Z.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

TANILO_MAPPINGS: Dict[str, str] = {
    "sha256-0a78263976790df6e76cd9f3f441bf5a3b5c3a82e346b5aca43e49626881d7b0": "agentoracle-v0.3-2026-05-30",
    "sha256-52842536d5c8444b6add8e8cb7e8987aa3fcc0bf40cc7ac266ddc1744f0711ce": "tanilo-v0.3-2026-10-13",
}
TANILO_LEGACY_MAPPING_IDS = ("agentoracle-v0.3-2026-05-30",)
TANILO_MAPPING_CUTOVER_AT = "2026-10-13T00:00:00Z"   # a configured policy threshold, planned for 2026-10-13T00:00:00Z

_INSTANT_RE = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,3}))?Z$")   # ASCII digits only
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")


def _parse_instant(s: Any) -> Optional[datetime]:
    """RFC 3339 UTC with a trailing Z and 0 to 3 fractional-second digits -> aware datetime; else None."""
    if not isinstance(s, str):
        return None
    m = _INSTANT_RE.match(s)
    if not m:
        return None
    try:
        y, mo, d, h, mi, sec = (int(x) for x in m.groups()[:6])
        frac = (m.group(7) or "").ljust(3, "0")
        return datetime(y, mo, d, h, mi, sec, int(frac) * 1000, tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None


STATUS_KNOWN = "known"
STATUS_UNKNOWN = "unknown"
STATUS_LEGACY_AFTER_CUTOVER = "legacy_after_cutover"
STATUS_ABSENT = "absent"


@dataclass
class MappingPolicy:
    status: str
    mapping_id: Optional[str] = None
    mapping_hash: Optional[str] = None
    known_as: Optional[str] = None
    signed_at: Optional[str] = None
    notes: list = field(default_factory=list)


class _DuplicateMember(ValueError):
    pass


def _reject_json_constant(name: str):
    raise ValueError(f"non-finite JSON number {name} is not allowed")


def _no_duplicate_members(pairs):
    obj: Dict[str, Any] = {}
    for k, v in pairs:
        if k in obj:
            raise _DuplicateMember(f"duplicate JSON member name {k!r}")
        obj[k] = v
    return obj


def _payload_of(envelope: Any) -> "tuple[Optional[Dict[str, Any]], Optional[str]]":
    """Strictly decode the JWS payload: base64url grammar, validated decoding, no
    duplicate member names. Returns (payload, problem); never raises."""
    try:
        jws = envelope.get("jws", envelope) if isinstance(envelope, dict) else None
        if not isinstance(jws, dict) or not isinstance(jws.get("payload"), str):
            return None, "payload is missing or not a string"
        raw = jws["payload"]
        if not _B64URL_RE.fullmatch(raw):
            return None, "payload is not base64url (characters outside A-Z a-z 0-9 - _)"
        try:
            data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            # validate=True rejects stray characters; the grammar check above already
            # excluded them, and standard base64 '+' '/' are not in the grammar.
            base64.b64decode(raw.replace("-", "+").replace("_", "/") + "=" * (-len(raw) % 4), validate=True)
        except (binascii.Error, ValueError) as e:
            return None, f"payload base64url decoding failed: {e}"
        try:
            obj = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_members, parse_constant=_reject_json_constant)
        except _DuplicateMember as e:
            return None, f"payload JSON rejected: {e}"
        except (UnicodeDecodeError, ValueError) as e:
            return None, f"payload is not valid JSON: {e}"
        if not isinstance(obj, dict):
            return None, "payload JSON is not an object"
        return obj, None
    except Exception as e:  # noqa: BLE001 -- never raise out of a policy helper
        return None, f"payload could not be decoded: {type(e).__name__}"


def _configuration_error(known: Any, legacy: Any, cutover_at: Any) -> "tuple[Optional[str], tuple]":
    """(problem, legacy_tuple). legacy_mapping_ids is read exactly once, here."""
    if not isinstance(known, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in known.items()):
        return "configuration error: known_mappings must be a dict mapping 'sha256-<hex>' strings to mapping-id strings", ()
    if legacy is None or isinstance(legacy, (str, bytes)):
        return "configuration error: legacy_mapping_ids must be an iterable of strings (not a single string, not None)", ()
    try:
        legacy_tuple = tuple(legacy)
    except Exception:  # noqa: BLE001 -- a generator may raise anything partway
        return "configuration error: legacy_mapping_ids could not be read", ()
    if not all(isinstance(x, str) for x in legacy_tuple):
        return "configuration error: legacy_mapping_ids must contain only strings", ()
    if cutover_at is not None and (not isinstance(cutover_at, str) or _parse_instant(cutover_at) is None):
        return "configuration error: cutover_at must be None or an RFC 3339 UTC instant ending in Z with 0 to 3 fractional digits", ()
    return None, legacy_tuple


def mapping_policy(
    envelope: Any,
    known_mappings: Optional[Dict[str, str]] = None,
    cutover_at: Optional[str] = TANILO_MAPPING_CUTOVER_AT,
    legacy_mapping_ids: Iterable[str] = TANILO_LEGACY_MAPPING_IDS,
) -> MappingPolicy:
    """Report the receipt's mapping binding against the caller's policy. Never raises.

    ``known_mappings`` maps ``"sha256-<hex>"`` to the mapping id the caller recognises
    (defaults to Tanilo's two published documents). ``cutover_at`` is an RFC 3339 UTC
    instant ending in Z (0 to 3 fractional digits), or None to skip the time rule; a
    receipt whose ``v_gate.signed_at`` (or ``timestamp``) is at or after it while
    carrying a legacy id is reported as ``legacy_after_cutover``. The two are compared
    as parsed instants. When the time rule applies (a legacy id with ``cutover_at``
    set) and ``signed_at`` is missing or cannot be parsed, the time policy cannot be
    evaluated and the status is ``unknown`` with a note; for a non-legacy id the time
    does not matter and the status stays ``known``.

    A malformed payload gives ``absent`` with a note. A bad configuration argument
    gives ``unknown`` with a configuration-error note.

    mapping_policy() inspects unverified payload claims. A known result means only
    that the supplied mapping identifier and hash match the configured registry; it
    does not authenticate the receipt, issuer, signing time or mapping application.
    Verify the same envelope separately using authenticated trust material.
    """
    known = TANILO_MAPPINGS if known_mappings is None else known_mappings
    problem, legacy = _configuration_error(known, legacy_mapping_ids, cutover_at)
    if problem is not None:
        return MappingPolicy(status=STATUS_UNKNOWN, notes=[problem])
    payload, decode_problem = _payload_of(envelope)
    if payload is None:
        return MappingPolicy(status=STATUS_ABSENT, notes=[decode_problem or "payload could not be decoded"])
    v_gate = payload.get("v_gate") if isinstance(payload.get("v_gate"), dict) else {}
    mid = v_gate.get("mapping_id") if isinstance(v_gate.get("mapping_id"), str) else None
    mhash = v_gate.get("mapping_hash") if isinstance(v_gate.get("mapping_hash"), str) else None
    signed_at = v_gate.get("signed_at") if isinstance(v_gate.get("signed_at"), str) else (
        payload.get("timestamp") if isinstance(payload.get("timestamp"), str) else None
    )
    if mid is None and mhash is None:
        return MappingPolicy(status=STATUS_ABSENT, signed_at=signed_at, notes=["v_gate carries no mapping_id or mapping_hash"])
    notes = []
    known_as = known.get(mhash) if mhash else None
    if known_as is None:
        notes.append("mapping_hash is not one of the known documents; fetch the document by its hash and check it before relying on v_recommendation")
        return MappingPolicy(status=STATUS_UNKNOWN, mapping_id=mid, mapping_hash=mhash, signed_at=signed_at, notes=notes)
    if mid is not None and mid != known_as:
        notes.append(f"mapping_id {mid!r} does not match the id published for this hash ({known_as!r})")
        return MappingPolicy(status=STATUS_UNKNOWN, mapping_id=mid, mapping_hash=mhash, known_as=known_as, signed_at=signed_at, notes=notes)
    if cutover_at and known_as in legacy:
        # Compare parsed instants, never strings: "…00:00:00.500Z" sorts before "…00:00:00Z"
        # as text. cutover_at was validated above.
        signed_dt = _parse_instant(signed_at)
        cutover_dt = _parse_instant(cutover_at)
        if signed_dt is None:
            notes.append("time policy not evaluated: the receipt carries a legacy mapping id and its signed_at is "
                         + ("missing" if signed_at is None else f"not an RFC 3339 UTC instant ending in Z with 0 to 3 fractional digits ({signed_at!r})"))
            return MappingPolicy(status=STATUS_UNKNOWN, mapping_id=mid, mapping_hash=mhash, known_as=known_as, signed_at=signed_at, notes=notes)
        if signed_dt >= cutover_dt:
            notes.append(f"legacy mapping {known_as!r} on a receipt signed at {signed_at}, at or after the cutover {cutover_at}")
            return MappingPolicy(status=STATUS_LEGACY_AFTER_CUTOVER, mapping_id=mid, mapping_hash=mhash, known_as=known_as, signed_at=signed_at, notes=notes)
    return MappingPolicy(status=STATUS_KNOWN, mapping_id=mid, mapping_hash=mhash, known_as=known_as, signed_at=signed_at, notes=notes)
