"""Informative mapping-document policy helper (added in 0.2.1).

A receipt's ``v_gate.mapping_id`` and ``v_gate.mapping_hash`` name the published,
immutable mapping document that governed its ``v_recommendation``. This helper reports
those members and, when the caller supplies the mapping documents it knows (hash -> id)
and the issuer's cutover rule, says whether the receipt's binding is one it recognises
and whether a legacy identifier appears on a receipt signed after the cutover.

It is policy, never validity: it inspects the payload only, raises nothing, and does not
change ``verify()``'s status. A receipt with an unrecognised or legacy mapping is a fact
for the relying party to act on, not an invalid signature.

Tanilo's published documents (both published and byte for byte unchanged since publication):

- ``agentoracle-v0.3-2026-05-30``,
  sha256 ``0a78263976790df6e76cd9f3f441bf5a3b5c3a82e346b5aca43e49626881d7b0``,
  receipts signed before the cutover on 13 October 2026 (UTC), byte for byte unchanged;
- ``tanilo-v0.3-2026-10-13``,
  sha256 ``52842536d5c8444b6add8e8cb7e8987aa3fcc0bf40cc7ac266ddc1744f0711ce``,
  receipts signed after it. Same rules; only ``mapping_id``, ``issuer``,
  ``resolution`` and ``published`` differ. Rely on ``mapping_id`` and ``mapping_hash``
  rather than the signing date to tell receipts apart; the time rule below is a
  relying-party policy, not a validity check. ``TANILO_MAPPING_CUTOVER_AT`` is the
  instant the deployment serving the new document began (planned 2026-10-13T00:00:00Z).
"""
from __future__ import annotations

import base64
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
TANILO_MAPPING_CUTOVER_AT = "2026-10-13T00:00:00Z"

_INSTANT_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$")


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


def _payload_of(envelope: Any) -> Optional[Dict[str, Any]]:
    try:
        jws = envelope.get("jws", envelope) if isinstance(envelope, dict) else None
        if not isinstance(jws, dict) or not isinstance(jws.get("payload"), str):
            return None
        raw = jws["payload"]
        data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        obj = json.loads(data.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def mapping_policy(
    envelope: Any,
    known_mappings: Optional[Dict[str, str]] = None,
    cutover_at: Optional[str] = TANILO_MAPPING_CUTOVER_AT,
    legacy_mapping_ids: Iterable[str] = TANILO_LEGACY_MAPPING_IDS,
) -> MappingPolicy:
    """Report the receipt's mapping binding against the caller's policy. Never raises.

    ``known_mappings`` maps ``"sha256-<hex>"`` to the mapping id the caller recognises
    (defaults to Tanilo's two published documents). ``cutover_at`` is an RFC 3339 UTC
    instant ending in Z (0 to 3 fractional digits); a receipt whose ``v_gate.signed_at``
    (or ``timestamp``) is at or after it while carrying a legacy id is reported as
    ``legacy_after_cutover``. The two are compared as parsed instants. If either cannot
    be parsed the time rule is skipped and a note says so. Pass ``cutover_at=None`` to
    skip the time rule.
    """
    known = TANILO_MAPPINGS if known_mappings is None else known_mappings
    legacy = tuple(legacy_mapping_ids)
    payload = _payload_of(envelope)
    if payload is None:
        return MappingPolicy(status=STATUS_ABSENT, notes=["payload could not be decoded"])
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
    if cutover_at and known_as in legacy and signed_at is not None:
        # Compare parsed instants, never strings: "…00:00:00.500Z" sorts before "…00:00:00Z"
        # as text. If either side cannot be parsed, the time rule is skipped and said so.
        signed_dt, cutover_dt = _parse_instant(signed_at), _parse_instant(cutover_at)
        if signed_dt is None or cutover_dt is None:
            notes.append(f"time rule skipped: {'signed_at' if signed_dt is None else 'cutover_at'} is not an RFC 3339 UTC instant ending in Z with 0 to 3 fractional digits ({signed_at if signed_dt is None else cutover_at!r})")
        elif signed_dt >= cutover_dt:
            notes.append(f"legacy mapping {known_as!r} on a receipt signed at {signed_at}, at or after the cutover {cutover_at}")
            return MappingPolicy(status=STATUS_LEGACY_AFTER_CUTOVER, mapping_id=mid, mapping_hash=mhash, known_as=known_as, signed_at=signed_at, notes=notes)
    return MappingPolicy(status=STATUS_KNOWN, mapping_id=mid, mapping_hash=mhash, known_as=known_as, signed_at=signed_at, notes=notes)
