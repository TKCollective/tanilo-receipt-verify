"""Anchor check: proof of when (stdlib only).

Sits beside ``verify``. Given a receipt's ``canonical_sha256`` (as returned in
``VerifyResult.canonical_sha256``) and its ``tanilo.anchor.v1`` proof, it

1. recomputes, offline, the RFC 6962 Merkle root from the receipt's hash and
   the proof's audit path, and
2. optionally asks a caller-supplied lookup whether that root was published
   where the proof says it was.

Three outcomes, never a raise, in the same style as the signature verifier:

    "anchored"       the path verifies AND a lookup confirmed the root
    "not_anchored"   the path fails, or a lookup ran and the root is NOT there
    "indeterminate"  the path verifies but nothing confirmed the publication
                     (no lookup supplied, RPC unreachable, wrong chain,
                     a contract the caller does not trust)

What an anchor shows: the receipt's canonical bytes existed no later than the
anchoring block's time (``AnchorResult.anchored_at``). What it does not show:
who issued the receipt (the signature shows which key signed), that the claim
is true, or that the receipt is not older than it says.

This module performs no network I/O by itself. ``evm_contract_lookup`` builds
a lookup that makes JSON-RPC calls when the caller chooses to use it.

Trust: the anchoring time is read from a contract, so the caller must say
which contract addresses it trusts. A proof that names any other contract is
"indeterminate", never "anchored": an unknown contract could report any time
it likes.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

PROOF_VERSION = "tanilo.anchor.v1"
LEAF_HASH_ALG = "rfc6962-sha256"
ANCHORED = "anchored"
NOT_ANCHORED = "not_anchored"
INDETERMINATE = "indeterminate"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
# keccak256("anchoredAt(bytes32)")[:4]. Precomputed so the standard library suffices.
_SEL_ANCHORED_AT = "9591a610"

# AnchorLookup(root_hex, anchor_record) ->
#   {"status": "confirmed" | "failed" | "pending" | "indeterminate", "reason": str | None, "anchored_at": str (optional)}
AnchorLookup = Callable[[str, Dict[str, Any]], Dict[str, Any]]


def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def root_from_proof(leaf: bytes, leaf_index: Any, tree_size: Any, path: List[bytes]) -> Optional[bytes]:
    """RFC 6962 section 2.1.1 audit-path check. Returns the root, or None if the path is inconsistent."""
    if isinstance(leaf_index, bool) or isinstance(tree_size, bool):
        return None
    if not isinstance(leaf_index, int) or not isinstance(tree_size, int):
        return None
    if leaf_index < 0 or leaf_index >= tree_size:
        return None
    fn, sn, r = leaf_index, tree_size - 1, _leaf(leaf)
    for p in path:
        if sn == 0:
            return None
        if fn % 2 == 1 or fn == sn:
            r = _node(p, r)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


@dataclass
class AnchorResult:
    status: str                       # "anchored" | "not_anchored" | "indeterminate"
    merkle_ok: Optional[bool]
    root: Optional[str] = None
    anchored_at: Optional[str] = None  # earliest confirmed anchoring time (RFC 3339, UTC), when anchored
    anchors: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    indeterminate_reason: Optional[str] = None


def verify_anchor(canonical_sha256: Any, proof: Any, lookups: Optional[Dict[str, AnchorLookup]] = None) -> AnchorResult:
    """Check that ``canonical_sha256`` is anchored as ``proof`` says.

    ``lookups`` maps an anchor ``kind`` (for example "evm-contract") to a
    callable that checks the publication point. With no lookup for any anchor
    in the proof the result is "indeterminate", not "anchored".
    """
    try:
        if not isinstance(proof, dict):
            return AnchorResult(NOT_ANCHORED, False, errors=["proof is not an object"])
        if proof.get("anchor_version") != PROOF_VERSION:
            return AnchorResult(NOT_ANCHORED, False, errors=[f"unsupported anchor_version {proof.get('anchor_version')!r}"])
        if proof.get("leaf_hash_alg") != LEAF_HASH_ALG:
            return AnchorResult(NOT_ANCHORED, False, errors=[f"unsupported leaf_hash_alg {proof.get('leaf_hash_alg')!r}"])
        if not isinstance(canonical_sha256, str) or not canonical_sha256.startswith("sha256-") or not _HEX64.match(canonical_sha256[7:]):
            return AnchorResult(NOT_ANCHORED, False, errors=["canonical_sha256 is not sha256-<64 lowercase hex>"])
        if proof.get("leaf") != canonical_sha256:
            return AnchorResult(NOT_ANCHORED, False, errors=["proof leaf is not this receipt's canonical_sha256"])
        path_hex = proof.get("path")
        if not isinstance(path_hex, list) or not all(isinstance(p, str) and _HEX64.match(p) for p in path_hex):
            return AnchorResult(NOT_ANCHORED, False, errors=["path is not a list of 64-hex strings"])
        stated = proof.get("root")
        if not isinstance(stated, str) or not _HEX64.match(stated):
            return AnchorResult(NOT_ANCHORED, False, errors=["root is not 64-hex"])
        root = root_from_proof(bytes.fromhex(canonical_sha256[7:]), proof.get("leaf_index"), proof.get("tree_size"), [bytes.fromhex(p) for p in path_hex])
        if root is None or root.hex() != stated:
            return AnchorResult(NOT_ANCHORED, False, errors=["audit path does not reduce to the stated root"])

        records = proof.get("anchors")
        if not isinstance(records, list):
            records = []
        anchors_out: List[Dict[str, Any]] = []
        times: List[str] = []
        failed = False
        for rec in records:
            kind = rec.get("kind") if isinstance(rec, dict) else None
            fn = (lookups or {}).get(kind) if isinstance(kind, str) else None
            if fn is None:
                anchors_out.append({"kind": kind, "status": INDETERMINATE, "reason": "no lookup supplied for this anchor kind"})
                continue
            try:
                res = fn(stated, rec)
                if not isinstance(res, dict):
                    res = {"status": INDETERMINATE, "reason": "lookup returned something other than an object"}
            except Exception as e:  # a lookup that blows up is "could not check", not "failed"
                res = {"status": INDETERMINATE, "reason": f"instrument_failure: {type(e).__name__}: {e}"}
            anchors_out.append({"kind": kind, **res})
            if res.get("status") == "confirmed":
                if isinstance(res.get("anchored_at"), str):
                    times.append(res["anchored_at"])
                else:
                    times.append("")
            failed = failed or res.get("status") == "failed"
        if failed:
            # A publication point was checked and does not carry this root.
            return AnchorResult(NOT_ANCHORED, True, stated, None, anchors_out, errors=["an anchor record points at a publication that does not commit to this root"])
        if times:
            known = sorted(t for t in times if t)
            return AnchorResult(ANCHORED, True, stated, known[0] if known else None, anchors_out)
        if anchors_out:
            reason = "merkle path verifies; no anchor publication was confirmed (" + "; ".join(f"{a.get('kind')}: {a.get('reason')}" for a in anchors_out) + ")"
        else:
            reason = "merkle path verifies; proof carries no anchors"
        return AnchorResult(INDETERMINATE, True, stated, None, anchors_out, indeterminate_reason=reason)
    except Exception as e:  # never raise
        return AnchorResult(INDETERMINATE, None, indeterminate_reason=f"instrument_failure: unhandled {type(e).__name__}: {e}")


def evm_contract_lookup(rpc_url: str, trusted_contracts: Iterable[str], chain_id: Optional[int] = None, timeout: float = 10.0) -> AnchorLookup:
    """Lookup for kind "evm-contract": asks a TaniloAnchor contract when a root was anchored.

    ``trusted_contracts``: the contract addresses the caller accepts. Required.
    A proof naming any other contract is "indeterminate".
    ``chain_id``: if given, the proof's chain and the RPC's chain must both equal it.
    The RPC's own chain id is always compared with the proof's.

    Two JSON-RPC calls per check: ``eth_chainId`` and ``eth_call``.
    """
    import urllib.request

    trusted = {str(a).lower() for a in trusted_contracts if isinstance(a, str) and _ADDR.match(a)}

    def rpc(method: str, params: list) -> Any:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(rpc_url, data=body, headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = json.loads(r.read())
        if not isinstance(out, dict) or "error" in out or "result" not in out:
            raise RuntimeError("rpc error")
        return out["result"]

    def lookup(root_hex: str, rec: Dict[str, Any]) -> Dict[str, Any]:
        contract = rec.get("contract")
        if not isinstance(contract, str) or not _ADDR.match(contract):
            return {"status": INDETERMINATE, "reason": "record has no contract address"}
        if contract.lower() not in trusted:
            return {"status": INDETERMINATE, "reason": "record names a contract the caller does not trust", "contract": contract}
        rec_chain = rec.get("chain_id")
        if isinstance(rec_chain, bool) or not isinstance(rec_chain, int):
            return {"status": INDETERMINATE, "reason": "record has no chain_id"}
        if chain_id is not None and rec_chain != chain_id:
            return {"status": INDETERMINATE, "reason": f"record is for chain {rec_chain}, caller expects {chain_id}"}
        try:
            live = int(rpc("eth_chainId", []), 16)
        except Exception as e:
            return {"status": INDETERMINATE, "reason": f"rpc unreachable: {type(e).__name__}"}
        if live != rec_chain:
            return {"status": INDETERMINATE, "reason": f"the RPC serves chain {live}, the record is for chain {rec_chain}"}
        try:
            raw = rpc("eth_call", [{"to": contract, "data": "0x" + _SEL_ANCHORED_AT + root_hex}, "latest"])
            if not isinstance(raw, str) or not re.match(r"^0x[0-9a-fA-F]{64}$", raw):
                return {"status": INDETERMINATE, "reason": "the contract did not answer anchoredAt as expected"}
            ts = int(raw, 16)
        except Exception as e:
            return {"status": INDETERMINATE, "reason": f"rpc unreachable: {type(e).__name__}"}
        if ts == 0:
            return {"status": "failed", "reason": "the contract has no anchoring for this root", "contract": contract}
        when = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {"status": "confirmed", "reason": None, "anchored_at": when, "contract": contract, "chain_id": rec_chain}

    return lookup
