"""Anchor check (proof of when): tanilo_receipt_verify.anchor.

The Merkle vectors were produced by the Node implementation in
TKCollective/tanilo-anchor; this file checks the Python implementation agrees
on every one, and that publication lookups resolve to the right one of three
outcomes. The chain is a local fake JSON-RPC server: nothing here touches a
real network or says anything about GOAT.
"""

import json
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tanilo_receipt_verify import verify_anchor, evm_contract_lookup, AnchorResult  # noqa: E402
from tanilo_receipt_verify.anchor import root_from_proof  # noqa: E402

VECTORS = json.loads((pathlib.Path(__file__).parent / "fixtures" / "anchor" / "merkle-proofs.json").read_text())
CONTRACT = "0x821b832D25d8E18BD3A761B935bfaf1c2F761D58"          # current testnet3 contract
RETIRED = "0x801fB569593ae8fd9E906059cA6d9e584F4Bc30b"           # first testnet3 contract; one batch, kept as a historical example
HIST = sorted((pathlib.Path(__file__).parent / "fixtures" / "anchor" / "historical-testnet3-2026-10-05").glob("*.anchor.json"))
OTHER = "0x000000000000000000000000000000000000dEaD"


def with_anchor(proof, **over):
    rec = {"kind": "evm-contract", "chain": "eip155:48816", "chain_id": 48816, "contract": CONTRACT, "tx_hash": "0x" + "11" * 32}
    rec.update(over)
    return dict(proof, anchors=[rec])


class FakeChain:
    """Answers eth_chainId and eth_call(anchoredAt) like a node would."""

    def __init__(self, chain_id=48816, anchored=None, broken=False, garbage=False):
        self.chain_id, self.anchored, self.broken, self.garbage, self.calls = chain_id, anchored or {}, broken, garbage, []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers["content-length"])))
                outer.calls.append(req)
                if outer.broken:
                    out = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "boom"}}
                elif req["method"] == "eth_chainId":
                    out = {"jsonrpc": "2.0", "id": 1, "result": hex(outer.chain_id)}
                elif outer.garbage:
                    out = {"jsonrpc": "2.0", "id": 1, "result": "0x"}
                else:
                    p = req["params"][0]
                    key = (p["to"].lower(), p["data"][10:])
                    out = {"jsonrpc": "2.0", "id": 1, "result": "0x" + format(outer.anchored.get(key, 0), "064x")}
                body = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def chain():
    made = []

    def make(**kw):
        c = FakeChain(**kw)
        made.append(c)
        return c

    yield make
    for c in made:
        c.close()


# ── Merkle: agreement with the Node implementation ──────────────────

def test_vector_file_is_the_expected_size():
    assert len(VECTORS["valid"]) == 78 and len(VECTORS["invalid"]) == 15


@pytest.mark.parametrize("v", VECTORS["valid"], ids=lambda v: v["name"])
def test_valid_vector_path_verifies(v):
    r = verify_anchor(v["canonical_sha256"], v["proof"])
    # The path verifies; with no anchors and no lookup that is indeterminate, never "anchored".
    assert r.status == "indeterminate" and r.merkle_ok is True and r.root == v["proof"]["root"]
    assert r.indeterminate_reason == "merkle path verifies; proof carries no anchors"


@pytest.mark.parametrize("v", VECTORS["invalid"], ids=lambda v: v["name"])
def test_invalid_vector_is_not_anchored(v):
    r = verify_anchor(v["canonical_sha256"], v["proof"], {"evm-contract": lambda root, rec: {"status": "confirmed"}})
    assert r.status == "not_anchored" and r.merkle_ok is False and r.errors


def test_same_shape_tree_size_recomputes_the_same_root():
    # Documented property: the path, not the stated tree_size, is what the root commits to.
    v = next(x for x in VECTORS["valid"] if x["name"] == "n7-leaf4")
    leaf = bytes.fromhex(v["canonical_sha256"][7:])
    path = [bytes.fromhex(p) for p in v["proof"]["path"]]
    assert root_from_proof(leaf, 4, 8, path) == root_from_proof(leaf, 4, 7, path)
    assert root_from_proof(leaf, 4, 5, path) != root_from_proof(leaf, 4, 7, path)


# ── outcomes ────────────────────────────────────────────────────────

V = next(x for x in VECTORS["valid"] if x["name"] == "n7-leaf4")
H, P = V["canonical_sha256"], V["proof"]


def test_without_a_lookup_an_anchor_record_is_indeterminate():
    r = verify_anchor(H, with_anchor(P))
    assert r.status == "indeterminate" and r.merkle_ok is True and r.anchored_at is None
    assert "no lookup supplied" in r.indeterminate_reason


def test_confirmed_lookup_is_anchored_and_carries_the_time():
    r = verify_anchor(H, with_anchor(P), {"evm-contract": lambda root, rec: {"status": "confirmed", "reason": None, "anchored_at": "2026-10-05T03:00:00Z"}})
    assert r.status == "anchored" and r.anchored_at == "2026-10-05T03:00:00Z"


def test_failed_lookup_is_not_anchored_even_with_a_good_path():
    r = verify_anchor(H, with_anchor(P), {"evm-contract": lambda root, rec: {"status": "failed", "reason": "no such root"}})
    assert r.status == "not_anchored" and r.merkle_ok is True


def test_one_failed_and_one_confirmed_is_not_anchored():
    proof = dict(P, anchors=[{"kind": "a"}, {"kind": "b"}])
    r = verify_anchor(H, proof, {"a": lambda *_: {"status": "confirmed"}, "b": lambda *_: {"status": "failed"}})
    assert r.status == "not_anchored"


def test_earliest_confirmed_time_is_reported():
    proof = dict(P, anchors=[{"kind": "a"}, {"kind": "b"}])
    r = verify_anchor(H, proof, {"a": lambda *_: {"status": "confirmed", "anchored_at": "2026-10-05T04:00:00Z"}, "b": lambda *_: {"status": "confirmed", "anchored_at": "2026-10-05T03:00:00Z"}})
    assert r.status == "anchored" and r.anchored_at == "2026-10-05T03:00:00Z"


def test_lookup_exception_or_bad_return_is_indeterminate():
    def boom(root, rec):
        raise ConnectionError("rpc down")
    r = verify_anchor(H, with_anchor(P), {"evm-contract": boom})
    assert r.status == "indeterminate" and "instrument_failure" in r.anchors[0]["reason"]
    r = verify_anchor(H, with_anchor(P), {"evm-contract": lambda *_: "yes"})
    assert r.status == "indeterminate"


def test_pending_is_indeterminate():
    r = verify_anchor(H, with_anchor(P), {"evm-contract": lambda *_: {"status": "pending", "reason": "not mined"}})
    assert r.status == "indeterminate"


def test_unknown_anchor_kind_is_ignored_not_failed():
    proof = dict(P, anchors=[{"kind": "something-new"}, {"kind": "evm-contract"}])
    r = verify_anchor(H, proof, {"evm-contract": lambda *_: {"status": "confirmed", "anchored_at": "2026-10-05T03:00:00Z"}})
    assert r.status == "anchored" and r.anchors[0]["status"] == "indeterminate"


@pytest.mark.parametrize("bad", [None, [], "x", 7, {}, {"anchor_version": "tanilo.anchor.v1"}])
def test_malformed_proof_never_raises(bad):
    r = verify_anchor(H, bad)
    assert isinstance(r, AnchorResult) and r.status == "not_anchored"


@pytest.mark.parametrize("bad", [None, 5, "", "sha256-xyz", "sha256-" + "AB" * 32, ["sha256-" + "ab" * 32]])
def test_malformed_hash_never_raises(bad):
    assert verify_anchor(bad, P).status == "not_anchored"


@pytest.mark.parametrize("anchors", [None, "x", 5, [None], [5], [{"kind": 3}], [{"kind": ["evm-contract"]}]])
def test_malformed_anchor_records_never_raise_and_never_anchor(anchors):
    r = verify_anchor(H, dict(P, anchors=anchors), {"evm-contract": lambda *_: {"status": "confirmed"}})
    assert r.status == "indeterminate" and r.merkle_ok is True


def test_boolean_index_is_refused():
    assert verify_anchor(H, dict(P, leaf_index=True)).status == "not_anchored"


# ── the contract lookup ─────────────────────────────────────────────

def test_lookup_confirms_a_root_the_trusted_contract_holds(chain):
    c = chain(anchored={(CONTRACT.lower(), P["root"]): 1791169200})
    r = verify_anchor(H, with_anchor(P), {"evm-contract": evm_contract_lookup(c.url, [CONTRACT])})
    assert r.status == "anchored" and r.anchored_at == "2026-10-05T03:00:00Z"
    assert [x["method"] for x in c.calls] == ["eth_chainId", "eth_call"]
    assert c.calls[1]["params"][0]["data"] == "0x9591a610" + P["root"]


def test_lookup_root_absent_is_not_anchored(chain):
    c = chain()
    r = verify_anchor(H, with_anchor(P), {"evm-contract": evm_contract_lookup(c.url, [CONTRACT])})
    assert r.status == "not_anchored" and r.merkle_ok is True


def test_untrusted_contract_is_indeterminate_and_is_never_called(chain):
    # A contract the caller does not trust could report any time it likes.
    c = chain(anchored={(OTHER.lower(), P["root"]): 1})
    r = verify_anchor(H, with_anchor(P, contract=OTHER), {"evm-contract": evm_contract_lookup(c.url, [CONTRACT])})
    assert r.status == "indeterminate" and "does not trust" in r.anchors[0]["reason"] and c.calls == []


def test_empty_trust_list_trusts_nothing(chain):
    c = chain(anchored={(CONTRACT.lower(), P["root"]): 1791169200})
    r = verify_anchor(H, with_anchor(P), {"evm-contract": evm_contract_lookup(c.url, [])})
    assert r.status == "indeterminate" and c.calls == []


def test_trust_list_is_case_insensitive(chain):
    c = chain(anchored={(CONTRACT.lower(), P["root"]): 1791169200})
    r = verify_anchor(H, with_anchor(P), {"evm-contract": evm_contract_lookup(c.url, [CONTRACT.lower()])})
    assert r.status == "anchored"


def test_rpc_on_another_chain_is_indeterminate(chain):
    c = chain(chain_id=2345, anchored={(CONTRACT.lower(), P["root"]): 1791169200})
    r = verify_anchor(H, with_anchor(P), {"evm-contract": evm_contract_lookup(c.url, [CONTRACT])})
    assert r.status == "indeterminate" and "serves chain 2345" in r.anchors[0]["reason"]


def test_expected_chain_mismatch_is_indeterminate_without_a_call(chain):
    c = chain(anchored={(CONTRACT.lower(), P["root"]): 1791169200})
    r = verify_anchor(H, with_anchor(P), {"evm-contract": evm_contract_lookup(c.url, [CONTRACT], chain_id=2345)})
    assert r.status == "indeterminate" and c.calls == []


def test_rpc_error_unreachable_or_garbage_is_indeterminate(chain):
    c = chain(broken=True)
    assert verify_anchor(H, with_anchor(P), {"evm-contract": evm_contract_lookup(c.url, [CONTRACT])}).status == "indeterminate"
    assert verify_anchor(H, with_anchor(P), {"evm-contract": evm_contract_lookup("http://127.0.0.1:1", [CONTRACT], timeout=1)}).status == "indeterminate"
    g = chain(garbage=True)
    assert verify_anchor(H, with_anchor(P), {"evm-contract": evm_contract_lookup(g.url, [CONTRACT])}).status == "indeterminate"


@pytest.mark.parametrize("over", [{"contract": None}, {"contract": "0x12"}, {"chain_id": None}, {"chain_id": "48816"}, {"chain_id": True}])
def test_record_without_contract_or_chain_is_indeterminate(chain, over):
    c = chain(anchored={(CONTRACT.lower(), P["root"]): 1791169200})
    r = verify_anchor(H, with_anchor(P, **over), {"evm-contract": evm_contract_lookup(c.url, [CONTRACT])})
    assert r.status == "indeterminate"


# ── the historical testnet3 batch (retired contract) ────────────────

HIST_ROOT = "bc014ab6e6295dbf4eaa685e23df922cb555ecc830aff3b846e35672bd3f9599"
HIST_TIME = 1791168333  # 2026-10-05T02:45:33Z, the contract's anchoredAt for that root


def test_three_historical_proofs_are_present():
    assert len(HIST) == 3


@pytest.mark.parametrize("f", HIST, ids=lambda f: f.name)
def test_historical_proof_path_still_verifies(f):
    proof = json.loads(f.read_text())
    r = verify_anchor(proof["leaf"], proof)
    assert r.status == "indeterminate" and r.merkle_ok is True and r.root == HIST_ROOT
    assert [a["kind"] for a in proof["anchors"]] == ["evm-contract", "opentimestamps"]
    assert proof["anchors"][0]["contract"] == RETIRED


@pytest.mark.parametrize("f", HIST, ids=lambda f: f.name)
def test_historical_proof_is_anchored_when_the_retired_contract_is_trusted(chain, f):
    proof = json.loads(f.read_text())
    c = chain(anchored={(RETIRED.lower(), HIST_ROOT): HIST_TIME})
    r = verify_anchor(proof["leaf"], proof, {"evm-contract": evm_contract_lookup(c.url, [CONTRACT, RETIRED], chain_id=48816)})
    assert r.status == "anchored" and r.anchored_at == "2026-10-05T02:45:33Z"
    # The second entry is a kind this checker does not know: indeterminate, not a failure.
    assert [a["status"] for a in r.anchors] == ["confirmed", "indeterminate"]


def test_historical_proof_is_indeterminate_when_only_the_current_contract_is_trusted(chain):
    proof = json.loads(HIST[0].read_text())
    c = chain(anchored={(RETIRED.lower(), HIST_ROOT): HIST_TIME})
    r = verify_anchor(proof["leaf"], proof, {"evm-contract": evm_contract_lookup(c.url, [CONTRACT])})
    assert r.status == "indeterminate" and c.calls == []


def test_no_network_without_a_lookup(monkeypatch):
    import socket

    def no_net(*a, **k):
        raise AssertionError("verify_anchor opened a socket")
    monkeypatch.setattr(socket.socket, "connect", no_net)
    assert verify_anchor(H, with_anchor(P)).status == "indeterminate"
