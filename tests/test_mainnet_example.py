"""The anchoring example from tanilo.io/docs/anchoring, as a test.

Offline part (always runs): the receipt in tests/fixtures/anchor/mainnet-2026-10-06/
verifies against the copy of Tanilo's published JWKS beside it, the hash the
verifier recomputes equals the proof's leaf, the RFC 6962 path reduces to the
proof's root, the result without a lookup is "indeterminate", and with a fake
chain that answers like the real contract it is "anchored" at the block time.

Live part (runs only with TANILO_LIVE_TESTS=1): fetches the current JWKS from
tanilo.io, the current proof from api.tanilo.io, and asks the GOAT Network
contract through https://rpc.goat.network, exactly as the documentation page
tells a reader to. This is the only test in the suite that touches a network,
and it is off by default so the suite stays reproducible offline.
"""

import json
import os
import pathlib
import sys
import urllib.request

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tanilo_receipt_verify import verify, verify_anchor, evm_contract_lookup  # noqa: E402
from tests.test_anchor import FakeChain  # noqa: E402

HERE = pathlib.Path(__file__).parent / "fixtures" / "anchor" / "mainnet-2026-10-06"
JWKS_URL = "https://tanilo.io/.well-known/jwks.json"
PROOF_URL = "https://api.tanilo.io/v1/anchor/proof/"
RPC_URL = "https://rpc.goat.network"
CONTRACT = "0xddCC4eb18b39a520b874046b91b748B5E8cE7C54"
CHAIN_ID = 2345
LEAF = "sha256-67d3ddb5888ac75266974c3277987556fe5a36df97d32d014f6a5f279384c51f"
ROOT = "326302795a1ce8be3447e02a30158e43b0ab7bded209eaeb3036cff340318bc7"
BLOCK_TIME = "2026-10-06T00:36:56Z"
BLOCK_EPOCH = 1791247016

receipt = json.loads((HERE / "receipt.json").read_text())
proof = json.loads((HERE / "proof.anchor.json").read_text())
jwks = json.loads((HERE / "jwks-tanilo-io-2026-10-07.json").read_text())


def test_signature_verifies_against_the_published_key_set():
    r = verify(receipt, jwks_by_issuer={JWKS_URL: jwks})
    assert r.status == "valid" and r.canonical_sha256 == LEAF


def test_path_verifies_offline_but_is_indeterminate_without_a_lookup():
    r = verify(receipt, jwks_by_issuer={JWKS_URL: jwks})
    a = verify_anchor(r.canonical_sha256, proof)
    assert a.merkle_ok is True and a.root == ROOT and a.status == "indeterminate"
    assert a.anchors[0]["kind"] == "evm-contract" and "no lookup" in a.anchors[0]["reason"]


def test_anchored_when_a_chain_answers_like_the_real_contract():
    c = FakeChain(chain_id=CHAIN_ID, anchored={(CONTRACT.lower(), ROOT): BLOCK_EPOCH})
    try:
        a = verify_anchor(LEAF, proof, {"evm-contract": evm_contract_lookup(c.url, [CONTRACT], chain_id=CHAIN_ID)})
    finally:
        c.close()
    assert a.status == "anchored" and a.anchored_at == BLOCK_TIME


def test_the_proofs_own_leaf_is_never_what_is_checked():
    # A proof for another receipt, passed with this receipt's hash, is not anchored:
    # the hash the caller passes comes from the verifier, not from the proof.
    other = dict(proof, leaf="sha256-" + "0" * 64)
    assert verify_anchor(LEAF, other).status == "not_anchored"


def test_no_network_in_the_offline_part(monkeypatch):
    import socket

    def no_net(*a, **k):
        raise AssertionError("opened a socket")
    monkeypatch.setattr(socket.socket, "connect", no_net)
    r = verify(receipt, jwks_by_issuer={JWKS_URL: jwks})
    assert verify_anchor(r.canonical_sha256, proof).status == "indeterminate"


def _get_json(url):
    with urllib.request.urlopen(url, timeout=20) as r:
        return json.loads(r.read())


@pytest.mark.skipif(os.environ.get("TANILO_LIVE_TESTS") != "1", reason="set TANILO_LIVE_TESTS=1 to run the live mainnet check")
def test_live_mainnet_example():
    live_jwks = _get_json(JWKS_URL)
    live_proof = _get_json(PROOF_URL + LEAF)["proof"]
    r = verify(receipt, jwks_by_issuer={JWKS_URL: live_jwks})
    assert r.status == "valid" and r.canonical_sha256 == LEAF
    assert verify_anchor(r.canonical_sha256, live_proof).merkle_ok is True
    lookup = evm_contract_lookup(RPC_URL, trusted_contracts=[CONTRACT], chain_id=CHAIN_ID)
    a = verify_anchor(r.canonical_sha256, live_proof, {"evm-contract": lookup})
    assert a.status == "anchored", a
    assert a.anchored_at == BLOCK_TIME
    print(f"\nlive: signature {r.status} | path ok {a.merkle_ok} | {a.status} {a.anchored_at}")
