"""Mixed-order Ed25519 keys and R: refused after the small-order checks.

A mixed-order point is neither small-order nor in the prime-order subgroup: [L]P is not the identity. Whether a
signature under a mixed-order key, or with a mixed-order R, verifies depends on whether the verifier uses the
cofactorless or the cofactored equation of RFC 8032 section 5.1.7, so two conforming verifiers can disagree. This is
a stricter acceptance policy than the RFC 8032 verification equation: some equation-valid signatures are refused.

The reasons `mixed_order_key` and `mixed_order_r` are diagnostics inside the existing statuses: a refused signature
is `verified: False` and the result is `invalid`, as for the small-order reasons. Never a raise.

Vectors: "Taming the many EdDSAs" (Chalkias, Garillot, Nikolaenko 2020; novifinancial/ed25519-speccheck) case 3,
and the three mixed-order vectors of @babyblueviper1's preaction-governance-conformance at 9d4cf2c.
"""

import base64
import hashlib
import json
import pathlib
import random
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tanilo_receipt_verify import verify  # noqa: E402
from tanilo_receipt_verify.verify import STATUS_INVALID, STATUS_VALID  # noqa: E402
from tanilo_receipt_verify import ed25519_guard as g  # noqa: E402

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"
MIX = FIX / "mixed-order"


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


B = g.decode_point(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))[0]
T8 = g.decode_point(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"))[0]   # order 8

# cases.txt from novifinancial/ed25519-speccheck (msg, pbk, sig), fetched 2026-10-14
# (file sha256 db14ccd6953ffa79c81586da8f4ab41dd893f7efd07af97d027a27c179b3ab6b)
TAMING_MIXED = [
    (3, "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009"),
    (4, "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09"),
    (5, "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405"),
]

ACC = json.loads((MIX / "acceptance-record-cold-9d4cf2c.json").read_text())
ACC_EXPECTED = {
    "acc-mixed-order-key-accepted-by-both-equations": "mixed_order_key",
    "acc-mixed-order-key-equations-disagree": "mixed_order_key",
    "acc-mixed-order-r-real-key": "mixed_order_r",
}
SHAPED = json.loads((MIX / "tanilo-shaped.json").read_text())
SHAPED_EXPECTED = {"mixed-order-key": "mixed_order_key", "mixed-order-r": "mixed_order_r"}


def _acc_pair(v):
    sig_entry = v["jws"]["signatures"][0]
    return b64u_decode(v["jwk"]["x"]), b64u_decode(sig_entry["signature"])


# ---------- the guard on raw bytes ----------

def test_the_vectors_are_the_published_ones():
    assert ACC["source_sha256"] == "c5d0a142cf22b1cfff366fb1b6689de0b0d88ba0ad5cf846db9027204f0c138a"
    assert [v["id"] for v in ACC["vectors"]] == list(ACC_EXPECTED)


@pytest.mark.parametrize("case,msg,pbk,sig", TAMING_MIXED, ids=[f"taming-{c[0]}" for c in TAMING_MIXED])
def test_taming_mixed_order_cases_are_refused_as_mixed_order_key(case, msg, pbk, sig):
    # Cases 3 and 4 have a mixed-order A and R; case 5 a mixed-order A. The key is checked first.
    reason = g.check_ed25519(bytes.fromhex(pbk), bytes.fromhex(sig))
    assert reason is not None and reason.startswith("mixed_order_key:"), reason


def test_taming_case_3_r_alone_is_mixed_order():
    sig = bytes.fromhex(TAMING_MIXED[0][3])
    r_pt, _ = g.decode_point(sig[:32])
    assert not g.is_small_order(r_pt) and not g.is_torsion_free(r_pt)


@pytest.mark.parametrize("vid", list(ACC_EXPECTED))
def test_babyblueviper1_mixed_order_vectors_at_the_guard(vid):
    v = [x for x in ACC["vectors"] if x["id"] == vid][0]
    pk, sig = _acc_pair(v)
    reason = g.check_ed25519(pk, sig)
    assert reason is not None and reason.startswith(ACC_EXPECTED[vid] + ":"), reason


def test_existing_reasons_keep_their_order_mixed_order_comes_last():
    mixed_a = bytes.fromhex(TAMING_MIXED[0][2])
    ok_sig = bytes.fromhex(TAMING_MIXED[0][3])
    # small-order R under a mixed-order key: still small_order_r (Taming case 2 shape)
    assert g.check_ed25519(mixed_a, bytes([1]) + bytes(31) + (1).to_bytes(32, "little")).startswith("small_order_r:")
    # S out of range under a mixed-order key and mixed-order R: still signature_s_out_of_range
    assert g.check_ed25519(mixed_a, ok_sig[:32] + g.L.to_bytes(32, "little")).startswith("signature_s_out_of_range:")
    # non-canonical R encoding is still reported as such
    assert g.check_ed25519(mixed_a, bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") + bytes(32)).startswith("small_order_r:")
    # the two existing per-part checks are unchanged: they do not look at the subgroup
    assert g.check_public_key(mixed_a) is None
    assert g.check_signature(ok_sig) is None


def test_multiplies_by_l_itself_never_by_l_mod_l():
    # [L mod L]P = [0]P is the identity for every point, so a reduced scalar would pass everything.
    mixed = g.point_add(B, T8)
    assert g.is_torsion_free(B) is True
    assert g.is_torsion_free(mixed) is False
    assert g.is_torsion_free(T8) is False
    assert g.is_torsion_free(g.point_mul(12345, B)) is True
    assert g.L_ORDER_SCALAR == 2**252 + 27742317777372353535851937790883648493 == g.L
    assert g.mul_is_identity(0, mixed) is True          # what a reduced scalar would do
    assert g.mul_is_identity(g.L, mixed) is False       # what the guard does


@pytest.mark.parametrize("k", [0, 1, 2, 7, 8, 9, 2**128 + 3, g.L - 1, g.L, g.L + 1, 8 * g.L, 8 * g.L - 1])
@pytest.mark.parametrize("which", ["B", "T8", "B+T8", "5B"])
def test_extended_multiplication_agrees_with_the_affine_one(k, which):
    pt = {"B": B, "T8": T8, "B+T8": g.point_add(B, T8), "5B": g.point_mul(5, B)}[which]
    assert g.mul_is_identity(k, pt) == (g.point_mul(k, pt) == g.IDENTITY)


def _published_keys():
    keys = {}
    for p in [FIX / "jwks_by_issuer.json", FIX / "aer1" / "jwks-tanilo-io-2026-10-08.json",
              FIX / "anchor" / "mainnet-2026-10-06" / "jwks-tanilo-io-2026-10-07.json"]:
        doc = json.loads(p.read_text())
        sets = [doc] if "keys" in doc else list(doc.values())
        for s in sets:
            for k in s["keys"]:
                if k.get("kty") == "OKP" and k.get("crv") == "Ed25519":
                    keys[k["kid"]] = b64u_decode(k["x"])
    return keys


def test_every_published_tanilo_key_is_in_the_prime_order_subgroup():
    keys = _published_keys()
    assert {"tanilo-2026-10-ed25519-7d885da9", "ao-receipt-2026-04-ed25519-f2753b7c"} <= set(keys)
    for kid, raw in keys.items():
        pt, _ = g.decode_point(raw)
        assert g.check_public_key(raw) is None, kid
        assert g.is_torsion_free(pt), kid


def test_random_and_malformed_inputs_never_raise():
    rnd = random.Random(20261014)
    inputs = [b"", b"\x00" * 31, b"\xff" * 32, b"\x00" * 33, bytes(range(32)), bytes(64), b"\xff" * 64, None, "x", 5, [1]]
    for _ in range(300):
        inputs.append(bytes(rnd.getrandbits(8) for _ in range(rnd.choice((31, 32, 33, 63, 64, 65)))))
    for pk in inputs[:40]:
        for sig in inputs[:40]:
            r = g.check_ed25519(pk, sig)
            assert r is None or isinstance(r, str)
    for raw in inputs:
        r = g.check_ed25519(raw, raw + raw if isinstance(raw, bytes) else raw)
        assert r is None or isinstance(r, str)


# ---------- through verify(): a failed verification with a named reason ----------

def _assert_refused(result, code):
    assert result.status == STATUS_INVALID and result.valid is False
    assert len(result.signers) == 1
    s = result.signers[0]
    assert s["verified"] is False
    assert s["reason"].startswith(code + ":"), s
    assert any(code in e for e in result.errors)
    assert result.indeterminate_reason is None


@pytest.mark.parametrize("jic", [False, True], ids=["jwks-partial", "jwks-complete"])
@pytest.mark.parametrize("vid", list(ACC_EXPECTED))
def test_babyblueviper1_vectors_through_verify(vid, jic):
    v = [x for x in ACC["vectors"] if x["id"] == vid][0]
    result = verify(v["jws"], jwks_by_issuer={"https://cp.example/jwks.json": {"keys": [v["jwk"]]}}, jwks_is_complete=jic)
    _assert_refused(result, ACC_EXPECTED[vid])


@pytest.mark.parametrize("jic", [False, True], ids=["jwks-partial", "jwks-complete"])
@pytest.mark.parametrize("name", list(SHAPED_EXPECTED))
def test_tanilo_shaped_receipts_through_verify(name, jic):
    jws = SHAPED["receipts"][name]["jws"]
    _assert_refused(verify(jws, jwks_by_issuer=SHAPED["jwks_by_issuer"], jwks_is_complete=jic), SHAPED_EXPECTED[name])
    _assert_refused(verify({"jws": jws}, jwks_by_issuer=SHAPED["jwks_by_issuer"]), SHAPED_EXPECTED[name])


def test_tanilo_shaped_fixture_rebuilds_byte_for_byte_and_carries_the_aer1_payload():
    sys.path.insert(0, str(MIX))
    import build_tanilo_shaped  # noqa: E402
    assert build_tanilo_shaped.build() == SHAPED
    payload = b64u_decode(SHAPED["receipts"]["mixed-order-key"]["jws"]["payload"])
    assert hashlib.sha256(payload).hexdigest() == "ca2fb84597076f9c8fac2d957a05bf21a11bd741e519879ff09ba78fd2305325"


def _four_equations(pub, sig, msg):
    """RFC 8032 section 5.1.7, computed here: cofactorless [S]B = R + [k]A and cofactored [8][S]B = [8]R + [8][k]A,
    with k = SHA-512 of R || A || M. The test evaluates both the full SHA-512 digest specified in RFC 8032 §5.1.7 and
    the digest reduced modulo L, as used in the RFC's illustrative verifier."""
    A, R, S = g.decode_point(pub)[0], g.decode_point(sig[:32])[0], int.from_bytes(sig[32:], "little")
    full = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little")
    out = {}
    for label, k in (("full_k", full), ("k_mod_L", full % g.L)):
        lhs, rhs = g.point_mul(S, B), g.point_add(R, g.point_mul(k, A))
        out["cofactorless_" + label] = lhs == rhs
        out["cofactored_" + label] = g.point_mul(8, lhs) == g.point_mul(8, rhs)
    return out


@pytest.mark.parametrize("name,expected", [
    ("mixed-order-key", {"cofactorless_full_k": True, "cofactored_full_k": True, "cofactorless_k_mod_L": True, "cofactored_k_mod_L": True}),
    ("mixed-order-r", {"cofactorless_full_k": False, "cofactored_full_k": True, "cofactorless_k_mod_L": False, "cofactored_k_mod_L": True}),
])
def test_tanilo_shaped_receipts_satisfy_the_recorded_equations_with_full_k_and_with_k_mod_L(name, expected):
    rec = SHAPED["receipts"][name]
    sig_entry = rec["jws"]["signatures"][0]
    kid = json.loads(b64u_decode(sig_entry["protected"]))["kid"]
    pub = b64u_decode([k for k in list(SHAPED["jwks_by_issuer"].values())[0]["keys"] if k["kid"] == kid][0]["x"])
    msg = (sig_entry["protected"] + "." + rec["jws"]["payload"]).encode("ascii")
    got = _four_equations(pub, b64u_decode(sig_entry["signature"]), msg)
    assert got == expected
    assert rec["equations"] == expected


def test_the_live_aer1_receipt_still_verifies():
    receipt = json.loads((FIX / "aer1" / "receipt.jws.json").read_text())
    jwks = json.loads((FIX / "aer1" / "jwks-tanilo-io-2026-10-08.json").read_text())
    r = verify(receipt, jwks_by_issuer={"https://tanilo.io/.well-known/jwks.json": jwks})
    assert r.status == STATUS_VALID and r.valid is True and r.errors == []
    assert r.canonical_sha256 == "sha256-ca2fb84597076f9c8fac2d957a05bf21a11bd741e519879ff09ba78fd2305325"
    assert [s["kid"] for s in r.signers] == ["tanilo-2026-10-ed25519-7d885da9"]
    assert all(s["verified"] is True and "reason" not in s for s in r.signers)


def test_the_other_published_fixtures_still_verify():
    env = json.loads((FIX / "signed_envelope.json").read_text())
    jb = json.loads((FIX / "jwks_by_issuer.json").read_text())
    r = verify(env, jwks_by_issuer=jb)
    assert r.status == STATUS_VALID and all(s["verified"] is True for s in r.signers)
    mainnet = FIX / "anchor" / "mainnet-2026-10-06"
    receipt = json.loads((mainnet / "receipt.json").read_text())
    jwks = json.loads((mainnet / "jwks-tanilo-io-2026-10-07.json").read_text())
    r2 = verify(receipt, jwks_by_issuer={"https://tanilo.io/.well-known/jwks.json": jwks})
    assert r2.status == STATUS_VALID, r2.errors
