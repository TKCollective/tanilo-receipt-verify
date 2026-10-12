"""0.2.1: Ed25519 small-order keys and R, non-canonical encodings, S >= L.

With the identity public key, the signature R = identity, S = 0 satisfies the
verification equation for every message. For other small-order keys,
acceptance depends on the verifier's equation and the message. This release
rejects all small-order public keys and R values.

The identity-key behavior was reported by Noûs through @robertolocatelli81-dev
in x402-foundation/tsc#4. @babyblueviper1 reproduced it and added small-order
checks to preaction-governance-conformance at 90b5032. This release adds
corresponding input restrictions to Tanilo's verifier.

Every rejection here is a failed verification with a named reason, never an
exception. These tests assert only that Tanilo rejects; what the crypto
backend itself accepts is reported by tests/diagnostic_ed25519_backend.py, not
asserted here. The published "Taming the many EdDSAs" vectors
(novifinancial/ed25519-speccheck, cases.txt) give the shapes. An ordinary
Tanilo receipt still verifies.
"""

import base64
import hashlib
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tanilo_receipt_verify import verify  # noqa: E402
from tanilo_receipt_verify.verify import STATUS_INVALID, STATUS_VALID  # noqa: E402
from tanilo_receipt_verify import ed25519_guard as g  # noqa: E402

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def envelope(payload: dict, kid: str, sig: bytes) -> dict:
    protected = b64u(json.dumps({"alg": "EdDSA", "kid": kid}, separators=(",", ":")).encode())
    return {"payload": b64u(json.dumps(payload, separators=(",", ":")).encode()),
            "signatures": [{"protected": protected, "signature": b64u(sig)}]}


def jwks(kid: str, raw_key: bytes) -> dict:
    return {"https://issuer.example/jwks.json": {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64u(raw_key)}]}}


def signing_input(env: dict) -> bytes:
    return (env["signatures"][0]["protected"] + "." + env["payload"]).encode("ascii")


IDENTITY_KEY = bytes([1]) + bytes(31)            # the point (0, 1), order 1
IDENTITY_SIG = IDENTITY_KEY + bytes(32)          # R = identity, S = 0

# cases.txt from novifinancial/ed25519-speccheck (msg, pbk, sig), fetched 2026-10-12
TAMING = [
    (0, "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000", "small_order_key"),
    (1, "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04", "small_order_key"),
    (2, "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e", "small_order_r"),
    (6, "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514", "signature_s_out_of_range"),
    (7, "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22", "signature_s_out_of_range"),
    (8, "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f", "small_order_r"),
    (9, "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908", "small_order_r"),
    (10, "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04", "small_order_key"),
    (11, "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04", "small_order_key"),
]

# The eight small-order points, canonical encodings (libsodium's list).
SMALL_ORDER_CANONICAL = [
    "0100000000000000000000000000000000000000000000000000000000000000",  # (0, 1) identity, order 1
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # (0, -1), order 2
    "0000000000000000000000000000000000000000000000000000000000000000",  # (sqrt(-1), 0), order 4
    "0000000000000000000000000000000000000000000000000000000000000080",  # (-sqrt(-1), 0), order 4
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  # order 8
]
# Non-canonical encodings of small-order points: y + p, and x = 0 with the sign bit set.
SMALL_ORDER_NONCANONICAL = [
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y = p + 1: the identity, non-canonical
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y = p: (0, 0)? no: y = 0 reduced -> (sqrt(-1), 0), order 4
    "0100000000000000000000000000000000000000000000000000000000000080",  # (0, 1) with the sign bit set
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # (0, -1) with the sign bit set (Taming cases 8-11)
]


# ---------- the guard on raw bytes ----------

@pytest.mark.parametrize("hexkey", SMALL_ORDER_CANONICAL)
def test_all_eight_small_order_keys_are_rejected(hexkey):
    reason = g.check_public_key(bytes.fromhex(hexkey))
    assert reason is not None and reason.startswith("small_order_key")


@pytest.mark.parametrize("hexkey", SMALL_ORDER_NONCANONICAL)
def test_noncanonical_encodings_of_small_order_keys_are_rejected_as_small_order(hexkey):
    reason = g.check_public_key(bytes.fromhex(hexkey))
    assert reason is not None and reason.startswith("small_order_key") and "non-canonical" in reason


@pytest.mark.parametrize("hexkey", SMALL_ORDER_CANONICAL + SMALL_ORDER_NONCANONICAL)
def test_the_same_points_as_r_are_rejected_as_small_order_r(hexkey):
    sig = bytes.fromhex(hexkey) + (1).to_bytes(32, "little")
    reason = g.check_signature(sig)
    assert reason is not None and reason.startswith("small_order_r")


def test_x_zero_with_sign_bit_set_is_the_rfc_8032_decode_rule():
    # (0, 1) canonical decodes; the same y with the sign bit set is flagged.
    pt, nc = g.decode_point(bytes.fromhex(SMALL_ORDER_CANONICAL[0]))
    assert pt == g.IDENTITY and nc is False
    pt2, nc2 = g.decode_point(bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000080"))
    assert pt2 == g.IDENTITY and nc2 is True


def test_s_at_and_above_l_is_rejected_and_s_just_below_l_is_not_on_that_ground():
    ok_r = bytes.fromhex("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43")  # a mixed-order point, not small-order
    assert g.check_signature(ok_r + (g.L - 1).to_bytes(32, "little")) is None
    assert g.check_signature(ok_r + g.L.to_bytes(32, "little")).startswith("signature_s_out_of_range")
    assert g.check_signature(ok_r + (2**256 - 1).to_bytes(32, "little")).startswith("signature_s_out_of_range")


def test_garbage_never_raises():
    for raw in (b"", b"\x00" * 31, b"\xff" * 32, b"\x00" * 33, bytes(range(32))):
        assert g.check_public_key(raw) is None or isinstance(g.check_public_key(raw), str)
    for sig in (b"", b"\x00" * 63, b"\xff" * 64, b"\x00" * 65):
        assert isinstance(g.check_signature(sig), str)


@pytest.mark.parametrize("case,msg,pbk,sig,expected", TAMING, ids=[f"taming-{c[0]}" for c in TAMING])
def test_taming_the_many_eddsas_vectors(case, msg, pbk, sig, expected):
    reason = g.check_ed25519(bytes.fromhex(pbk), bytes.fromhex(sig))
    assert reason is not None and reason.startswith(expected), reason


def test_wrong_input_types_are_reasons_not_exceptions():
    for bad in (None, "0100", 1, [1] * 32, 3.5):
        assert g.check_public_key(bad) == "key_type: expected bytes or bytearray"
        assert g.check_signature(bad) == "signature_type: expected bytes or bytearray"
        assert g.check_ed25519(bad, bad) == "key_type: expected bytes or bytearray"
    assert g.check_public_key(bytearray(IDENTITY_KEY)).startswith("small_order_key")
    assert g.check_signature(bytearray(IDENTITY_SIG)).startswith("small_order_r")


# ---------- through verify(): a failed verification with a named reason ----------

def _assert_rejected(result, code):
    assert result.status == STATUS_INVALID and result.valid is False
    assert len(result.signers) == 1
    s = result.signers[0]
    assert s["verified"] is False
    assert s["reason"].startswith(code), s
    assert any(code in e for e in result.errors)
    assert result.indeterminate_reason is None


@pytest.mark.parametrize("payload", [{"a": 1}, {"a": 2, "b": "a different message"}], ids=["message-1", "message-2"])
def test_identity_key_with_r_identity_and_s_zero_fails_on_different_messages(payload):
    env = envelope(payload, "identity-kid", IDENTITY_SIG)
    _assert_rejected(verify(env, jwks_by_issuer=jwks("identity-kid", IDENTITY_KEY)), "small_order_key")


def test_identity_key_fails_even_with_jwks_declared_complete():
    env = envelope({"x": "y"}, "identity-kid", IDENTITY_SIG)
    _assert_rejected(verify(env, jwks_by_issuer=jwks("identity-kid", IDENTITY_KEY), jwks_is_complete=True), "small_order_key")


def test_published_small_order_key_fails_with_an_equation_valid_signature():
    # Taming cases 0/1's key A (order 8). Build a signature that satisfies the
    # verification equation for OUR signing input: S = 0 and R = -(h mod 8) * A,
    # where h = SHA-512(R || A || M), so S*B = R + h*A holds. The guard must
    # reject it: small_order_key. (Whether the backend accepts it is not asserted.)
    raw_a = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")
    a_pt, _ = g.decode_point(raw_a)
    assert g.is_small_order(a_pt)
    env = envelope({"receipt": "shaped like ours"}, "small-kid", bytes(64))
    m = signing_input(env)
    sig = None
    for k in range(8):                                   # find the k with k*A = -h*A
        r = g.encode_point(g.point_mul(k, a_pt))
        h = int.from_bytes(hashlib.sha512(r + raw_a + m).digest(), "little") % g.L
        if (k + h) % 8 == 0:
            sig = r + bytes(32)
            break
    assert sig is not None
    env = envelope({"receipt": "shaped like ours"}, "small-kid", sig)
    _assert_rejected(verify(env, jwks_by_issuer=jwks("small-kid", raw_a)), "small_order_key")


def test_small_order_r_under_an_ordinary_key_fails_with_its_own_reason():
    # An ordinary key with R = identity: the library rejects it anyway, but the
    # guard answers first with the distinct reason.
    jb = json.loads((FIX / "jwks_by_issuer.json").read_text())
    issuer, ks = next(iter(jb.items()))
    key = [k for k in ks["keys"] if k.get("kty") == "OKP"][0]
    env = envelope({"a": 1}, key["kid"], IDENTITY_KEY + (1).to_bytes(32, "little"))
    _assert_rejected(verify(env, jwks_by_issuer={issuer: {"keys": [key]}}), "small_order_r")


def test_s_out_of_range_under_an_ordinary_key_fails_with_its_own_reason():
    jb = json.loads((FIX / "jwks_by_issuer.json").read_text())
    issuer, ks = next(iter(jb.items()))
    key = [k for k in ks["keys"] if k.get("kty") == "OKP"][0]
    ok_r = bytes.fromhex("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43")
    env = envelope({"a": 1}, key["kid"], ok_r + g.L.to_bytes(32, "little"))
    _assert_rejected(verify(env, jwks_by_issuer={issuer: {"keys": [key]}}), "signature_s_out_of_range")


def test_an_ordinary_valid_tanilo_receipt_still_verifies():
    env = json.loads((FIX / "signed_envelope.json").read_text())
    jb = json.loads((FIX / "jwks_by_issuer.json").read_text())
    r = verify(env, jwks_by_issuer=jb)
    assert r.status == STATUS_VALID and r.valid is True and r.errors == []
    assert all(s["verified"] is True for s in r.signers)
