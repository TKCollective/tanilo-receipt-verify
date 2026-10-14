"""Ed25519 input guard: small-order points, non-canonical encodings, S range.

Why this exists (0.2.1, 2026-10-12). With the identity public key, the signature R = identity, S = 0 satisfies the
verification equation for every message. For other small-order keys,
acceptance depends on the verifier's equation and the message. This release
rejects all small-order public keys and R values.

Acceptance of these edge cases varies by library, backend and version. In our
measurements, cryptography 50.0.1 (OpenSSL 4.0.2) and Node 18 (OpenSSL 3.0.16)
accepted Taming cases 0, 1, 2 and 11 and the identity-key signature; Node 24
(OpenSSL 3.5.7) rejected them. This release applies its input restrictions
independently of the backend.
(Vectors: "Taming the many EdDSAs", Chalkias, Garillot, Nikolaenko 2020;
novifinancial/ed25519-speccheck.)

Rejecting a small-order R is a stricter acceptance policy than the RFC 8032
verification equation: an equation-valid signature whose R is a small-order
point is refused here. A key holder can construct an equation-valid signature with small-order R
deliberately. Small-order R is also possible, with negligible probability,
under normal RFC 8032 signing.

The identity-key behavior was reported by Noûs through @robertolocatelli81-dev
in x402-foundation/tsc#4. @babyblueviper1 reproduced it and added small-order
checks to preaction-governance-conformance at 90b5032. This release adds
corresponding input restrictions to Tanilo's verifier.

Mixed-order points (unreleased, after 0.2.1). A mixed-order point is neither
small-order nor in the prime-order subgroup: [L]P is not the identity. Whether
a signature under a mixed-order key, or with a mixed-order R, verifies depends
on whether the verifier uses the cofactorless or the cofactored equation of
RFC 8032 section 5.1.7, so two conforming verifiers can disagree. This module
refuses both, after every other check. Like the small-order R rule, this is a
stricter acceptance policy than the RFC 8032 verification equation: some
equation-valid signatures with a mixed-order A or R are refused. It is not a
fix for a forgery under an ordinary key. Measured on x402-foundation/tsc#4
(Taming case 3, a mixed-order A and R, was accepted by 0.2.1 and by the
library); @babyblueviper1 added mixed-order checks and three vectors to
preaction-governance-conformance at 9d4cf2c.

This module checks the key and the signature before the library verifies the
signature:

- the public key must decode to a point on the curve (RFC 8032 section
  5.1.3, including its rule that x = 0 with the sign bit set is invalid),
  must be canonically encoded (y < p), and must not be a small-order point
  (order 1, 2, 4 or 8: the eight points of the torsion subgroup, whatever
  their encoding);
- the signature's R must decode and must not be a small-order point;
- the signature's S must satisfy 0 <= S < L (RFC 8032 section 5.1.7);
- then, after all of the above: [L]A must be the identity, and [L]R must be
  the identity (L = 2^252 + 27742317777372353535851937790883648493, the
  prime order of the base point, RFC 8032 section 5.1). The point is
  multiplied by L itself; the scalar is never reduced mod L, which would
  multiply by zero and pass every point.

Everything here is pure Python on integers and never raises (a wrong input
type, a wrong length or malformed bytes return a reason instead). The [L]P
checks use extended coordinates, with no field inversion per step.

Reason codes returned by `check_ed25519` (each followed by a short text), in
the order they are checked:
  key_type, key_length, key_not_on_curve, small_order_key,
  noncanonical_key_encoding, signature_type, signature_length,
  r_not_on_curve, small_order_r, noncanonical_r_encoding,
  signature_s_out_of_range, mixed_order_key, mixed_order_r.
"""

from __future__ import annotations

from typing import Optional, Tuple

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, P - 2, P)) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)

IDENTITY = (0, 1)

Point = Tuple[int, int]


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def decode_point(b: bytes) -> Tuple[Optional[Point], bool]:
    """Decode 32 bytes per RFC 8032 section 5.1.3.

    Returns (point, noncanonical). `point` is None when the bytes do not
    encode a point on the curve. `noncanonical` is True when the encoding is
    not the canonical one: y >= p, or x = 0 with the sign bit set (the RFC
    rejects both; the point is still returned so a caller can tell a
    non-canonically encoded small-order point from an ordinary bad encoding).
    """
    if len(b) != 32:
        return None, False
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    noncanonical = False
    if y >= P:
        y -= P
        noncanonical = True
    y2 = (y * y) % P
    u = (y2 - 1) % P
    v = (_D * y2 + 1) % P
    x2 = (u * _inv(v)) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = (x * _SQRT_M1) % P
    if (x * x - x2) % P != 0:
        return None, noncanonical
    if x == 0:
        if sign == 1:
            noncanonical = True
    elif (x & 1) != sign:
        x = P - x
    return (x, y), noncanonical


def encode_point(pt: Point) -> bytes:
    x, y = pt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def point_add(a: Point, b: Point) -> Point:
    x1, y1 = a
    x2, y2 = b
    k = (_D * x1 * x2 * y1 * y2) % P
    x3 = ((x1 * y2 + x2 * y1) * _inv(1 + k)) % P
    y3 = ((y1 * y2 + x1 * x2) * _inv(1 - k)) % P
    return (x3, y3)


def point_mul(k: int, pt: Point) -> Point:
    result = IDENTITY
    addend = pt
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def is_small_order(pt: Point) -> bool:
    """True when 8 * pt is the identity: pt has order 1, 2, 4 or 8."""
    return point_mul(8, pt) == IDENTITY


# The scalar for the subgroup check: the prime order of the base point, RFC 8032 section 5.1. Used as it is,
# never reduced mod L ([L mod L]P = [0]P is the identity for every point, so a reduced scalar would pass everything).
L_ORDER_SCALAR = 2**252 + 27742317777372353535851937790883648493
assert L_ORDER_SCALAR == L
_D2 = (2 * _D) % P


def _ext_add(p1, p2):
    """Extended twisted Edwards addition, a = -1 (Hisil, Wong, Carter, Dawson 2008, "add-2008-hwcd-3").
    Complete for Ed25519 (d is not a square), so it also doubles and handles the identity."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (t1 * _D2 * t2) % P
    d = (z1 * 2 * z2) % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def mul_is_identity(k: int, pt: Point) -> bool:
    """True when [k]pt is the identity. k is used exactly as given (no reduction)."""
    x, y = pt
    result = (0, 1, 1, 0)
    addend = (x, y, 1, (x * y) % P)
    while k > 0:
        if k & 1:
            result = _ext_add(result, addend)
        addend = _ext_add(addend, addend)
        k >>= 1
    rx, ry, rz, _ = result
    return rx % P == 0 and (ry - rz) % P == 0


def is_torsion_free(pt: Point) -> bool:
    """True when [L]pt is the identity: pt is in the prime-order subgroup (or is the identity)."""
    return mul_is_identity(L_ORDER_SCALAR, pt)


def check_public_key(raw: bytes) -> Optional[str]:
    """None when the key is a canonical encoding of a point that is not small-order."""
    if not isinstance(raw, (bytes, bytearray)):
        return "key_type: expected bytes or bytearray"
    raw = bytes(raw)
    if len(raw) != 32:
        return f"key_length: an Ed25519 public key is 32 bytes, got {len(raw)}"
    pt, noncanonical = decode_point(raw)
    if pt is None:
        return "key_not_on_curve: the public key bytes do not encode a point on the Ed25519 curve"
    if is_small_order(pt):
        return (
            "small_order_key: the public key encodes a small-order point (order 1, 2, 4 or 8)"
            + (", in a non-canonical encoding" if noncanonical else "")
            + "; under such a key a signature can verify for every message, so a valid signature would establish nothing"
        )
    if noncanonical:
        return "noncanonical_key_encoding: the public key is not a canonical RFC 8032 encoding (y >= p, or x = 0 with the sign bit set)"
    return None


def check_signature(sig: bytes) -> Optional[str]:
    """None when R is a canonical encoding of a point that is not small-order and 0 <= S < L."""
    if not isinstance(sig, (bytes, bytearray)):
        return "signature_type: expected bytes or bytearray"
    sig = bytes(sig)
    if len(sig) != 64:
        return f"signature_length: an Ed25519 signature is 64 bytes, got {len(sig)}"
    r_pt, noncanonical = decode_point(sig[:32])
    if r_pt is None:
        return "r_not_on_curve: the signature's R does not encode a point on the Ed25519 curve"
    if is_small_order(r_pt):
        return (
            "small_order_r: the signature's R encodes a small-order point (order 1, 2, 4 or 8)"
            + (", in a non-canonical encoding" if noncanonical else "")
            + "; this verifier's acceptance policy rejects small-order R values (stricter than the RFC 8032 verification equation)"
        )
    if noncanonical:
        return "noncanonical_r_encoding: the signature's R is not a canonical RFC 8032 encoding (y >= p, or x = 0 with the sign bit set)"
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return "signature_s_out_of_range: S >= L; RFC 8032 section 5.1.7 requires 0 <= S < L"
    return None


def check_mixed_order(public_key: bytes, signature: bytes) -> Optional[str]:
    """The subgroup checks, for a pair that has passed check_public_key and check_signature: None when [L]A and
    [L]R are both the identity. Never raises."""
    try:
        a_pt, _ = decode_point(bytes(public_key))
        r_pt, _ = decode_point(bytes(signature)[:32])
        if a_pt is None or r_pt is None:
            return None   # not reached after the earlier checks; those already returned a reason
        if not is_torsion_free(a_pt):
            return (
                "mixed_order_key: the public key is a mixed-order point ([L]A is not the identity: it has a "
                "small-order component); whether a signature under it verifies depends on the verifier's equation "
                "(cofactored or cofactorless, RFC 8032 section 5.1.7), so this verifier's acceptance policy rejects "
                "it (stricter than the RFC 8032 verification equation)"
            )
        if not is_torsion_free(r_pt):
            return (
                "mixed_order_r: the signature's R is a mixed-order point ([L]R is not the identity: it has a "
                "small-order component); whether the signature verifies depends on the verifier's equation "
                "(cofactored or cofactorless, RFC 8032 section 5.1.7), so this verifier's acceptance policy rejects "
                "it (stricter than the RFC 8032 verification equation)"
            )
        return None
    except Exception:  # noqa: BLE001 -- the guard never raises
        return "mixed_order_check_failed: the subgroup check could not run on these bytes"


def check_ed25519(public_key: bytes, signature: bytes) -> Optional[str]:
    """Reason the pair must be rejected before the library verifies the signature, or None.

    The key is checked first, so a small-order key with a small-order R
    reports `small_order_key`. The mixed-order checks run last, after every
    earlier check has passed, so every earlier reason is reported exactly as
    before; a mixed-order key with a mixed-order R reports `mixed_order_key`.
    """
    return check_public_key(public_key) or check_signature(signature) or check_mixed_order(public_key, signature)
