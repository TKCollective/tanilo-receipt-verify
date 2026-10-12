"""Ed25519 input guard: small-order points, non-canonical encodings, S range.

Why this exists (0.2.1, 2026-10-12). RFC 8032 Ed25519 verification as most
libraries implement it (OpenSSL and therefore `cryptography`, Node, BoringSSL,
Go, ...) accepts a public key that is a small-order point. Under such a key a
signature can verify for *every* message: with the identity point as the key,
R = identity and S = 0 satisfies the verification equation whatever the
message is. A receipt "verified" under such a key would therefore establish
nothing, yet the library says valid. The same holds for a signature whose R is
a small-order point, and the published "Taming the many EdDSAs" vectors
(Chalkias, Garillot, Nikolaenko, 2020; novifinancial/ed25519-speccheck) show
`cryptography` ("PyCA") accepting their cases 0, 1, 2 and 11.

This module checks the key and the signature *before* the library is called:

- the public key must decode to a point on the curve (RFC 8032 section
  5.1.3, including its rule that x = 0 with the sign bit set is invalid),
  must be canonically encoded (y < p), and must not be a small-order point
  (order 1, 2, 4 or 8: the eight points of the torsion subgroup, whatever
  their encoding);
- the signature's R must decode and must not be a small-order point;
- the signature's S must satisfy 0 <= S < L (RFC 8032 section 5.1.7).

Everything here is pure Python on integers; it is a few field operations per
check and never raises on malformed input (it returns a reason instead).

Reason codes returned by `check_ed25519` (each followed by a short text):
  key_length, key_not_on_curve, noncanonical_key_encoding, small_order_key,
  signature_length, r_not_on_curve, noncanonical_r_encoding, small_order_r,
  signature_s_out_of_range.
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


def check_public_key(raw: bytes) -> Optional[str]:
    """None when the key is a canonical encoding of a point that is not small-order."""
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
    if len(sig) != 64:
        return f"signature_length: an Ed25519 signature is 64 bytes, got {len(sig)}"
    r_pt, noncanonical = decode_point(sig[:32])
    if r_pt is None:
        return "r_not_on_curve: the signature's R does not encode a point on the Ed25519 curve"
    if is_small_order(r_pt):
        return (
            "small_order_r: the signature's R encodes a small-order point (order 1, 2, 4 or 8)"
            + (", in a non-canonical encoding" if noncanonical else "")
            + "; such an R contributes nothing message-dependent to the verification equation"
        )
    if noncanonical:
        return "noncanonical_r_encoding: the signature's R is not a canonical RFC 8032 encoding (y >= p, or x = 0 with the sign bit set)"
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return "signature_s_out_of_range: S >= L; RFC 8032 section 5.1.7 requires 0 <= S < L"
    return None


def check_ed25519(public_key: bytes, signature: bytes) -> Optional[str]:
    """Reason the pair must be rejected before any library call, or None.

    The key is checked first, so a small-order key with a small-order R
    reports `small_order_key`.
    """
    return check_public_key(public_key) or check_signature(signature)
