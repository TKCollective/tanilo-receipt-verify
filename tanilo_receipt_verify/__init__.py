"""Tanilo composed-envelope verifier (Python).

Canonicalizes with RFC 8785 JCS, verifies Ed25519 JWS signatures against
supplied JWKS, and checks recompute-invariants. JCS output and SHA-256 are
byte-identical to the production Node canonicalizer; see tests/.

IMPORTANT: `verify()` requires `jwks_by_issuer` to reach a valid/invalid
verdict. Called without key material on a signed envelope it returns
`status="indeterminate"` / `valid=None` -- never `valid=True`. Recompute
alone does not bind a payload to an issuer.

Also in this release: a signer whose key material could not be resolved
(no matching `kid` in the supplied JWKS for that issuer) now reports
`verified: None` on that signer specifically -- not `verified: False`.
A composed envelope with JWKS for some but not all signers previously
adjudicated the whole envelope `invalid`, collapsing "we never checked
this signer" into "this signer's signature failed." See CHANGELOG.

Public API:
    verify(envelope: dict, jwks_by_issuer: dict | None) -> VerifyResult
    jcs(v) -> str
    sha256_hex(s: str) -> str
    recompute_decision_ref(decision_ref_slot: dict) -> str
"""

from .verify import (
    verify,
    jcs,
    sha256_hex,
    recompute_decision_ref,
    VerifyResult,
    STATUS_VALID,
    STATUS_INVALID,
    STATUS_INDETERMINATE,
)

__all__ = [
    "verify",
    "jcs",
    "sha256_hex",
    "recompute_decision_ref",
    "VerifyResult",
    "STATUS_VALID",
    "STATUS_INVALID",
    "STATUS_INDETERMINATE",
]
__version__ = "0.1.0"
