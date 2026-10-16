"""Tanilo composed-envelope verifier (Python).

Canonicalizes with RFC 8785 JCS, verifies Ed25519 JWS signatures against
supplied JWKS, and checks recompute-invariants. JCS output and SHA-256 match
the Node reference on the shared fixtures and supported receipt-number ranges;
see tests/.

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

Test and fixture keys (0.2.4): a signer whose JWK carries tanilo_status
"fixture" or "test", or whose kid is in KNOWN_FIXTURE_KIDS, is refused by
default (`fixture_key_refused`, result invalid). `allow_test_keys=True`
verifies such keys for callers that check fixtures on purpose.

Public API:
    verify(envelope: dict, jwks_by_issuer: dict | None, jwks_is_complete=False, allow_test_keys=False) -> VerifyResult
    jcs(v) -> str
    sha256_hex(s: str) -> str
    recompute_decision_ref(decision_ref_slot: dict) -> str

Anchor check (proof of when), new in 0.2.0, in ``tanilo_receipt_verify.anchor``:
    verify_anchor(canonical_sha256: str, proof: dict, lookups: dict | None) -> AnchorResult
    evm_contract_lookup(rpc_url, trusted_contracts, chain_id=None) -> lookup
The signature verifier above is unchanged from 0.1.2.
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
    FIXTURE_KEY_STATUSES,
    KNOWN_FIXTURE_KIDS,
)

from .anchor import verify_anchor, evm_contract_lookup, AnchorResult
from .mapping import mapping_policy, MappingPolicy, TANILO_MAPPINGS, TANILO_MAPPING_CUTOVER_AT

__all__ = [
    "mapping_policy",
    "MappingPolicy",
    "TANILO_MAPPINGS",
    "TANILO_MAPPING_CUTOVER_AT",
    "verify_anchor",
    "evm_contract_lookup",
    "AnchorResult",
    "verify",
    "jcs",
    "sha256_hex",
    "recompute_decision_ref",
    "VerifyResult",
    "STATUS_VALID",
    "STATUS_INVALID",
    "STATUS_INDETERMINATE",
    "FIXTURE_KEY_STATUSES",
    "KNOWN_FIXTURE_KIDS",
]
__version__ = "0.2.4"
