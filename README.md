# tanilo-receipt-verify

Verifier for composed verification-state envelopes: RFC 8785 JCS canonicalization plus EdDSA/ES256 JWS signature verification. Canonicalization output is byte-identical to the production Node canonicalizer.

**JCS number formatting:** this implementation's number serialization matches RFC 8785 for the value ranges receipt fields actually use (small integers and simple decimals) — it does not implement the full RFC 8785 §3.2.2.3 ECMAScript-compatible number-to-string algorithm across every double (extreme exponents, `-0`, etc.). If a future receipt field ever carries a number outside that range, re-verify canonicalization against the Node reference before trusting a byte-identical claim for it.

**Supersedes `agentoracle-receipt-verify` 0.1.0.** Same author, same verifier, corrected defect (AC-11) described below. If you have `agentoracle-receipt-verify` installed, switch to this package; `agentoracle-receipt-verify` will not receive further fixes.

## Design goal

Three language bindings, one canonicalization. A receipt canonicalized in Node, Python, or the browser must produce the byte-identical string and byte-identical SHA-256. No language-specific behavior. No trusted issuer round-trip.

## Install

```bash
pip install tanilo-receipt-verify
```

## Usage

**Key material is required to reach a verdict.** Pass `jwks_by_issuer`:

```python
from tanilo_receipt_verify import verify

result = verify(envelope, jwks_by_issuer={
    "https://agentoracle.co/.well-known/jwks.json": ao_jwks,
    "https://agenttrust.uk/.well-known/jwks.json": at_jwks,
})

if result.status == "valid":
    print("verified — canonical:", result.canonical_sha256)
```

### Three outcomes, not two

| `status` | `valid` | Meaning |
|---|---|---|
| `"valid"` | `True` | Every check ran and passed |
| `"invalid"` | `False` | A check ran and failed; see `.errors` |
| `"indeterminate"` | `None` | A check could not run; see `.indeterminate_reason` |

**Calling `verify(envelope)` without `jwks_by_issuer` on a signed envelope returns `indeterminate`, not `valid`.** Canonicalization recompute proves the payload matches its claimed hash; it binds the payload to no issuer. Only the signature does that. A verifier that reported `valid` there would assert a property it never tested.

`None` is falsy, so `if result.valid:` fails closed. Branch on `.status` when you need to distinguish "failed" from "could not check".

## What it checks

| Invariant | Description |
|---|---|
| `canonical_recomputes` | JCS(payload) → SHA-256 recomputes byte-identical to claimed |
| `decision_ref_recomputes` | `sha256(JCS(preimage))` matches published `decision_ref` (per invinoveritas/babyblueviper1 spec) |
| `decision_signer_ne_runtime` | Decision signer issuer ≠ runtime issuer (fail-closed: self-approval is void). `None` when either issuer is absent from the payload — the check could not run, which is not the same fact as "it ran and they matched" |
| `all_signatures_verified` | Every JWS signature (`EdDSA` or `ES256`, per draft-krausz-verification-state-02 §5.1) verifies against a resolvable JWK by `kid`. `None` when a signer's key material could not be resolved from the supplied JWKS, its key material was malformed, or its algorithm isn't one of the two this verifier implements — unevaluated, not failed. `False` for an unresolved kid instead of `None` when `jwks_is_complete=True` — see below |

## Corrects a defect in `agentoracle-receipt-verify` 0.1.0 (AC-11)

"AC-11" names this bug *class* — a checker's own incomplete input reported as a finding about the artifact it's checking, rather than a fact about the checker — as case AC-11 in [stillmarcus24/assurance-run](https://github.com/stillmarcus24/assurance-run), the independent conformance suite this class of defect was first named in. This package's own instance of it (below) is credited under that name, not coined here.

`agentoracle-receipt-verify` 0.1.0 correctly returned `indeterminate` when called with **no** `jwks_by_issuer` at all. It did **not** correctly handle the partial case: a composed, multi-signer envelope where the caller supplies JWKS for *some* but not *all* signers.

For a signer whose `kid` could not be matched against any supplied JWKS, 0.1.0 recorded `{"verified": False}` — the same value a genuine cryptographic signature failure produces. `all_signatures_verified` then read that as a real failure, and the adjudication logic ranked it above "unevaluated," returning `status: "invalid"` for an envelope that was never actually disproven — only partially checked.

This package resolves the two cases distinctly:

- **Signer's `kid` not found in any supplied JWKS** → that signer's entry reports `verified: None`, `issuer: "unresolved"`. The envelope's overall status becomes `indeterminate` (not `invalid`) when every other check passes, with `indeterminate_reason` naming which `kid`(s) could not be resolved.
- **Signer's `kid` found, signature verification actually run and fails** → that signer's entry reports `verified: False`. The envelope's overall status is `invalid`.

An unresolved key lookup and a cryptographic failure are different facts. Reporting both as `invalid` collapsed "we never checked this" into "this was checked and failed" — the same failure class documented in the 0.1.0 CHANGELOG for the fully-omitted-JWKS case, here on the partial-JWKS path instead.

## The two meanings of a missing key — `jwks_is_complete`

An unresolved `kid` can mean two different things, and this verifier cannot tell them apart on its own:

1. **"This is whatever keys I happened to have on hand."** A missing kid is a gap in what the caller fetched, not a statement about the receipt. That's the default above: `verified: None`, `status: "indeterminate"`.
2. **"This IS my complete trust list."** The caller is asserting every issuer they will ever accept is already in `jwks_by_issuer`, so a kid that isn't there is a deliberate refusal, not a gap.

Both readings are legitimate; the verifier has no way to guess which one the caller means, so it's an explicit argument instead of a guess:

```python
result = verify(
    envelope,
    jwks_by_issuer={"https://agentoracle.co/.well-known/jwks.json": ao_jwks},
    jwks_is_complete=True,  # this IS the whole trust list
)
# an unresolved kid now reports verified=False, is named in .errors,
# and the envelope's status is "invalid" — a policy refusal, not a gap
```

`jwks_is_complete` defaults to `False`, matching every example above with no behavior change. Setting it to `True` only changes what happens when a kid can't be resolved against the supplied JWKS — it does not change how a signature that resolves and genuinely fails cryptographic verification is reported; that's always `invalid` either way.

Credit where it's due: this split converged out of a public thread rather than being invented here. [robertolocatelli81-dev](https://github.com/robertolocatelli81-dev) proposed the same distinction for JWKS lookups as `keys_are_complete` in `cryptovalid-opencore`, and [babyblueviper1](https://github.com/babyblueviper1) shipped the same distinction for a different artifact — a referenced-proof set, not a key set — as `--referenced-set-is-complete` in [preaction-governance-conformance](https://github.com/babyblueviper1/preaction-governance-conformance). Both land on: absent-by-default is an absence, not a judgment; the caller has to declare completeness before a missing entry becomes a refusal. `jwks_is_complete` here is that same shape applied to this package's own JWKS lookup.

## `verify()` never raises

Any input -- not just a well-formed envelope with the wrong content, but a
non-dict `envelope`, a non-dict `jws`, a non-string `payload`, or a
`signatures` value that isn't a list of objects -- returns a `VerifyResult`.
It never raises.

Structurally malformed input (wrong shape, checkable directly) returns
`status="invalid"` with a specific error. Anything unanticipated deeper in
the verification logic is caught and returned as `status="indeterminate"`
with `indeterminate_reason` beginning `"instrument_failure: "` --
draft-krausz-verification-state-02 Section 3.1's reason code for a check that
could not run to completion. Either way, a caller gets one of the spec's four
states back, never a traceback -- per stillmarcus24's report (tsc#4,
2026-09-24) that 0.1.0 raised on 22 of 30 malformed envelopes he tested, from
unguarded call sites at the top of `verify()` and inside its signature loop.
See `CHANGELOG.md` for the full account.

## Anchor check: proof of when (in preparation for 0.2.0)

A receipt's signature shows which key signed it. An anchor adds one thing: the
receipt's canonical bytes existed no later than a public block's time.
`verify_anchor` checks a `tanilo.anchor.v1` proof for a receipt. It is separate
from `verify()` and does not change a signature result.

```python
from tanilo_receipt_verify import verify, verify_anchor, evm_contract_lookup

r = verify(envelope, jwks_by_issuer={...})
lookup = evm_contract_lookup(
    "https://rpc.testnet3.goat.network",
    trusted_contracts=["0x801fB569593ae8fd9E906059cA6d9e584F4Bc30b"],  # the contract you trust
    chain_id=48816,
)
a = verify_anchor(r.canonical_sha256, proof, {"evm-contract": lookup})
print(a.status, a.anchored_at)   # "anchored" | "not_anchored" | "indeterminate"
```

- Without a lookup, a proof whose path verifies is `indeterminate`, not
  `anchored`: the path alone does not show the root was published.
- You list the contract addresses you trust. A proof that names another
  contract is `indeterminate`.
- `verify_anchor` makes no network call itself; the lookup makes two JSON-RPC
  calls when you pass it in. It never raises.
- The example uses a testnet contract. Testnets can be reset; a proof that
  points at a reset chain can no longer be confirmed.

## Cross-language guarantees

The `tests/` suite includes byte-identical fixtures shared with the Node reference implementation:

- `test_jcs_byte_identical_to_node` — Python JCS output byte-matches Node output for a payload with nested objects, arrays, unicode, booleans, and integers.
- `test_decision_ref_recompute_babyblueviper1` — Python recomputes the shipped [invinoveritas fixture](https://github.com/babyblueviper1/preaction-governance-conformance/tree/3e54ee2/examples/decision-ref-recompute), byte-identical to her Python and our Node.
- `test_conformance_sample_canonical_hash` — reproduces the canonical hash from the production `/v1/conformance/sample` endpoint.

## License

MIT — see `LICENSE`.
