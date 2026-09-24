# Changelog

## Unreleased — `jwks_is_complete` parameter

New keyword argument on `verify()`: `jwks_is_complete: bool = False`.

An unresolved `kid` is ambiguous on its own — it can mean "this is just whatever keys I fetched" (a gap) or "this IS my complete trust list" (a refusal). Previously the verifier always assumed the former. Now the caller says which:

- **`jwks_is_complete=False` (default, no behavior change):** an unresolved `kid` reports `verified: None`; overall status is `indeterminate` when nothing else fails. Identical to every prior release.
- **`jwks_is_complete=True`:** an unresolved `kid` reports `verified: False`, an error naming the `kid` is added to `.errors`, and overall status is `invalid` — a policy refusal, not a gap. Applies both to the partial-JWKS case (some issuers supplied, this one isn't) and to the fully-omitted case (no JWKS supplied at all, declared complete regardless).

Does not change how a signature that resolves and genuinely fails cryptographic verification is reported — that is `invalid` under either setting, unchanged.

Converged out of the tsc#4 GitHub thread (2026-09-24): [robertolocatelli81-dev](https://github.com/robertolocatelli81-dev)'s `keys_are_complete` and [babyblueviper1](https://github.com/babyblueviper1)'s `--referenced-set-is-complete` (shipped in [preaction-governance-conformance@3ffddb0](https://github.com/babyblueviper1/preaction-governance-conformance/commit/3ffddb0)) are the same split applied to different artifacts — a JWKS key set here, a referenced-proof set there. `jwks_is_complete` is that shape, credited to both, applied to this package's own JWKS lookup.

**Test coverage:** `tests/test_jwks_is_complete.py`, 7 tests — the default-unchanged case, the declared-complete refusal case (partial JWKS and fully-omitted JWKS), confirms a resolved signer's `verified: True` is untouched by the flag, and confirms the flag never softens a genuine cryptographic failure.

## 0.1.0 — first release of `tanilo-receipt-verify`

Supersedes `agentoracle-receipt-verify` 0.1.0. Same verifier, same API, one defect correction (AC-11).

### AC-11 — partial-JWKS case no longer reported as `invalid`

`agentoracle-receipt-verify` 0.1.0 handled the fully-omitted-JWKS case correctly (`indeterminate`, not `valid`). It did not handle the partial case: a composed, multi-signer envelope where the caller supplies JWKS for some but not all signers.

For a signer whose `kid` had no match in any supplied JWKS, 0.1.0 recorded `{"verified": False}` — indistinguishable from a genuine cryptographic signature failure. `all_signatures_verified` then read that as a real failure, and adjudication ranked it above "unevaluated," so the envelope came back `status: "invalid"` — a verdict about a signature that was never actually checked, not one that failed a check.

This release distinguishes the two cases:

- **Unresolved key lookup** (no JWK for that signer's `kid` in any supplied issuer's set) → `verified: None`, `issuer: "unresolved"`. Overall status is `indeterminate` when every other check passes, with `indeterminate_reason` naming the unresolved `kid`(s).
- **Cryptographic failure** (key found, signature checked, verification fails) → `verified: False`. Overall status is `invalid`.

Precedence rule: a real `False` outranks a `None` for the overall `all_signatures_verified` check. All-`None`-no-`False` means every signer that had key material verified, and at least one signer's key was never supplied — an honest "could not fully check," not a pass and not a fail.

**Upgrading:** if your code branches on `status == "invalid"` to detect a partial-JWKS call, that call now correctly returns `status == "indeterminate"` instead. `result.errors` no longer contains a "signature verify failed" line for a signer whose key was never supplied — check `result.indeterminate_reason` for that case instead.

**Test coverage:** `tests/test_ac11_partial_jwks.py` locks this in with a real multi-signer fixture (three genuine Ed25519 signers). Its core assertions were confirmed to fail against the actual published `agentoracle-receipt-verify==0.1.0` wheel (status came back `invalid` with the unresolved kid in `errors`) and pass against this release. The file also promotes five other hand-checked scenarios from the fix into the permanent suite: all-omitted and empty-dict JWKS on a multi-signer envelope, a genuine cryptographic failure with the key present, a mixed real-failure-plus-unresolved-key case (failure must still outrank unresolved), and a fully resolvable single- and three-signer happy path.

### Also in this release

- Package renamed `agentoracle-receipt-verify` → `tanilo-receipt-verify`. Import path is now `from tanilo_receipt_verify import verify` (previously `agentoracle_receipt_verify`).
- No behavior changes beyond the AC-11 fix above. Everything in `agentoracle-receipt-verify` 0.1.0's own CHANGELOG entry (tri-state `status`/`valid`, `indeterminate_reason`, fail-closed `None`) carries forward unchanged.

---

## Prior history (as `agentoracle-receipt-verify`)

### 0.1.0 — 2026-08-11

**Corrected a defect in 0.0.1 that could report a signed envelope as `valid` without checking any signature.**

`verify(envelope, jwks_by_issuer=None)` gated all signature verification behind the presence of key material. Called without `jwks_by_issuer` on a genuinely signed envelope, it returned `valid=True` with zero signatures checked. Fixed by introducing the tri-state `status` (`"valid"` / `"invalid"` / `"indeterminate"`) and making `valid` `Optional[bool]`, `None` when indeterminate.

### 0.0.1 — 2026-06-01

Initial release. Superseded — see above.
