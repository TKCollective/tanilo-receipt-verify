# Changelog

## 0.2.1 — 2026-10-13: Ed25519 small-order guard (security); `mapping_policy`

### Security: small-order Ed25519 keys and signatures are now rejected

`verify()` now rejects small-order Ed25519 public keys and R values,
non-canonical point encodings and out-of-range S values *before* calling the
crypto library, and returns a failed verification with a reason. 0.2.0 and
earlier had no check of their own.

With the identity public key, the signature R = identity, S = 0 satisfies the
verification equation for every message. For other small-order keys,
acceptance depends on the verifier's equation and the message. This release
rejects all small-order public keys and R values.

Acceptance of these edge cases varies by library, backend and version. In our
measurements, cryptography 50.0.1 (OpenSSL 4.0.2) and Node 18 (OpenSSL 3.0.16)
accepted Taming cases 0, 1, 2 and 11 and the identity-key signature; Node 24
(OpenSSL 3.5.7) rejected them. This release applies its input restrictions
independently of the backend.
(Vectors: "Taming the many EdDSAs", Chalkias, Garillot, Nikolaenko 2020;
novifinancial/ed25519-speccheck. `python tests/diagnostic_ed25519_backend.py`
prints what the installed backend accepts.)

The identity-key behavior was reported by Noûs through @robertolocatelli81-dev
in x402-foundation/tsc#4. @babyblueviper1 reproduced it and added small-order
checks to preaction-governance-conformance at 90b5032. This release adds
corresponding input restrictions to Tanilo's verifier.

**Receipts signed with Tanilo's published keys are not affected:** all five published keys pass the new checks, and an RFC 8032 signature made
with an ordinary key has a small-order R only with negligible probability. The
risk concerned a verifier given a key set containing a crafted key. Note that
0.2.1 applies a stricter acceptance policy than the RFC 8032 verification
equation: it also rejects an equation-valid signature whose R is small-order,
which a key holder could only produce deliberately.

- New module `tanilo_receipt_verify.ed25519_guard` (pure Python integers, no
  new dependency). Before the library runs, the public key must decode per
  RFC 8032 section 5.1.3 (including: x = 0 with the sign bit set is invalid),
  be canonically encoded (y < p) and not be a small-order point (order 1, 2, 4
  or 8, in any encoding); the signature's R must decode and not be small-order;
  S must satisfy 0 <= S < L (section 5.1.7).
- A rejection is a failed verification, never a raise: `status="invalid"`,
  the signer entry carries `verified: False` and a `reason` that starts with
  one of `small_order_key`, `small_order_r`, `noncanonical_key_encoding`,
  `noncanonical_r_encoding`, `key_not_on_curve`, `r_not_on_curve`,
  `signature_s_out_of_range`, `signature_length`, `key_type`, `signature_type`;
  the same text is appended to the `errors` entry. An ordinary cryptographic failure is reported exactly as
  before (no `reason`).
- Not checked: a *mixed-order* key or R (a point outside the prime-order
  subgroup that is not itself small-order; Taming case 3). RFC 8032 does not
  require rejecting those and the library accepts them; a full-order check
  (L * A = identity) may come in a later release.
- Tests: `tests/test_ed25519_small_order.py` (44 cases): the eight small-order
  points and their non-canonical encodings as key and as R; the identity key
  with R = identity, S = 0 on two different messages; the published
  small-order key of Taming cases 0/1 with a signature the library accepts;
  Taming cases 0, 1, 2, 6, 7, 8, 9, 10, 11; S at L and above; an ordinary
  valid Tanilo receipt still verifies. The existing suite is unchanged.

### `mapping_policy`, an informative mapping-document helper

**New module `tanilo_receipt_verify.mapping`** (standard library only). `verify_anchor()` is unchanged, and `verify()` changes only as described
under Security above; all existing tests pass unmodified.

- `mapping_policy(envelope, known_mappings=None, cutover_at=…, legacy_mapping_ids=…)`
  reports a receipt's `v_gate.mapping_id`, `v_gate.mapping_hash` and `signed_at`, says
  whether the hash is one of the known documents, and flags a legacy identifier on a
  receipt signed after the cutover as `legacy_after_cutover`. Statuses: `known`,
  `unknown`, `legacy_after_cutover`, `absent`. It never raises and never changes
  `verify()`'s status: a receipt with an unrecognised or legacy mapping is a fact for
  the relying party's policy, not an invalid signature.
- Defaults name Tanilo's two published mapping documents: `agentoracle-v0.3-2026-05-30`
  (sha256 `0a78263976790df6e76cd9f3f441bf5a3b5c3a82e346b5aca43e49626881d7b0`, receipts
  signed before the cutover on 13 October 2026 (UTC), byte for byte unchanged) and
  `tanilo-v0.3-2026-10-13` (sha256
  `52842536d5c8444b6add8e8cb7e8987aa3fcc0bf40cc7ac266ddc1744f0711ce`, receipts signed
  after it). The two differ only in `mapping_id`, `issuer`, `resolution` and
  `published`; rely on `mapping_id` and `mapping_hash` rather than the signing date to
  tell receipts apart. `TANILO_MAPPING_CUTOVER_AT` is a configured policy threshold, planned for 2026-10-13T00:00:00Z.
- `signed_at` and `cutover_at` are compared as parsed RFC 3339 UTC instants (Z, 0 to
  3 fractional digits), never as strings. When the time rule applies (a legacy id
  with `cutover_at` set) and `signed_at` is missing or cannot be parsed, the status
  is `unknown` with the note "time policy not evaluated"; a non-legacy id stays
  `known`. The payload is decoded strictly (base64url grammar, validated decoding,
  duplicate JSON member names rejected; malformed gives `absent` with a note), and
  the configuration arguments are validated (a bad `known_mappings`,
  `legacy_mapping_ids` or `cutover_at` gives `unknown` with a configuration-error
  note). Nothing raises.
- mapping_policy() inspects unverified payload claims. A known result means only that the supplied mapping identifier and hash match the configured registry; it does not authenticate the receipt, issuer, signing time or mapping application. Verify the same envelope separately using authenticated trust material. (Audit finding, 2026-10-12: as strings,
  `…00:00:00.500Z` sorted before `…00:00:00Z`.)
- Tests: `tests/test_mapping_policy.py` (eleven cases, including the cutover boundary
  at `00:00:00.000Z`, `00:00:00.500Z` and one millisecond before, unparseable
  instants, that the helper is separate from `verify()` and that the time rule can be
  disabled).

## 0.2.0 — 2026-10-07: anchor check (a time bound on the payload)

**New module `tanilo_receipt_verify.anchor`** (standard library only). The
signature-verifier implementation is unchanged; all 241 existing tests pass
unmodified.

- `verify_anchor(canonical_sha256, proof, lookups=None)` recomputes, offline,
  the RFC 6962 Merkle root from a receipt's `canonical_sha256` and its
  `tanilo.anchor.v1` proof. Three outcomes, never a raise: `anchored`,
  `not_anchored`, `indeterminate`.
- With no lookup the result is `indeterminate` even when the path verifies: a
  path that reduces to a root does not show the root was ever published.
- `evm_contract_lookup(rpc_url, trusted_contracts, chain_id=None)` builds a
  lookup that asks a TaniloAnchor contract when a root was anchored. The caller
  must list the contract addresses it trusts; a proof naming any other
  contract is `indeterminate`, because an unknown contract could report any
  time it likes. An RPC on a different chain, an unreachable RPC or an
  unexpected answer is `indeterminate`. A trusted contract that does not hold
  the root is `not_anchored`.
- `AnchorResult.anchored_at` is the earliest available timestamp returned by
  successful lookups for the supplied proof's anchor records. For the EVM lookup,
  this is the trusted contract's reported timestamp, as returned by the
  configured RPC.
- The module is byte-identical to `python/tanilo_anchor_verify.py` in
  TKCollective/tanilo-anchor at `e11d8c6`, the checker the documentation page
  has been pointing readers at.

**What an anchor shows, and what it does not.** It shows that the receipt's
canonical payload existed no later than the anchoring block's timestamp, under
the hash and chain assumptions. It does not show when the signature was made
or the receipt issued, which key signed it (the signature shows that), or that
the claim is true. The lookup reads the contract's current `anchoredAt(root)`
as the RPC endpoint reports it; it does not verify the transaction details
carried in the proof and does not establish finality. Anchor status is
reported beside signature validity, never folded into it.

**391 offline/local tests; external-network testing is opt-in. Contract-lookup tests use a local fake JSON-RPC server.** `tests/test_anchor.py`
(145): 78 valid and 15 invalid Merkle vectors generated by the Node
implementation in TKCollective/tanilo-anchor (`vectors/merkle-proofs.json`,
copied byte-identical, CC0-1.0), outcome rules, malformed input, the contract
lookup against a local fake JSON-RPC server, and the three proofs of the first
GOAT testnet3 batch (retired contract, kept as a historical example).
`tests/test_mainnet_example.py` (5 offline, 1 live): the example from
tanilo.io/docs/anchoring, a receipt issued on 2026-10-06 and anchored on GOAT
Network (`eip155:2345`, contract `0xddCC4eb18b39a520b874046b91b748B5E8cE7C54`),
with the receipt, the proof and a copy of Tanilo's published key set as
fixtures. The live case runs only with `TANILO_LIVE_TESTS=1` and asks
`https://rpc.goat.network`; on 2026-10-07 it reported `anchored
2026-10-06T00:36:56Z`.

Note added 2026-10-07: the 0.1.2 entry below was headed "Unreleased" in the
repository after 0.1.2 had been published on PyPI (2026-09-28). The heading now
carries that date; the entry's text is unchanged.

## 0.1.2 — 2026-09-28: accurate reason for a non-list `signatures`; Marcus Still's vectors in the regression suite

**Reason wording.** When `signatures` is present but not a list at all, 0.1.1's
reason still said "signatures must be a list of objects (dicts); at least one
entry was not". That input has no entries, so the reason described a problem it
doesn't have. We found this while running Marcus Still's malformed-input corpus
and said so on x402-foundation/tsc#4 on 2026-09-26. The status was right; the
wording was wrong.

- A `signatures` that is a string, number, object or boolean now reports
  "signatures must be a list (JSON array) of signature objects; got a string"
  (or "a number", "an object", "a boolean").
- This also covers falsy non-list values (`""`, `0`, `{}`, `false`), which
  0.1.1 let past the shape check and reported as "missing payload or
  signatures" even though the member is present.
- Unchanged: a list with a non-object entry keeps the entry wording, and an
  absent, `null` or empty-list (`[]`) `signatures` still reports "missing
  payload or signatures".
- The status is `invalid` in every case, exactly as in 0.1.1. All 162 existing
  tests, including the well-formed cases, pass unchanged.

**Regression suite: Marcus Still's (stillmarcus24) 15 malformed-input
vectors.** They come from babyblueviper1/preaction-governance-conformance pull
request #7, commit `ac90da4e1d35fe7f840add20544cc33d123a4ff9` (merged as
`1f7cf09`), `corpus/phase1/stillmarcus24-malformed-input/`, under CC0 1.0. They
are copied byte-identical into `tests/fixtures/stillmarcus24-malformed-input/`,
with a NOTICE giving source and credit. `tests/test_stillmarcus24_corpus.py`
checks, for every vector:

- that `verify()` returns and never raises, with no key set, with a key set, and
  with `jwks_is_complete=True`;
- that the status is one his `expected.json` allows;
- that the status equals his as-run reference for 0.1.1.

It also pins the fixture files' SHA-256 to the source commit.

**Tests:** 241 pass, none raises. That is the 162 from 0.1.1 plus 14 reason
tests (`tests/test_signatures_type_reason.py`) and 65 corpus tests. The reason
test fails on 0.1.1 (9 of its 14 cases) and passes on 0.1.2.

## 0.1.1 — 2026-09-24: `verify()` no longer raises

stillmarcus24 (tsc#4, 2026-09-24) threw 30 malformed envelopes at this package
and got a traceback on 22 of them. His point is about the spec, not just the
code: an exception is not one of draft-krausz-verification-state-02's four
states. A caller that catches a traceback cannot tell `contradicted` from
`instrument_failure` apart -- so a verifier that raises has silently opted out
of the vocabulary it implements.

All three call sites he named (verify.py:291-293, :363-364, :500) crash on
some malformed input -- confirmed directly, `signatures=5` (a plain int, not
a list) with no `jwks_by_issuer` raises `TypeError: 'int' object is not
iterable` at the `for sig_entry in signatures:` line feeding :500, before its
inner `try` ever runs. All three are now unreachable in their crashing form.

`verify()` is now a two-stage gate:

1. **Structural validation first.** `envelope` must be an object; the object
   actually carrying `payload`/`signatures` (itself, or `envelope["jws"]`)
   must be an object; `payload` must be a string; `signatures` must be a list
   of objects. Any violation is a definite, checkable fact about the input's
   shape -- returns `status="invalid"` with a specific error naming what was
   wrong, same as any other malformed envelope this verifier already rejected.
2. **Everything else runs inside a broad exception guard.** The real
   canonicalization and signature-verification logic moved to a private
   `_verify_core()`; `verify()` calls it inside `try/except Exception` and
   converts anything unanticipated into `status="indeterminate"` with
   `indeterminate_reason` beginning `"instrument_failure: "` -- never a raised
   exception.

No change to any well-formed input's result. All 44 tests from the prior
release pass unchanged.

**Test coverage:** `tests/test_malformed_never_raises.py` -- 30 malformed-shape
cases (non-dict envelope, non-dict `jws`, non-string `payload`, non-list or
list-of-non-dict `signatures`, non-string `protected`/`signature` fields),
each run under three configurations (no `jwks_by_issuer`, `jwks_by_issuer`
supplied, `jwks_is_complete=True`) for 90 assertions that `verify()` returns a
result and never raises. Includes a negative control that reproduces
stillmarcus24's exact unguarded-`.get()` pattern in isolation and confirms it
still raises on the same inputs the shipped fix now handles -- proving the fix
rather than a corpus that would have passed regardless. His own vectors will
be added, credited, once he publishes them.

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
