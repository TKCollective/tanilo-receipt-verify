# Mixed-order Ed25519 fixtures

## `acceptance-record-cold-9d4cf2c.json`

The three mixed-order vectors from @babyblueviper1's preaction-governance-conformance at
9d4cf2c7782fe79b68c7679b4967180ebdb9e0bd, `examples/acceptance-record-cold/vectors.json` (CC0-1.0; that file's
sha256 is `c5d0a142cf22b1cfff366fb1b6689de0b0d88ba0ad5cf846db9027204f0c138a`):

- `acc-mixed-order-key-accepted-by-both-equations`
- `acc-mixed-order-key-equations-disagree`
- `acc-mixed-order-r-real-key`

Each vector's `acceptance` JWS is rewritten from flattened to general serialization. The `protected`, `payload` and
`signature` strings are copied unchanged, so the signing input is the same. `jwk` is the trust-material entry for the
signature's kid. `expect_in_source` is the acceptance-record profile's expectation, kept for reference only: this
verifier reports its own statuses (`valid` / `invalid` / `indeterminate`) and does not use that profile's
`key_unresolved` mapping.

## `tanilo-shaped.json`

Built by `build_tanilo_shaped.py` (deterministic). Two receipts in the form the Tanilo API issues, over the payload of
the live AER-1 interop receipt (`aer1-payload.b64u.txt`, copied unchanged from
tanilo-receipt-spec `examples/interop/aer1/receipt.jws.json`), under fixture keys whose scalar is published in the
builder on purpose. Neither key is a production key.

- `mixed-order-key`: a mixed-order key with a signature that satisfies both the cofactorless and the cofactored
  RFC 8032 section 5.1.7 equation, with k taken as the full SHA-512 digest (as RFC 8032 states it) and with k
  reduced mod L (as common implementations compute it).
- `mixed-order-r`: a prime-order key with a mixed-order R; the cofactored equation holds and the cofactorless one
  does not, with the full k and with k mod L.

Correction, 2026-10-15: the first version of this fixture (0.2.2) chose its nonce with k mod L only. Its
`mixed-order-key` signature satisfied the cofactorless equation with k mod L but not with the full k. The builder now
checks both readings of k, and the fixture was regenerated.
