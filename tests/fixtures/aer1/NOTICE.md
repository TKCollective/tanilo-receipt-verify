# AER-1 interop receipt (copied)

`receipt.jws.json` and `jwks-tanilo-io-2026-10-08.json` are byte-identical copies of the files of the same name in
TKCollective/tanilo-receipt-spec, `examples/interop/aer1/`, as of commit e1206d1a54ae23d7e0f6fed55cd85ca7149275e2
(the last commit that changed them).

| File | sha256 |
| --- | --- |
| `receipt.jws.json` | `3feb5a4fee5c2d4719c53c144ce143b2b76b3f96903d43f45dec01d4ad8cebd8` |
| `jwks-tanilo-io-2026-10-08.json` | `296616c95c3fe2e7ec048b5fe7d4a33050f516a5e3eafd43731197d24eef5691` |

The receipt was issued by the live API on 2026-10-08 (kid `tanilo-2026-10-ed25519-7d885da9`). It is used by
`tests/test_ed25519_mixed_order.py` to show that a published receipt still verifies with the mixed-order checks.
