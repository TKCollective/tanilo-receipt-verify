`merkle-proofs.json` is a byte-identical copy of `vectors/merkle-proofs.json` in
TKCollective/tanilo-anchor (CC0-1.0), generated there by `scripts/make-vectors.mjs`
with the Node implementation. The tests here check that the Python implementation
reaches the same answer on every vector.

`historical-testnet3-2026-10-05/` holds byte-identical copies of the three proofs of
the first GOAT testnet3 batch, from `examples/historical/testnet3-2026-10-05/` in the
same repository. They name the retired contract
`0x801fB569593ae8fd9E906059cA6d9e584F4Bc30b` and carry a second anchor entry of a
kind this checker does not know (`opentimestamps`, pending).
