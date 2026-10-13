# tanilo-receipt-verify 0.2.1 against the "Taming the many EdDSAs" cases and the identity-key forgery

Run 2026-10-13 (UTC) for the x402-foundation/tsc#4 follow-up. The package was installed from PyPI into a fresh virtual environment; nothing was imported from a source checkout. Every package in that environment is pinned in `requirements.txt`. The pins are the versions pip resolved for `tanilo-receipt-verify==0.2.1` in a first run earlier the same day (`pip freeze` of that environment); that run gave the same results, byte for byte.

## What was tested

| | |
|---|---|
| Package | tanilo-receipt-verify 0.2.1, from PyPI |
| File pip installed | `tanilo_receipt_verify-0.2.1-py3-none-any.whl` |
| Its sha256 (from pip's install report, `pip-report.json`) | `2acc8939b7a2890bee70354426f0de880a9f1b22ccde89ac921db84392b32ab2` |
| Same file downloaded separately, sha256 | `2acc8939b7a2890bee70354426f0de880a9f1b22ccde89ac921db84392b32ab2` (equal) |
| sdist on PyPI, sha256 | `67bedbbde1a95ca3fb521f36f096d7f8fd56fab69e68ddc723dce84b338ee3b7` |
| Environment | tanilo-receipt-verify 0.2.1; cryptography 50.0.2; OpenSSL 4.0.3 29 Sep 2026; Python 3.14.7 |
| Vectors | cases 0, 1, 2, 6, 7, 8, 9, 10, 11: read from `tests/test_ed25519_small_order.py` inside the 0.2.1 sdist. Cases 3, 4, 5 are not in the package's tests; they come from the published `cases.txt` of novifinancial/ed25519-speccheck (sha256 `db14ccd6953ffa79c81586da8f4ab41dd893f7efd07af97d027a27c179b3ab6b`; the command that fetches it is under "Exact commands"). The script asserts that the nine vectors in the tests equal the published ones. |

The crypto library pinned in `requirements.txt` is newer than the one named in the 0.2.1 CHANGELOG (cryptography 50.0.1 with OpenSSL 4.0.2 there; 50.0.2 with OpenSSL 4.0.3 here). The last column shows what this newer library does by itself.

## Cases 0 to 11

"0.2.1" is the result of the two steps `verify()` performs for an EdDSA signature, applied to each vector's own message: first the input guard (`check_ed25519`), then, only if the guard lets it through, the crypto library. The vectors' messages are raw bytes, not JWS signing inputs, so they cannot be passed through `verify()` itself; the next section does that for inputs that can.

| Case | What it is | 0.2.1 | Reason code | Decided by | Library alone |
|---|---|---|---|---|---|
| 0 | small A and R, S = 0 | **rejected** | `small_order_key` | guard | accepts |
| 1 | small A only | **rejected** | `small_order_key` | guard | accepts |
| 2 | small R only | **rejected** | `small_order_r` | guard | accepts |
| 3 | mixed-order A and R | **accepted** | none | library | accepts |
| 4 | mixed-order A and R | **rejected** | (none: ordinary signature failure) | library | rejects |
| 5 | mixed-order A, R of order L | **rejected** | (none: ordinary signature failure) | library | rejects |
| 6 | S > L | **rejected** | `signature_s_out_of_range` | guard | rejects |
| 7 | S >> L | **rejected** | `signature_s_out_of_range` | guard | rejects |
| 8 | non-canonical R (small-order) | **rejected** | `small_order_r` | guard | rejects |
| 9 | non-canonical R (small-order) | **rejected** | `small_order_r` | guard | rejects |
| 10 | non-canonical A (small-order) | **rejected** | `small_order_key` | guard | rejects |
| 11 | non-canonical A (small-order) | **rejected** | `small_order_key` | guard | accepts |

- **Rejected by the guard, with a reason code: cases 0, 1, 2, 6, 7, 8, 9, 10, 11.** Among these the library alone accepts cases 0, 1, 2 and 11.
- **Case 3 is accepted by the tested library after passing the guard. The guard does not test whether A or R belongs to the prime-order subgroup.** Its key and R are mixed-order: outside the prime-order subgroup but not small-order. RFC 8032 does not require rejecting such points, the guard lets them through, and the library accepts this signature.
- **Cases 4 and 5 are rejected, but by the library, not by the guard.** They are mixed-order too, so the guard lets them through; the library's verification then fails. The result is an ordinary failed signature with no reason code.

## Through the public `verify()`

JWS envelopes built for the purpose, so the status and reason are the ones a caller of `verify()` sees.

| Input | `verify()` status | Reason code | Library alone |
|---|---|---|---|
| identity key, R = identity, S = 0, payload {"a": 1} | **invalid** | `small_order_key` | accepts |
| identity key, R = identity, S = 0, payload {"a": 2, "b": "a different message"} | **invalid** | `small_order_key` | accepts |
| the small-order key of cases 0/1 with an equation-valid signature for a JWS | **invalid** | `small_order_key` | accepts |
| a key that passes the key checks, signature with R = identity | **invalid** | `small_order_r` | rejects |
| a key that passes the key checks, signature with S = L | **invalid** | `signature_s_out_of_range` | (not run) |

The identity-key forgery (public key = the identity point, signature R = identity, S = 0) is rejected as `small_order_key` on both messages. The library alone accepts it on both.

## Exact commands

In an empty directory, with `run_cases.py` and `requirements.txt` from this folder:

```bash
python3 -m venv venv
./venv/bin/python -m pip install --no-cache-dir --report pip-report.json -r requirements.txt
./venv/bin/python -m pip freeze
./venv/bin/python -m pip download --no-cache-dir --no-deps --only-binary :all: -d wheel "tanilo-receipt-verify==0.2.1"
./venv/bin/python -m pip download --no-cache-dir --no-deps --no-binary :all: -d sdist "tanilo-receipt-verify==0.2.1"
shasum -a 256 wheel/* sdist/*
mkdir sdist-x && tar -xzf sdist/*.tar.gz -C sdist-x
curl -sSL -o cases.txt https://raw.githubusercontent.com/novifinancial/ed25519-speccheck/master/cases.txt
shasum -a 256 cases.txt
D="$PWD" && cd / && "$D/venv/bin/python" "$D/run_cases.py" "$D/sdist-x/tanilo_receipt_verify-0.2.1/tests/test_ed25519_small_order.py" "$D/cases.txt"
```

`shasum -a 256 cases.txt` must print `db14ccd6953ffa79c81586da8f4ab41dd893f7efd07af97d027a27c179b3ab6b  cases.txt`. If it prints any other hash, the published file has changed since this run: stop. `cases.txt` is not kept in this folder; the file fetched by the command above was identical on 12 and 13 October 2026.

`pip freeze` must print the four lines of `requirements.txt`. `pip-report.json` beside this file is pip's own report of the install command above, unedited; it contains no local paths.

The script is run from `/` so that Python cannot pick up a source checkout from the current directory. It prints `results.json`, which is saved beside this file.
