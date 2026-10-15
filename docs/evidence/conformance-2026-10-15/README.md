# tanilo-receipt-verify as the Ed25519 layer in the acceptance-record conformance corpus

This tests our package as the Ed25519 layer inside the upstream runner and acceptance-record checker. It is not a test of verify() and not an independent implementation of the acceptance-record profile.

Run 2026-10-15 (UTC) on the acceptance-record corpus of babyblueviper1/preaction-governance-conformance
(`examples/acceptance-record-cold/`, 50 vectors).

## Results

| Ed25519 layer | Vectors that agree with the corpus |
|---|---|
| The corpus's own `tools/_ed25519.py` (runner and checker unchanged) | 50/50 |
| tanilo-receipt-verify 0.2.1, installed from PyPI | 48/50 |
| tanilo-receipt-verify 0.2.3, installed from a wheel built from this repository | 50/50 |

The two vectors 0.2.1 does not agree with, and the package's own answer on their signature step (`reasons-*.txt`):

| Vector | Corpus expects | Result with 0.2.1 | 0.2.1's answer | 0.2.3's answer |
|---|---|---|---|---|
| `acc-mixed-order-key-accepted-by-both-equations` | `key_unresolved` | `verified` | guard passes; library accepts | `mixed_order_key` |
| `acc-mixed-order-key-equations-disagree` | `key_unresolved` | `malformed` / `signature_invalid` | guard passes; library rejects (no reason) | `mixed_order_key` |

The third mixed-order vector, `acc-mixed-order-r-real-key`, agrees with both versions: with 0.2.1 the library
rejects the signature (`signature_invalid`, as expected); with 0.2.3 the guard refuses it as `mixed_order_r`.

## What was replaced, and how results map

The runner (`examples/acceptance-record-cold/run_vectors.py`), the checker (`tools/acceptance_record_check.py`) and
the vectors are not changed. `run_with_tanilo.py` replaces three functions of the corpus's `tools/_ed25519.py` at
import time, then runs the runner:

| Replaced function | Backed by the installed tanilo-receipt-verify |
|---|---|
| `_ed25519.verify(public_key, message, signature)` | `ed25519_guard.check_ed25519`; if it gives a reason, `False`; otherwise the result of the crypto library's Ed25519 verification (the EdDSA path of the package's `verify()`) |
| `_ed25519.is_small_order_key(public_key)` | `True` when `ed25519_guard.check_public_key` gives a `small_order_key` reason |
| `_ed25519.is_mixed_order_key(public_key)` | `True` when the key passes `check_public_key` and `ed25519_guard.is_torsion_free` is false; always `False` with 0.2.1, which has no subgroup check |

How the checker turns these into outcomes (`tools/acceptance_record_check.py` at the commit below):

- `is_small_order_key` or `is_mixed_order_key` true: the key is not usable for its kid. With no usable key the
  result is `key_unresolved`.
- `verify` false: the result is `malformed`, with `key_step` and condition `signature_invalid`.
- `verify` true: `key_step` is `signature_verified` and the checker goes on to its later steps; `verified` is the
  result when those pass too.

So here our guard's answer on a key is used at the checker's key-resolution step and shows up as `key_unresolved`.
The package's own `verify()` checks the key when it checks the signature, and refuses a mixed-order key there as a
failed verification with reason `mixed_order_key`.

## Environment

| | |
|---|---|
| Corpus | babyblueviper1/preaction-governance-conformance at `5abe7a646ca2361a9009a18957f62215d23fa2dd` (`corpus-commit.txt`) |
| `vectors.json` sha256 | `c5d0a142cf22b1cfff366fb1b6689de0b0d88ba0ad5cf846db9027204f0c138a` (`vectors-sha256.txt`); the same bytes as at `9d4cf2c` |
| OS | macOS 26.6.2 (build 25G83), arm64 |
| Python | 3.14.7, in both virtual environments |
| Crypto library | cryptography 50.0.2 with OpenSSL 4.0.3 (29 Sep 2026), in both |
| 0.2.1 | `tanilo-receipt-verify==0.2.1` from PyPI; installed `ed25519_guard.py` sha256 `2fb65a919a4aecf83d1345b319de2a984fe8c8e0b5d198433093343a0b3243e3` |
| 0.2.3 | wheel built from commit `a0f49bd` of this repository, sha256 `574e47d95dd2431799a220560d97ff8681ddeccf2f2a8fbfd8642af86ffd633f`; its package files are listed below |

The corpus's own runner (`baseline.txt`) is run with the system `python3`, also Python 3.14.7 (the corpus's tools are stdlib only). Package lists of both environments are in
`environment-venvs.txt`.

Package files of the 0.2.3 wheel used (sha256):

```
bfc70d1b273baeae78ab41bb908f8a8d7fca674017ef689a950c35ba35344a66  tanilo_receipt_verify/__init__.py
e6b83f70b5235b315303d48e37c833c8b1a8e4023362a09147108df1aa3c0d8b  tanilo_receipt_verify/anchor.py
8222e828d7e6f12331f901535707371bc87bf85e21037a481731234ec6d8ea45  tanilo_receipt_verify/ed25519_guard.py
99b9bdcea005b8e3b1535b9fb639692fd7193917b5e3db05e26a9e5282f8144f  tanilo_receipt_verify/mapping.py
08e2be703a7d62e6007a56338d9064e6bf8222dcc930cde3c2d25d8aa69528c8  tanilo_receipt_verify/verify.py
```

## Exact commands

`run.sh` holds them. In an empty directory:

```bash
WHEEL=/path/to/tanilo_receipt_verify-0.2.3-py3-none-any.whl sh /path/to/this/folder/run.sh
```

It clones the corpus and checks out the commit above, records the commit and the `vectors.json` digest, runs the
corpus's runner unchanged (`baseline.txt`), creates one virtual environment with 0.2.1 from PyPI and one with the
0.2.3 wheel, runs `run_with_tanilo.py` in each (`tanilo-0.2.1.txt`, `tanilo-0.2.3.txt`), runs `reasons.py` in each
(`reasons-0.2.1.txt`, `reasons-0.2.3.txt`), and records both environments (`environment-venvs.txt`).

## Files

- `run_with_tanilo.py`: the adapter, as run.
- `reasons.py`: prints the package's own answer on the signature step for the mixed-order vectors, as run.
- `run.sh`: the exact commands.
- `baseline.txt`, `tanilo-0.2.1.txt`, `tanilo-0.2.3.txt`: the runner's full output, unedited.
- `reasons-0.2.1.txt`, `reasons-0.2.3.txt`: the output of `reasons.py`, unedited.
- `corpus-commit.txt`, `vectors-sha256.txt`, `environment-venvs.txt`: recorded by `run.sh`.
- `bbv-vector-equations.txt`: the RFC 8032 section 5.1.7 equation results for
  `acc-mixed-order-key-accepted-by-both-equations`, computed separately (cofactorless holds only with k reduced
  modulo L; cofactored holds with either reading of k).
