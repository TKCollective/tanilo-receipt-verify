# Build and publish

Releases are built on a maintainer's machine and uploaded to PyPI by hand with `twine`, using a PyPI API
token. There is no CI publish step. Replace `X.Y.Z` below with the version being released.

## Before building

- `version` in `pyproject.toml` and `__version__` in `tanilo_receipt_verify/__init__.py` are both `X.Y.Z`.
- `CHANGELOG.md` has a `## X.Y.Z` entry.
- The full suite passes: `python -m pytest -q`.
- The release branch is committed and the working tree is clean: `git status --short` prints nothing.
- If `tanilo_receipt_verify/ed25519_guard.py` changed, TKCollective/tanilo-receipt-spec has a branch that carries
  the byte-identical copy in `examples/ed25519_guard.py`, its sha256 in `examples/README.md`, and the JavaScript
  twin `examples/ed25519_guard.mjs` giving the same answers.

## Build

From the repository root, with a virtual environment that has `build` and `twine`:

```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip build twine
rm -rf build tanilo_receipt_verify.egg-info dist/tanilo_receipt_verify-X.Y.Z*
.venv/bin/python -m build
```

This writes `dist/tanilo_receipt_verify-X.Y.Z-py3-none-any.whl` and `dist/tanilo_receipt_verify-X.Y.Z.tar.gz`.
`dist/` is ignored by git and may also hold earlier versions.

## Check before uploading

```bash
.venv/bin/twine check dist/tanilo_receipt_verify-X.Y.Z-py3-none-any.whl dist/tanilo_receipt_verify-X.Y.Z.tar.gz
shasum -a 256 dist/tanilo_receipt_verify-X.Y.Z*
```

- Run the suite from the extracted sdist, so every test file and fixture the tests need is known to ship.
- Install the wheel in a fresh virtual environment, outside the repository, and verify a published receipt
  with it (for example tanilo-receipt-spec `examples/interop/aer1/receipt.jws.json` against its key set).
- Keep the two sha256 values: they are compared with PyPI after the upload.

## Upload

Name the two files explicitly, so no other version in `dist/` is uploaded:

```bash
.venv/bin/twine upload dist/tanilo_receipt_verify-X.Y.Z-py3-none-any.whl dist/tanilo_receipt_verify-X.Y.Z.tar.gz
```

At the prompt, the username is `__token__` and the password is the PyPI API token. The upload is the publish
step; nothing before it touches PyPI.

## After the upload

1. Compare PyPI's sha256 values with the local ones:
   `https://pypi.org/pypi/tanilo-receipt-verify/X.Y.Z/json`, field `urls[].digests.sha256`.
2. Install `tanilo-receipt-verify==X.Y.Z` from PyPI in a fresh virtual environment and repeat the receipt check.
3. Fast-forward `main` to the release branch and push it.
4. Tag the release commit and push the tag:

   ```bash
   git tag -a vX.Y.Z -m "tanilo-receipt-verify X.Y.Z"
   git push origin vX.Y.Z
   ```

5. If the guard changed, merge the tanilo-receipt-spec branch into its `main` and push it (its README links the
   PyPI page for X.Y.Z, so this comes after the upload).
