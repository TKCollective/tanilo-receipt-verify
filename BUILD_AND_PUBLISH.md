# Build and publish — run from your machine, not from here

This package is built and tested and **final**. **Nothing has been pushed or published.** The hold pending Oracle's counsel reply is lifted — `-02` is publicly posted on the IETF datatracker with the Tanilo contact (`joe@tanilo.io`), so the reason for withholding the `tanilo-receipt-verify` ↔ `agentoracle-receipt-verify` naming link from public surfaces no longer applies.

## What's already done

- Renamed from `agentoracle-receipt-verify` → `tanilo-receipt-verify`, module path `tanilo_receipt_verify`.
- AC-11 fix carried over (unresolved key lookup vs. cryptographic failure — see CHANGELOG.md).
- **37/37 tests pass** (`tests/test_byte_identical.py`, `tests/test_indeterminate_default.py`, `tests/test_ac11_partial_jwks.py`, `tests/test_defensive_and_es256.py` — the last covers ES256 support and the defensive fixes from the 2026-09-23 review round).
- Author metadata confirmed: `Joe Krausz <joe@tanilo.io>` in `pyproject.toml`.
- Repository URL confirmed: `https://github.com/TKCollective/tanilo-receipt-verify` (matches the package name, no `-py` suffix).
- `dist/` already contains a built wheel and sdist for inspection:
  - `tanilo_receipt_verify-0.1.0-py3-none-any.whl`
  - `tanilo_receipt_verify-0.1.0.tar.gz`

These were built here for verification only. Rebuild from your machine before publishing so the artifact you upload is one you built yourself.

## Before you publish — decide these

1. **PyPI project name availability.** Confirm `tanilo-receipt-verify` is unclaimed on PyPI (it wasn't checked from here since that itself would touch a public surface).
2. **GitHub repo.** `pyproject.toml` points `Repository` at `https://github.com/TKCollective/tanilo-receipt-verify` (matches the package name, no `-py` suffix) — a repo that does not exist yet. Create it (private until you're ready, or public — your call) before or after PyPI publish, but the URL in the metadata should resolve by the time anyone checks it.
3. **Author/homepage metadata.** Set to `Joe Krausz <joe@tanilo.io>` / homepage `https://tanilo.io` in `pyproject.toml`. Change before building your own copy if you want different contact details.

## Build (from your machine)

```bash
cd tanilo-receipt-verify
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip build twine
rm -rf dist build tanilo_receipt_verify.egg-info
python -m build
```

This produces `dist/tanilo_receipt_verify-0.1.0-py3-none-any.whl` and the matching `.tar.gz`.

## Verify before upload

```bash
# Confirm license is bundled correctly and metadata is right
python -m zipfile -l dist/tanilo_receipt_verify-0.1.0-py3-none-any.whl
twine check dist/*

# Optional: install the built wheel into a clean venv and re-run tests
python3 -m venv /tmp/verify_venv
source /tmp/verify_venv/bin/activate
pip install dist/tanilo_receipt_verify-0.1.0-py3-none-any.whl pytest
python -m pytest tests/ -v
deactivate
```

## Upload to PyPI

```bash
source .venv/bin/activate
twine upload dist/*
```

You'll be prompted for PyPI credentials (or use a saved `~/.pypirc` / `TWINE_USERNAME` + `TWINE_PASSWORD`/API token). This step is the actual publish — nothing before it touches PyPI.

## Recommended order once you're ready to publish

1. Create the `TKCollective/tanilo-receipt-verify` GitHub repo (no `-py` suffix — matches the package name) and push. (No existing `agentoracle-receipt-verify-py` repo to rename — checked; it doesn't exist. This is a new repo, not a rename.)
2. `twine upload dist/*` to publish to PyPI.
3. Post the two "fixed" notices (drafted separately) on `tsc#4` and `SCITT#462` linking the new package.
