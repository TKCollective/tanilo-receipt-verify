#!/bin/sh
# The exact commands of this run. Run from an empty directory, with run_with_tanilo.py, reasons.py and the 0.2.3
# wheel path given as WHEEL. Outputs are written to the current directory.
set -e
: "${WHEEL:?set WHEEL to the path of tanilo_receipt_verify-0.2.3-py3-none-any.whl}"
HERE=$(cd "$(dirname "$0")" && pwd)
git clone -q https://github.com/babyblueviper1/preaction-governance-conformance.git corpus
git -C corpus checkout -q 5abe7a646ca2361a9009a18957f62215d23fa2dd
git -C corpus rev-parse HEAD > corpus-commit.txt
shasum -a 256 corpus/examples/acceptance-record-cold/vectors.json > vectors-sha256.txt
(cd corpus/examples/acceptance-record-cold && python3 -I run_vectors.py) > baseline.txt || true
python3 -m venv venv-021
venv-021/bin/python -m pip install -q --no-cache-dir "tanilo-receipt-verify==0.2.1"
python3 -m venv venv-023
venv-023/bin/python -m pip install -q --no-cache-dir "$WHEEL"
venv-021/bin/python -I "$HERE/run_with_tanilo.py" corpus > tanilo-0.2.1.txt
venv-023/bin/python -I "$HERE/run_with_tanilo.py" corpus > tanilo-0.2.3.txt
venv-021/bin/python -I "$HERE/reasons.py" corpus > reasons-0.2.1.txt
venv-023/bin/python -I "$HERE/reasons.py" corpus > reasons-0.2.3.txt
for v in venv-021 venv-023; do
  echo "== $v"; $v/bin/python -I -c "import sys, platform, cryptography; from cryptography.hazmat.backends.openssl import backend; print('Python', sys.version.split()[0], '|', platform.platform()); print('cryptography', cryptography.__version__, '|', backend.openssl_version_text())"; $v/bin/python -m pip list --format=freeze
done > environment-venvs.txt
