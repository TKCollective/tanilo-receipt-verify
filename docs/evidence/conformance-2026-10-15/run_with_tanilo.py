"""Runs the corpus's own runner (examples/acceptance-record-cold/run_vectors.py, unchanged) with the corpus's Ed25519
module (tools/_ed25519.py) replaced at import time by functions backed by the installed tanilo-receipt-verify:
  verify(pk, msg, sig)      -> the package's EdDSA path: ed25519_guard.check_ed25519, then the crypto library
  is_small_order_key(pk)    -> the package's guard says small_order_key for this key
  is_mixed_order_key(pk)    -> the package's guard says the key is mixed-order (0.2.1 has no such check: False)
The checker (tools/acceptance_record_check.py) and the vectors are not changed.
usage: python -I run_with_tanilo.py <corpus repo>
"""
import os, runpy, sys
repo = os.path.abspath(sys.argv[1])
sys.path.insert(0, os.path.join(repo, "tools"))
import _ed25519 as E
import tanilo_receipt_verify as T
from tanilo_receipt_verify import ed25519_guard as G
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import hashlib
print(f"# tanilo-receipt-verify {T.__version__}; installed ed25519_guard.py sha256 "
      f"{hashlib.sha256(open(G.__file__, 'rb').read()).hexdigest()}")

def verify(public_key, message, signature):
    if G.check_ed25519(public_key, signature) is not None:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message); return True
    except Exception:
        return False

def is_small_order_key(public_key):
    r = G.check_public_key(public_key)
    return bool(r) and r.startswith("small_order_key")

def is_mixed_order_key(public_key):
    if not hasattr(G, "is_torsion_free") or G.check_public_key(public_key) is not None:
        return False
    pt, _ = G.decode_point(bytes(public_key))
    return pt is not None and not G.is_torsion_free(pt)

E.verify, E.is_small_order_key, E.is_mixed_order_key = verify, is_small_order_key, is_mixed_order_key
sys.argv = [os.path.join(repo, "examples/acceptance-record-cold/run_vectors.py")]
try:
    runpy.run_path(sys.argv[0], run_name="__main__")
except SystemExit as e:
    print(f"# runner exit code {e.code}")
