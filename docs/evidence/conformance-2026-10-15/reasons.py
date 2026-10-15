"""For each vector whose id contains 'mixed-order' (or that differs), the installed package's own answer on the
signature step: the guard's reason, else what the crypto library says.  usage: python -I reasons.py <corpus repo>"""
import base64, json, os, sys
import tanilo_receipt_verify as T
from tanilo_receipt_verify import ed25519_guard as G
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
d = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
V = json.load(open(os.path.join(sys.argv[1], "examples/acceptance-record-cold/vectors.json")))["vectors"]
for v in V:
    if "mixed-order" not in v["id"]: continue
    a = v["case"]["acceptance"]; kid = json.loads(d(a["protected"]))["kid"]
    pk = d([k for k in v["case"]["trust_material"]["keys"] if k["kid"] == kid][0]["x"]); sig = d(a["signature"])
    r = G.check_ed25519(pk, sig)
    if r is None:
        try: Ed25519PublicKey.from_public_bytes(pk).verify(sig, (a["protected"] + "." + a["payload"]).encode()); lib = "library accepts"
        except Exception: lib = "library rejects (ordinary signature failure, no reason)"
        r = "guard passes; " + lib
    else:
        r = r.split(":")[0]
    print(f"  {T.__version__}  {v['id']:48s} expected {v['expect']['result']:15s} our answer: {r}")
