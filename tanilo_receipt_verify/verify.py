"""Tanilo composed-envelope verifier.

Supersedes agentoracle-receipt-verify 0.1.0 (see CHANGELOG.md for the AC-11
fix this release adds). Canonicalization matches the Node reference on the
shared fixtures and supported receipt-number ranges.
Design notes (must not drift):

1. JCS sort order — RFC 8785 requires UTF-16 code-unit sort. In Node we use
   `Buffer.from(k, "utf16le").compare(...)`. Python 3 strings are Unicode code
   points; for BMP-only keys (99.999% of receipt fields) sorting by the raw
   string is byte-identical to the Node behavior. For safety against future
   emoji keys, we sort by UTF-16 BE encoding.

2. JSON.stringify vs json.dumps — Node's default JSON.stringify escapes only
   the strictly-required set (\", \\, \b, \f, \n, \r, \t, \u0000-\u001f).
   Python's json.dumps default matches when `ensure_ascii=False` and
   `separators=(",", ":")`. We reimplement the emit path explicitly to lock
   this in and never rely on library defaults.

3. Algorithms — draft-krausz-verification-state-02 Section 5.1 requires a
   conforming implementation to accept both `EdDSA` (Ed25519) and `ES256`
   (P-256 / SHA-256 ECDSA). `cryptography.hazmat`'s Ed25519PublicKey verifies
   raw 32-byte pubkeys and 64-byte sigs directly, matching Node crypto's
   Ed25519 behavior. ES256 JWS signatures are the raw R||S concatenation
   (64 bytes for P-256), which `cryptography`'s EllipticCurvePublicKey does
   NOT accept directly -- it verifies DER-encoded signatures, so ES256
   verification here re-encodes R||S to DER before calling `.verify()`.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
    SECP256R1,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

# Algorithms this verifier can actually check a signature for. draft-krausz-
# verification-state-02 Section 5.1 requires both; anything else is a known
# algorithm we simply don't verify (see _jwk_to_pubkey), not an error.
SUPPORTED_ALGS = ("EdDSA", "ES256")


# ---------- JCS (RFC 8785) ----------

def _utf16be_sort_key(k: str) -> bytes:
    """Match Node's Buffer.from(k, 'utf16le').compare(...) behavior.

    Note: Node uses UTF-16LE but on comparison operates byte-wise over the
    little-endian representation. UTF-16BE byte order gives the same relative
    ordering for BMP code points as UTF-16 code-unit sort (which RFC 8785
    requires). We use UTF-16BE for cross-language determinism.
    """
    return k.encode("utf-16-be")


def _emit(v: Any) -> str:
    """Emit JSON in the same shape Node's JSON.stringify produces (no whitespace)."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        # RFC 8785 number formatting — for the receipt use case we only emit
        # integers and unambiguous doubles that round-trip cleanly.
        if isinstance(v, float) and v.is_integer():
            return str(int(v))
        return json.dumps(v)  # matches Node for the values we emit
    if isinstance(v, str):
        # ensure_ascii=False + default escape set matches JSON.stringify
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(_emit(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=_utf16be_sort_key)
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _emit(v[k]) for k in keys) + "}"
    raise TypeError(f"unsupported JSON value type: {type(v).__name__}")


def jcs(v: Any) -> str:
    """RFC 8785 JCS canonicalization, byte-identical to the Node/Browser siblings."""
    return _emit(v)


# ---------- Hashing ----------

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ---------- decision_ref recompute (per babyblueviper1 shipped semantics) ----------

def recompute_decision_ref(slot: Dict[str, Any]) -> str:
    """Rebuild decision_ref strictly from the published preimage_fields.

    Returns "sha256:<hex>".
    """
    fields = slot["decision_ref_preimage_fields"]
    preimage = {k: slot[k] for k in fields}
    return "sha256:" + sha256_hex(jcs(preimage))


# ---------- Ed25519 JWS verify ----------

def _b64url_decode(s: str) -> bytes:
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _jwk_to_pubkey(jwk: Dict[str, Any]):
    """Return an Ed25519PublicKey or EllipticCurvePublicKey from a JWK.

    Raises ValueError on any malformed or unsupported key -- the caller MUST
    catch this (a matching `kid` with garbage key material is a fact about
    the supplied JWKS, not proof the receipt itself is invalid; see the
    call site's unresolved-kid handling, which this is deliberately folded
    into rather than allowed to propagate and crash verify()).
    """
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "OKP" and crv == "Ed25519":
        raw = _b64url_decode(jwk["x"])
        if len(raw) != 32:
            raise ValueError(f"invalid Ed25519 pubkey length: {len(raw)}")
        return Ed25519PublicKey.from_public_bytes(raw)
    if kty == "EC" and crv == "P-256":
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        return EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
    raise ValueError(f"unsupported JWK: kty={kty} crv={crv}")


def _verify_jws_signature(alg: str, payload_b64: str, protected_b64: str, sig_b64: str, pubkey) -> bool:
    """Verify a JWS signature for either EdDSA or ES256.

    Returns False (never raises) for: a cryptographically invalid signature,
    a garbled/non-base64url signature string, or a signature whose length
    doesn't match what `alg` requires. All three are "this signature does
    not verify" from the relying party's perspective -- a resolvable key
    was found and an actual check was attempted, so `False` (a real,
    evaluated failure) is the correct outcome, not an unevaluated `None`.
    """
    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
    try:
        sig = _b64url_decode(sig_b64)
    except Exception:
        return False
    try:
        if alg == "EdDSA":
            pubkey.verify(sig, signing_input)
            return True
        if alg == "ES256":
            if len(sig) != 64:
                return False
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:], "big")
            der_sig = encode_dss_signature(r, s)
            pubkey.verify(der_sig, signing_input, ECDSA(SHA256()))
            return True
        return False
    except InvalidSignature:
        return False
    except Exception:
        # Any other cryptography-level failure (wrong key type for the
        # claimed alg, malformed numbers, etc.) is still "this signature
        # does not verify" -- fail closed to False, never raise out of a
        # function whose whole job is to answer "did this verify."
        return False


# ---------- Verify result ----------

# Status vocabulary — mirrors verification-v0.4 draft §3.5 ("Anchoring status
# — adjudication without a trusted wall-clock", agentoracle-receipt-spec,
# drafts/verification-v0.4.md), NOT draft-krausz-verification-state-02, which
# has no §3.5 on this topic.
#
# That §3.5 establishes that `indeterminate_pending` "is an honest named state
# and MUST NOT be defaulted into either `not_yet_anchored` or
# `short_of_commitment`". The same reasoning governs signature evaluation
# here: an envelope whose signatures were never checked is neither valid nor
# invalid, and MUST NOT be defaulted into either neighbor. That draft's
# snapshot vocabulary already names this class of outcome `could_not_check`;
# we reuse that term rather than invent one.
STATUS_VALID = "valid"
STATUS_INVALID = "invalid"
STATUS_INDETERMINATE = "indeterminate"


@dataclass
class VerifyResult:
    """Result of a verification attempt.

    Attributes:
        status: One of "valid", "invalid", "indeterminate". This is the
            authoritative machine-readable outcome. Always prefer it over
            `valid` when branching.
        valid: Tri-state convenience mirror of `status`.
              True  -> status == "valid"
              False -> status == "invalid"
              None  -> status == "indeterminate"
            `None` is falsy, so legacy `if result.valid:` callers fail closed.
            Callers testing `result.valid == False` to detect failure MUST be
            updated: that comparison is False for the indeterminate case.
        indeterminate_reason: Populated only when status is "indeterminate";
            states plainly what could not be evaluated and why.
    """

    valid: Optional[bool]
    canonical_sha256: str
    status: str = STATUS_INVALID
    checks: Dict[str, Optional[bool]] = field(default_factory=dict)
    signers: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    indeterminate_reason: Optional[str] = None


# ---------- Public verify() ----------

def _is_list_of_dicts(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, dict) for item in value)


def _json_type_phrase(value: Any) -> str:
    """Name a decoded JSON value's type the way a JSON author would ("a string",
    "an object"), not by its Python class. bool is checked before int because
    bool is an int subclass in Python."""
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, dict):
        return "an object"
    if isinstance(value, list):
        return "an array"
    if value is None:
        return "null"
    return f"a non-JSON value ({type(value).__name__})"


def verify(
    envelope: Dict[str, Any],
    jwks_by_issuer: Optional[Dict[str, Dict[str, Any]]] = None,
    jwks_is_complete: bool = False,
) -> VerifyResult:
    """Verify an AgentOracle composed envelope.

    This is a thin, never-raising gate in front of `_verify_core`, added in
    0.1.1 per stillmarcus24's report (tsc#4, 2026-09-24): 0.1.0 raised on 22
    of 30 malformed envelopes he tested, and an exception is not one of the
    four states draft-krausz-verification-state-02 Section 3 defines. A
    caller that catches a traceback cannot tell `contradicted` from
    `instrument_failure` -- so a verifier that raises has silently opted out
    of the vocabulary it implements. This function makes that impossible:

    1. Structural validation first. `envelope` must be a dict; the object
       actually carrying `payload`/`signatures` (either `envelope` itself or
       `envelope["jws"]`) must be a dict; `payload` must be a string;
       `signatures` must be a list of dicts. Any violation is a definite,
       checkable fact about the input's shape -- not an unknown -- so it
       returns `status="invalid"` with a specific error, same as any other
       structurally-invalid envelope this verifier already rejected.
    2. Everything else -- the actual canonicalization, hashing and
       signature-verification logic in `_verify_core` -- runs inside a
       broad `except Exception`. Anything unanticipated there returns
       `status="indeterminate"` with `indeterminate_reason` beginning
       `"instrument_failure: "`, per Section 3.1's reason code for a check
       that could not run to completion -- never a raised exception.
    """
    if not isinstance(envelope, dict):
        return VerifyResult(
            valid=False, status=STATUS_INVALID, canonical_sha256="",
            errors=[f"envelope must be an object (dict), got {type(envelope).__name__}"],
        )

    jws_candidate = envelope.get("jws") if "jws" in envelope else envelope
    if not isinstance(jws_candidate, dict):
        return VerifyResult(
            valid=False, status=STATUS_INVALID, canonical_sha256="",
            errors=[f"envelope['jws'] must be an object (dict), got {type(jws_candidate).__name__}"],
        )

    payload_candidate = jws_candidate.get("payload")
    if payload_candidate is not None and not isinstance(payload_candidate, str):
        return VerifyResult(
            valid=False, status=STATUS_INVALID, canonical_sha256="",
            errors=[f"payload must be a string, got {type(payload_candidate).__name__}"],
        )

    signatures_candidate = jws_candidate.get("signatures", [])
    # 0.1.2: found while running Marcus Still's (stillmarcus24) malformed-input
    # corpus, and reported on x402-foundation/tsc#4 on 2026-09-26. A present
    # `signatures` that is not a list at all has no entries, so the list-entry
    # reason below would describe a problem the input doesn't have. Name its
    # JSON type instead.
    # This includes falsy non-lists ("", 0, {}, false), which 0.1.1 let through
    # to be reported as "missing". Absent, null and [] are still "missing".
    if signatures_candidate is not None and not isinstance(signatures_candidate, list):
        return VerifyResult(
            valid=False, status=STATUS_INVALID, canonical_sha256="",
            errors=[f"signatures must be a list (JSON array) of signature objects; got {_json_type_phrase(signatures_candidate)}"],
        )
    if signatures_candidate and not _is_list_of_dicts(signatures_candidate):
        return VerifyResult(
            valid=False, status=STATUS_INVALID, canonical_sha256="",
            errors=["signatures must be a list of objects (dicts); at least one entry was not"],
        )

    try:
        return _verify_core(envelope, jwks_by_issuer=jwks_by_issuer, jwks_is_complete=jwks_is_complete)
    except Exception as e:  # noqa: BLE001 -- intentional: see docstring above
        return VerifyResult(
            valid=None, status=STATUS_INDETERMINATE, canonical_sha256="",
            indeterminate_reason=f"instrument_failure: unhandled {type(e).__name__} during verification: {e}",
        )


def _verify_core(
    envelope: Dict[str, Any],
    jwks_by_issuer: Optional[Dict[str, Dict[str, Any]]] = None,
    jwks_is_complete: bool = False,
) -> VerifyResult:
    """Verify an AgentOracle composed envelope.

    Structural validation of `envelope`'s shape already happened in the
    public `verify()` wrapper above -- this function assumes it, and any
    exception it raises past that point is caught there and reported as
    `instrument_failure`, never propagated to the caller.

    Args:
        envelope: The composed envelope. May be either the wrapped form
            {"jws": {...}, "canonical_sha256": "...", ...} or the raw
            {"payload": "...", "signatures": [...]} JWS form.
        jwks_by_issuer: Map from JWKS URL → JWKS dict. When provided, signature
            verification runs.

            When OMITTED and the envelope carries signatures, the result is
            `status="indeterminate"` / `valid=None` — never `valid=True`.
            Recompute-invariants alone do not establish validity of a signed
            envelope: an attacker can freely produce a payload that
            canonicalizes correctly. Only the signature binds it to an issuer.

            To perform a full check, fetch each issuer's JWKS and pass it here.
            See `examples/verify.py` for the reference workflow.
        jwks_is_complete: A missing key can mean two different things and
            this verifier cannot tell them apart on its own -- the caller
            has to say which. Converged on in the tsc#4 thread (2026-09-24):
            robertolocatelli81-dev's `keys_are_complete` and
            babyblueviper1's `--referenced-set-is-complete` are the same
            split under different names.

            False (default, unchanged behavior): `jwks_by_issuer` is
            whatever keys the caller happened to have on hand, not a
            claim about every issuer that could ever sign. An unresolved
            kid is folded into `verified=None` and the result is
            `status="indeterminate"` -- an honest "could not check", not
            a failure.

            True: the caller is asserting `jwks_by_issuer` IS the complete
            trust list -- every issuer this relying party will ever accept
            is in there, so a kid absent from it is a refusal, not a gap.
            An unresolved kid then reports `verified=False`, an error
            naming the kid is added to `.errors`, and the result is
            `status="invalid"`. This does not change how a signature that
            actually fails cryptographic verification is reported -- both
            settings already return `verified=False` / invalid for that.

    Returns:
        VerifyResult. Branch on `.status`, not on the truthiness of `.valid`.
    """
    jwks_by_issuer = jwks_by_issuer or {}
    errors: List[str] = []
    # A check value of None means "not evaluated" and is NEVER a failure.
    checks: Dict[str, Optional[bool]] = {}
    signers: List[Dict[str, str]] = []

    # Accept both wrapped and raw JWS forms
    jws = envelope.get("jws") if "jws" in envelope else envelope
    payload_b64 = jws.get("payload")
    signatures = jws.get("signatures", [])
    if not payload_b64 or not signatures:
        errors.append("missing payload or signatures")
        return VerifyResult(
            valid=False, status=STATUS_INVALID, canonical_sha256="", checks=checks, errors=errors
        )

    # Decode payload
    try:
        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        errors.append(f"payload decode failed: {e}")
        return VerifyResult(
            valid=False, status=STATUS_INVALID, canonical_sha256="", checks=checks, errors=errors
        )

    # Canonical hash recompute
    canonical = jcs(payload)
    canonical_sha256 = "sha256-" + sha256_hex(canonical)
    checks["canonical_recomputes"] = True

    claimed_canonical_hash = envelope.get("canonical_sha256")
    if claimed_canonical_hash:
        checks["canonical_matches_claimed"] = (claimed_canonical_hash == canonical_sha256)
        if not checks["canonical_matches_claimed"]:
            errors.append(f"canonical hash mismatch: {claimed_canonical_hash} != {canonical_sha256}")

    # decision_ref invariant (if slot present)
    if isinstance(payload.get("decision_ref"), dict):
        slot = payload["decision_ref"]
        if "decision_ref_preimage_fields" in slot and "decision_ref" in slot:
            expected = recompute_decision_ref(slot)
            checks["decision_ref_recomputes"] = (expected == slot["decision_ref"])
            if not checks["decision_ref_recomputes"]:
                errors.append(f"decision_ref recompute mismatch: {expected} != {slot['decision_ref']}")

            # signer ≠ runtime negative
            #
            # v_gate is REQUIRED to be an object by the spec, but a malformed
            # or adversarial payload can put anything there -- a bare string,
            # a number, null. `(payload.get("v_gate") or {}).get(...)` raised
            # AttributeError on any non-dict truthy v_gate (a string is
            # truthy, so `or {}` never substitutes), crashing verify()
            # entirely instead of answering with a result. Guard with an
            # explicit isinstance check instead of relying on truthiness.
            v_gate = payload.get("v_gate")
            runtime_issuer = v_gate.get("issuer") if isinstance(v_gate, dict) else None
            decision_issuer = slot.get("issuer") if isinstance(slot, dict) else None

            if runtime_issuer is None or decision_issuer is None:
                # AC-11-class: one or both issuers are simply absent from the
                # payload -- this check cannot run at all, which is a
                # different fact from "it ran and the issuers matched."
                # `bool(None and ...)` previously collapsed this straight to
                # False (a real failure), which is exactly the
                # unevaluated-reported-as-failed bug this file exists to
                # stop. Record None; it joins `unevaluated`, not `failed`,
                # below -- and is not added to `errors`, which is reserved
                # for checks that actually ran and failed.
                checks["decision_signer_ne_runtime"] = None
            else:
                checks["decision_signer_ne_runtime"] = (runtime_issuer != decision_issuer)
                if not checks["decision_signer_ne_runtime"]:
                    errors.append(f"decision signer == runtime ({decision_issuer})")

    # JWS signature verification
    if jwks_by_issuer:
        signature_meta = payload.get("signature_meta", {})
        for sig_entry in signatures:
            protected_b64 = sig_entry.get("protected", "")
            sig_b64 = sig_entry.get("signature", "")
            try:
                protected = json.loads(_b64url_decode(protected_b64).decode("utf-8"))
            except Exception as e:
                errors.append(f"protected header decode failed: {e}")
                continue

            alg = protected.get("alg")
            kid = protected.get("kid", "")
            if alg not in SUPPORTED_ALGS:
                # draft-krausz-verification-state-02 Section 5.1 REQUIRES
                # accepting EdDSA and ES256; it does not forbid other
                # algorithms existing in the wild. A signature under an
                # algorithm this verifier doesn't implement is a LIMITATION
                # OF THIS VERIFIER, not evidence the receipt is invalid --
                # the AC-11 class of bug, on the algorithm axis instead of
                # the key-lookup axis. Record unevaluated (None), never a
                # hard error/False.
                signers.append({"kid": kid, "issuer": "unresolved", "verified": None,
                                 "reason": f"alg={alg!r} not implemented by this verifier (supports {SUPPORTED_ALGS})"})
                continue

            # Resolve pubkey by scanning provided JWKS sets
            pubkey = None
            issuer_matched: Optional[str] = None
            key_material_error: Optional[str] = None
            for issuer_url, jwks in jwks_by_issuer.items():
                for key in jwks.get("keys", []):
                    if key.get("kid") == kid:
                        try:
                            pubkey = _jwk_to_pubkey(key)
                            issuer_matched = issuer_url
                        except Exception as e:
                            # A kid MATCHED but the key material itself is
                            # malformed or an unsupported key type. Same
                            # verdict as "kid not found at all": a fact
                            # about the supplied JWKS, not the receipt --
                            # fold into the unresolved path below rather
                            # than letting the exception crash verify().
                            key_material_error = str(e)
                        break
                if pubkey or key_material_error:
                    break

            if not pubkey:
                # AC-11: key material was supplied for SOME issuer(s), but not
                # for THIS signer's issuer -- the partial-JWKS case. This is
                # not the same fact as a signature that was checked and did
                # not verify. Recording False here (pre-fix) was
                # indistinguishable from an actual cryptographic failure, so
                # one caller mistake (omitting a single issuer's JWKS on a
                # multi-signer envelope) collapsed a fully valid envelope to
                # "invalid" -- a false fail, mirroring the false-pass shape
                # reported independently on scitt#462 for an unresolved
                # signing key.
                #
                # jwks_is_complete=False (default): verified=None --
                # unevaluated, not failed. Not added to `errors`, which is
                # reserved for checks that ran and failed -- the unresolved
                # kid is recorded in `signers` (issuer="unresolved") and
                # rolled into indeterminate_reason below instead, so the
                # fact is still visible, just not miscategorized as a
                # failure.
                #
                # jwks_is_complete=True: the caller has declared
                # jwks_by_issuer IS the complete trust list, so a kid not in
                # it isn't a gap in what we happened to fetch -- it's a
                # policy refusal. This only applies when the kid is
                # genuinely absent from every supplied JWKS (key_material_error
                # is None); a kid that MATCHED but carried garbage key
                # material is a different fact (a malformed JWKS entry, not
                # an absent one) and stays unevaluated either way.
                if jwks_is_complete and key_material_error is None:
                    entry = {
                        "kid": kid,
                        "issuer": "unresolved",
                        "verified": False,
                        "reason": (
                            "jwks_is_complete=True and no JWK found for this kid in any "
                            "supplied issuer's JWKS -- treated as a policy refusal, not "
                            "an unevaluated check"
                        ),
                    }
                    signers.append(entry)
                    errors.append(f"kid not found in complete key set: kid={kid}")
                    continue
                entry = {"kid": kid, "issuer": "unresolved", "verified": None}
                if key_material_error:
                    entry["reason"] = f"kid matched but key material invalid: {key_material_error}"
                signers.append(entry)
                continue

            ok = _verify_jws_signature(alg, payload_b64, protected_b64, sig_b64, pubkey)
            signers.append({"kid": kid, "issuer": issuer_matched or "unknown", "verified": ok})
            if not ok:
                errors.append(f"signature verify failed for kid={kid}")

        # AC-11 precedence: a real False (checked, failed) outranks a None
        # (not checked). All-None-no-False means every signer that HAD key
        # material verified, but at least one signer's key was never
        # supplied -- an honest "could not fully check", not a pass and not
        # a fail. This mirrors the existing all-omitted branch below rather
        # than introducing new vocabulary.
        verified_values = [s.get("verified") for s in signers]
        if any(v is False for v in verified_values):
            checks["all_signatures_verified"] = False
        elif any(v is None for v in verified_values):
            checks["all_signatures_verified"] = None
        else:
            checks["all_signatures_verified"] = True if signers else False
    else:
        # No key material supplied at all, but the envelope IS signed.
        #
        # jwks_is_complete=False (default, unchanged): signatures were
        # neither verified nor falsified. Reporting valid=True here would
        # assert a property that was never tested; reporting False would
        # assert a failure that never occurred. Per verification-v0.4
        # draft §3.5's indeterminate_pending reasoning (see the STATUS_VALID
        # block above for the citation), this is an honest named state that
        # MUST NOT be defaulted into either neighbor. Recorded as None, not
        # False. A False entry here would be read by the adjudication below
        # as a genuine failure and would wrongly return `invalid` —
        # defaulting an unevaluated check into the other neighbor, which is
        # precisely what that §3.5 forbids.
        #
        # jwks_is_complete=True: an empty/omitted jwks_by_issuer, declared
        # complete, means the caller trusts no issuer at all -- every
        # signer's kid is a policy refusal, same reasoning as the partial-
        # JWKS branch above, just with zero keys instead of some.
        if jwks_is_complete:
            checks["all_signatures_verified"] = False
        else:
            checks["all_signatures_verified"] = None
        for sig_entry in signatures:
            kid = ""
            try:
                protected = json.loads(_b64url_decode(sig_entry.get("protected", "")).decode("utf-8"))
                kid = protected.get("kid", "")
            except Exception:
                pass
            if jwks_is_complete:
                signers.append({
                    "kid": kid,
                    "issuer": "unresolved",
                    "verified": False,
                    "reason": (
                        "jwks_is_complete=True and no JWKS was supplied at all -- "
                        "treated as a policy refusal, not an unevaluated check"
                    ),
                })
                errors.append(f"kid not found in complete key set: kid={kid}")
            else:
                # verified is None, never False — nothing was disproven.
                signers.append({"kid": kid, "issuer": "unresolved", "verified": None})

    # ---- Status adjudication ----
    #
    # Evaluated as a strict precedence: a real failure outranks an unevaluated
    # check, and an unevaluated check outranks a pass. Note that `None` entries
    # in `checks` are deliberately excluded from the failure test — an
    # unevaluated check is not a failed one.
    failed = bool(errors) or any(v is False for v in checks.values())
    unevaluated = any(v is None for v in checks.values())

    if failed:
        status = STATUS_INVALID
        valid: Optional[bool] = False
        reason = None
    elif unevaluated:
        status = STATUS_INDETERMINATE
        valid = None
        unresolved_kids = [s["kid"] for s in signers if s.get("verified") is None]
        if not jwks_by_issuer:
            # AC-11 (original case): no key material supplied at all.
            reason = (
                "envelope carries {n} signature(s) that were not checked: no key material "
                "supplied (jwks_by_issuer omitted). Canonicalization recomputed correctly, "
                "but recompute alone does not bind the payload to an issuer. Pass "
                "jwks_by_issuer to obtain a valid/invalid result."
            ).format(n=len(signatures))
        else:
            # AC-11 (partial case): some issuer(s)' JWKS supplied, but not
            # every signer's. Every signer that COULD be checked verified —
            # otherwise `failed` above would already be True. Name exactly
            # which kid(s) are unresolved so the caller can tell "missing one
            # issuer's JWKS" apart from "a signature actually failed."
            reason = (
                "{n} of {total} signature(s) could not be checked: no JWK found for "
                "kid(s) [{kids}] in the supplied jwks_by_issuer. Every signature that "
                "COULD be resolved verified successfully. This is not a failure — it is "
                "an incomplete check. Supply the missing issuer's JWKS to obtain a "
                "valid/invalid result."
            ).format(n=len(unresolved_kids), total=len(signatures), kids=", ".join(unresolved_kids))
    else:
        status = STATUS_VALID
        valid = True
        reason = None

    return VerifyResult(
        valid=valid,
        status=status,
        canonical_sha256=canonical_sha256,
        checks=checks,
        signers=signers,
        errors=errors,
        indeterminate_reason=reason,
    )
