"""Chain verification for current-schema EvidenceReceipt v2 entries.

Pipelock's flight recorder wraps each v2 EvidenceReceipt in an entry of
type ``evidence_receipt``. This module checks those receipts the way the Go
verifier does (``internal/contract/receipt``):

* the envelope fields, canonicalization profile and ``crit`` list;
* the key purpose required for the ``payload_kind``;
* ``signer_key_id`` equal to the hex public key of the verifying key;
* the Ed25519 signature over the JCS bytes of the receipt with the
  ``signature`` object replaced by four empty strings;
* the chain: ``chain_seq`` equal to the position, ``chain_prev_hash``
  equal to ``genesis`` and then the SHA-256 hex of the previous receipt's
  JCS bytes, and a single signer across the chain.

Payload bodies are not validated field by field. The signature covers them,
so they cannot be altered without detection, but their schema is not
checked here.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._common import _is_valid_rfc3339
from ._jcs import JCSError, canonicalize

_RECORD_TYPE = "evidence_receipt_v2"
_RECEIPT_VERSION = 2
_SIGNATURE_PREFIX = "ed25519:"
_SIGNATURE_LEN = 64
_PUBLIC_KEY_LEN = 32
_GENESIS = "genesis"
_UINT64_MAX = 2**64 - 1
_HEX64 = re.compile(r"[0-9a-f]{64}")

# Envelope fields of receipt.EvidenceReceipt (internal/contract/receipt/receipt.go).
_REQUIRED_FIELDS = frozenset(
    {
        "record_type",
        "receipt_version",
        "payload_kind",
        "canonicalization",
        "crit",
        "event_id",
        "timestamp",
        "signature",
        "chain_seq",
        "chain_prev_hash",
        "payload",
    }
)
# Fields Go omits when empty. Present-but-empty values would change the
# signed bytes, so they are rejected rather than silently accepted.
_OPTIONAL_STRING_FIELDS = frozenset(
    {
        "principal",
        "actor",
        "active_manifest_hash",
        "contract_hash",
        "policy_hash",
        "selector_id",
    }
)
_ENVELOPE_FIELDS = (
    _REQUIRED_FIELDS | _OPTIONAL_STRING_FIELDS | {"delegation_chain", "contract_generation"}
)
_SIGNATURE_FIELDS = frozenset({"signer_key_id", "key_purpose", "algorithm", "signature"})

# DefaultCanonicalizationProfile in internal/contract/receipt.
_CANONICALIZATION = {
    "jcs_profile": "pipelock-jcs-rfc8785-nfc-v1",
    "jcs_version": "rfc8785",
    "hash_alg": "sha256",
    "sig_alg": "ed25519",
    "redaction_ruleset_id": "pipelock-transform-v1",
    "redaction_ruleset_version": "1",
    "redaction_ruleset_hash": (
        "sha256:541896788b42651a202448894583a847db9d1aa081c33a7e1f0512303d72527e"
    ),
}

# payloadAuthority in internal/contract/verify.go.
_PAYLOAD_AUTHORITY = {
    "proxy_decision": "receipt-signing",
    "proxy_decision_with_spans": "receipt-signing",
    "secret_egress_decision_v1": "receipt-signing",
    "contract_ratified": "receipt-signing",
    "contract_promote_intent": "contract-activation-signing",
    "contract_promote_committed": "receipt-signing",
    "contract_rollback_authorized": "contract-activation-signing",
    "contract_rollback_committed": "receipt-signing",
    "contract_demoted": "receipt-signing",
    "contract_expired": "receipt-signing",
    "contract_drift": "receipt-signing",
    "shadow_delta": "receipt-signing",
    "opportunity_missing": "receipt-signing",
    "key_rotation": "contract-activation-signing",
    "contract_redaction_request": "contract-activation-signing",
}
# Kinds whose signature is not the plain envelope signature checked here.
_UNSUPPORTED_KINDS = frozenset({"secret_egress_decision_v1"})
_POLICY_HASH_KINDS = frozenset(
    {"proxy_decision", "proxy_decision_with_spans", "secret_egress_decision_v1"}
)
# crit names tied to one payload kind: allowed for that kind and required by it.
_KIND_CRIT = {
    "proxy_decision_with_spans": "source_spans",
    "secret_egress_decision_v1": "secret_egress_decision_v1",
}
_ZERO_SIGNATURE = {"signer_key_id": "", "key_purpose": "", "algorithm": "", "signature": ""}


@dataclass
class EvidenceChainResult:
    """Outcome of verifying the evidence receipts of one recorder file."""

    valid: bool
    error: str | None = None
    broken_at_seq: int | None = None
    count: int = 0
    signer_key_id: str | None = None
    key_pinned: bool = False
    root_hash: str | None = None


def is_current_schema(receipt: dict[str, Any]) -> bool:
    """Return True for v2 envelopes that use the current Go schema."""
    return receipt.get("record_type") == _RECORD_TYPE and "canonicalization" in receipt


def signable_preimage(receipt: dict[str, Any]) -> bytes:
    """JCS bytes the signer signed: the receipt with an all-empty signature."""
    clone = dict(receipt)
    clone["signature"] = dict(_ZERO_SIGNATURE)
    return canonicalize(clone)


def receipt_hash(receipt: dict[str, Any]) -> str:
    """SHA-256 hex of the JCS bytes of the full receipt (Go ReceiptHash)."""
    return hashlib.sha256(canonicalize(receipt)).hexdigest()


def _check_crit(crit: Any, payload_kind: str) -> str | None:
    if not isinstance(crit, list) or not all(isinstance(c, str) for c in crit):
        return "crit must be a list of strings"
    seen: set[str] = set()
    for name in crit:
        if name == "":
            return "crit carries an empty name"
        if name in seen:
            return f"crit carries duplicate name {name!r}"
        seen.add(name)
        if name == "canonicalization":
            continue
        if _KIND_CRIT.get(payload_kind) != name:
            return f"crit name {name!r} is not allowed for payload_kind {payload_kind!r}"
    if "canonicalization" not in seen:
        return "crit must include 'canonicalization'"
    required = _KIND_CRIT.get(payload_kind)
    if required is not None and required not in seen:
        return f"crit must include {required!r} for payload_kind {payload_kind!r}"
    return None


def _check_policy_hash(value: Any) -> str | None:
    if not isinstance(value, str) or value == "":
        return "policy_hash is required"
    if not value.startswith("sha256:") or not _HEX64.fullmatch(value[len("sha256:") :]):
        return "policy_hash must be sha256:<64 lowercase hex>"
    return None


def check_structure(receipt: Any) -> str | None:
    """Envelope checks that do not need a key. Returns an error or None."""
    if not isinstance(receipt, dict):
        return "evidence receipt must be a JSON object"
    unknown = sorted(set(receipt) - _ENVELOPE_FIELDS)
    if unknown:
        return f"unknown envelope fields: {unknown}"
    missing = sorted(_REQUIRED_FIELDS - set(receipt))
    if missing:
        return f"missing envelope fields: {missing}"
    if receipt["record_type"] != _RECORD_TYPE:
        return f"record_type must be {_RECORD_TYPE!r}"
    version = receipt["receipt_version"]
    if not isinstance(version, int) or isinstance(version, bool) or version != _RECEIPT_VERSION:
        return f"receipt_version must be {_RECEIPT_VERSION}"
    if receipt["canonicalization"] != _CANONICALIZATION:
        return "canonicalization profile does not match pipelock-jcs-rfc8785-nfc-v1"
    payload_kind = receipt["payload_kind"]
    if not isinstance(payload_kind, str) or payload_kind not in _PAYLOAD_AUTHORITY:
        return f"unknown payload_kind: {payload_kind!r}"
    if payload_kind in _UNSUPPORTED_KINDS:
        return f"payload_kind {payload_kind!r} is not supported by this verifier"
    err = _check_crit(receipt["crit"], payload_kind)
    if err:
        return err
    event_id = receipt["event_id"]
    if not isinstance(event_id, str) or event_id == "":
        return "event_id is required"
    if not _is_valid_rfc3339(receipt["timestamp"]):
        return "timestamp must be RFC 3339"
    for name in _OPTIONAL_STRING_FIELDS:
        if name in receipt and (not isinstance(receipt[name], str) or receipt[name] == ""):
            return f"{name} must be a non-empty string when present"
    if "delegation_chain" in receipt:
        chain = receipt["delegation_chain"]
        if not isinstance(chain, list) or not chain or not all(isinstance(c, str) for c in chain):
            return "delegation_chain must be a non-empty list of strings when present"
    if "contract_generation" in receipt:
        gen = receipt["contract_generation"]
        if not isinstance(gen, int) or isinstance(gen, bool) or not 0 < gen <= _UINT64_MAX:
            return "contract_generation must be a positive uint64 when present"
    if payload_kind in _POLICY_HASH_KINDS:
        err = _check_policy_hash(receipt.get("policy_hash"))
        if err:
            return err
    seq = receipt["chain_seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or not 0 <= seq <= _UINT64_MAX:
        return "chain_seq must be a uint64"
    if not isinstance(receipt["chain_prev_hash"], str) or receipt["chain_prev_hash"] == "":
        return "chain_prev_hash is required"
    if not isinstance(receipt["payload"], dict):
        return "payload must be a JSON object"
    sig = receipt["signature"]
    if not isinstance(sig, dict) or set(sig) != _SIGNATURE_FIELDS:
        return f"signature must carry exactly {sorted(_SIGNATURE_FIELDS)}"
    if not all(isinstance(sig[name], str) for name in _SIGNATURE_FIELDS):
        return "signature fields must be strings"
    if sig["signer_key_id"] == "":
        return "signature.signer_key_id is required"
    if sig["key_purpose"] != _PAYLOAD_AUTHORITY[payload_kind]:
        return (
            f"key_purpose {sig['key_purpose']!r} is not authorized for payload_kind "
            f"{payload_kind!r} (requires {_PAYLOAD_AUTHORITY[payload_kind]!r})"
        )
    if sig["algorithm"] != "ed25519":
        return f"unsupported signature algorithm: {sig['algorithm']!r}"
    return None


def _decode_signature(value: str) -> bytes | str:
    if not value.startswith(_SIGNATURE_PREFIX):
        return f"invalid signature format: missing {_SIGNATURE_PREFIX} prefix"
    # Go encoding/hex.DecodeString rejects whitespace; bytes.fromhex ignores it.
    encoded = value[len(_SIGNATURE_PREFIX) :]
    if re.fullmatch(r"[0-9a-fA-F]*", encoded) is None:
        return "decoding signature: invalid hexadecimal encoding"
    try:
        raw = bytes.fromhex(encoded)
    except ValueError as exc:
        return f"decoding signature: {exc}"
    if len(raw) != _SIGNATURE_LEN:
        return f"invalid signature length: got {len(raw)}, want {_SIGNATURE_LEN}"
    return raw


def _decode_key(public_key_hex: str) -> bytes | str:
    if re.fullmatch(r"[0-9a-fA-F]*", public_key_hex) is None:
        return "decoding public key: invalid hexadecimal encoding"
    try:
        raw = bytes.fromhex(public_key_hex)
    except ValueError as exc:
        return f"decoding public key: {exc}"
    if len(raw) != _PUBLIC_KEY_LEN:
        return f"invalid public key length: got {len(raw)}, want {_PUBLIC_KEY_LEN}"
    return raw


def verify_receipt(
    receipt: Any,
    public_key_hex: str,
    expected_signer_key_id: str | None = None,
) -> str | None:
    """Verify one current-schema evidence receipt. Returns an error or None.

    ``signer_key_id`` must equal ``public_key_hex`` (lowercase hex), as in
    Go ``VerifyWithKey`` with ``SignerKeyID(pinned)``. When
    ``expected_signer_key_id`` is given it must match as well.
    """
    err = check_structure(receipt)
    if err:
        return err
    key = public_key_hex.strip().lower()
    key_bytes = _decode_key(key)
    if isinstance(key_bytes, str):
        return key_bytes
    signer_key_id = receipt["signature"]["signer_key_id"]
    if expected_signer_key_id is not None and signer_key_id != expected_signer_key_id:
        return f"signer_key_id {signer_key_id!r} does not match expected {expected_signer_key_id!r}"
    if signer_key_id != key:
        return f"signer_key_id {signer_key_id!r} does not match the verifying key"
    sig = _decode_signature(receipt["signature"]["signature"])
    if isinstance(sig, str):
        return sig
    try:
        preimage = signable_preimage(receipt)
    except JCSError as exc:
        return f"computing preimage: {exc}"
    try:
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(sig, preimage)
    except InvalidSignature:
        return "signature verification failed"
    return None


def verify_evidence_chain(
    receipts: Sequence[Any],
    public_key_hex: str | None = None,
    expected_signer_key_id: str | None = None,
) -> EvidenceChainResult:
    """Verify every evidence receipt of a recorder file as one chain.

    Without ``public_key_hex`` the key is taken from the first receipt's
    ``signer_key_id`` (which Go sets to the hex public key) and every
    receipt must verify against it, mirroring how the v1 chain trusts the
    first ``signer_key``. Pass ``public_key_hex`` to pin the key.
    """
    if not receipts:
        return EvidenceChainResult(valid=True)
    key = (public_key_hex or "").strip().lower()
    pinned = key != ""
    if not pinned:
        first = receipts[0]
        sig = first.get("signature") if isinstance(first, dict) else None
        candidate = sig.get("signer_key_id") if isinstance(sig, dict) else None
        if not isinstance(candidate, str) or not _HEX64.fullmatch(candidate):
            return EvidenceChainResult(
                valid=False,
                broken_at_seq=0,
                error=(
                    "evidence seq 0: signer_key_id is not a hex public key; "
                    "pass the signer key to verify evidence receipts"
                ),
            )
        key = candidate

    prev_hash = _GENESIS
    for i, receipt in enumerate(receipts):
        # Linkage first, then the signature, in the order Go reports them.
        err = check_structure(receipt)
        if err is None and receipt["chain_seq"] != i:
            err = f"chain_seq {receipt['chain_seq']} does not match position {i}"
        if err is None and receipt["chain_prev_hash"] != prev_hash:
            err = "chain_prev_hash does not match the previous receipt"
        if err is None:
            err = verify_receipt(receipt, key, expected_signer_key_id)
        if err is not None:
            return EvidenceChainResult(
                valid=False,
                broken_at_seq=i,
                error=f"evidence seq {i}: {err}",
                count=i,
                signer_key_id=key,
                key_pinned=pinned,
            )
        try:
            prev_hash = receipt_hash(receipt)
        except JCSError as exc:
            return EvidenceChainResult(
                valid=False, broken_at_seq=i, error=f"evidence seq {i}: hashing: {exc}"
            )
    return EvidenceChainResult(
        valid=True,
        count=len(receipts),
        signer_key_id=key,
        key_pinned=pinned,
        root_hash=prev_hash,
    )
