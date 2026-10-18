"""EvidenceReceipt v2 schema parsing, payload validation, and verification.

Mirrors ``internal/contract/receipt/`` in Pipelock. Strict unknown-field
rejection, recursive data-class validation, JCS canonicalization over typed
structures.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._common import InvalidReceiptError, _is_valid_rfc3339
from ._jcs import JCSError, canonicalize, parse_json_strict

# Wire format constants matching internal/contract/receipt/receipt.go.
_RECORD_TYPE_EVIDENCE_V2 = "evidence_receipt_v2"
_RECEIPT_VERSION_V2 = 2
_SIGNATURE_PREFIX = "ed25519:"
_SIGNATURE_LEN = 64
_PUBLIC_KEY_LEN = 32

# All 13 payload kinds. Matches the PayloadKind constants in receipt.go.
PAYLOAD_KINDS = frozenset(
    {
        "proxy_decision",
        "contract_ratified",
        "contract_promote_intent",
        "contract_promote_committed",
        "contract_rollback_authorized",
        "contract_rollback_committed",
        "contract_demoted",
        "contract_expired",
        "contract_drift",
        "shadow_delta",
        "opportunity_missing",
        "key_rotation",
        "contract_redaction_request",
    }
)

# Key purpose authority matrix.  Maps payload_kind -> required key_purpose.
# Source: internal/contract/verify.go payloadAuthority.
PAYLOAD_AUTHORITY: dict[str, str] = {
    "proxy_decision": "receipt-signing",
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

# Top-level envelope fields. Used for unknown-field rejection.
_ENVELOPE_FIELDS = frozenset(
    {
        "record_type",
        "receipt_version",
        "payload_kind",
        "event_id",
        "timestamp",
        "principal",
        "actor",
        "delegation_chain",
        "signature",
        "chain_seq",
        "chain_prev_hash",
        "active_manifest_hash",
        "contract_hash",
        "selector_id",
        "contract_generation",
        "payload",
    }
)

# Signature proof fields. Used for unknown-field rejection.
_SIGNATURE_FIELDS = frozenset(
    {
        "signer_key_id",
        "key_purpose",
        "algorithm",
        "signature",
    }
)

# ---- Payload schemas: maps of field_name -> required ----

_PROXY_DECISION_FIELDS: dict[str, bool] = {
    "action_type": True,
    "target": True,
    "verdict": True,
    "transport": True,
    "policy_sources": True,
    "winning_source": True,
    "rule_id": False,
}

_CONTRACT_RATIFIED_FIELDS: dict[str, bool] = {
    "contract_hash": True,
    "ratifier_key_id": True,
    "ratified_rule_ids": True,
    "ratification_decision_per_rule": True,
}

_CONTRACT_PROMOTE_INTENT_FIELDS: dict[str, bool] = {
    "target_manifest_hash": True,
    "target_generation": False,  # uint64 — zero is allowed
    "prior_manifest_hash": True,
    "intent_id": True,
}

_CONTRACT_PROMOTE_COMMITTED_FIELDS: dict[str, bool] = {
    "target_manifest_hash": True,
    "prior_manifest_hash": True,
    "intent_id": True,
    "validation_outcome": True,
    "reject_reason": False,
}

_CONTRACT_ROLLBACK_AUTHORIZED_FIELDS: dict[str, bool] = {
    "rollback_target_hash": True,
    "current_generation": False,  # uint64
    "authorizer_signatures": True,
    "authorization_id": True,
}

_CONTRACT_ROLLBACK_COMMITTED_FIELDS: dict[str, bool] = {
    "rollback_target_hash": True,
    "prior_manifest_hash": True,
    "authorization_id": True,
    "validation_outcome": True,
    "reject_reason": False,
}

_CONTRACT_DEMOTED_FIELDS: dict[str, bool] = {
    "contract_hash": True,
    "rule_id": True,
    "demotion_reason": True,
    "prior_state": True,
    "new_state": True,
    "aggregation_window": True,
}

_CONTRACT_EXPIRED_FIELDS: dict[str, bool] = {
    "contract_hash": True,
    "rule_id": True,
    "expiration_reason": True,
}

_CONTRACT_DRIFT_FIELDS: dict[str, bool] = {
    "contract_hash": True,
    "rule_id": True,
    "drift_kind": True,
    "observation_summary": False,
    "missed_windows": False,
    "opportunity_status": False,
}

_SHADOW_DELTA_FIELDS: dict[str, bool] = {
    "contract_hash": True,
    "rule_id": True,
    "original_verdict": True,
    "candidate_verdict": True,
    "aggregation": True,
}

_SHADOW_DELTA_AGGREGATION_FIELDS: dict[str, bool] = {
    "window_start": True,
    "window_end": True,
    "lossless_count": True,
    "delta_sample_count": True,
    "exemplar_ids": True,
}

_OPPORTUNITY_MISSING_FIELDS: dict[str, bool] = {
    "contract_hash": True,
    "rule_id": True,
    "parent_context": True,
    "historical_opportunity_rate": True,
    "current_opportunity_rate": True,
    "window": True,
}

_KEY_ROTATION_FIELDS: dict[str, bool] = {
    "key_id": True,
    "key_purpose": True,
    "old_status": True,
    "new_status": True,
    "roster_hash": True,
    "authorization_id": True,
}

_CONTRACT_REDACTION_REQUEST_FIELDS: dict[str, bool] = {
    "target_contract_hash": True,
    "request_kind": True,
    "reason_class": True,
    "authorization_id": True,
    "tombstone_hash": True,
}

_VALID_VALIDATION_OUTCOMES = frozenset({"accepted", "rejected"})
_VALID_REQUEST_KINDS = frozenset({"withdraw_public_proof", "local_erasure_tombstone"})


@dataclass
class EvidenceVerifyResult:
    """Outcome of verifying a single EvidenceReceipt v2.

    ``valid`` is the only field guaranteed to be set. Descriptive fields
    are populated on success (and may be on some failures) for diagnostic
    output. ``error`` holds a short reason string on failure.
    """

    valid: bool
    error: str | None = None
    event_id: str | None = None
    record_type: str | None = None
    payload_kind: str | None = None
    signer_key_id: str | None = None
    key_purpose: str | None = None
    chain_seq: int | None = None
    chain_prev_hash: str | None = None
    timestamp: str | None = None


# Current-schema payload rules published by internal/contract/receipt at the
# Go revision this verifier tracks. Source-span enums are the registry
# constants; integer bounds are the uint64 fields in those structs.
_UINT64_MAX = 2**64 - 1
_INT64_MAX = 2**63 - 1
_SHA256_PREFIX = "sha256:"
_LOWER_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_TRANSFORM_PREFIX = "pipelock-transform-v"
_HMAC_MATCH_PREFIX = "hmac-sha256:"
_DLP_NORMALIZED_PREFIX = "dlp_normalized:"
_SOURCE_KINDS = frozenset(
    {
        "http_request_url",
        "http_response",
        "mcp_tool_result",
        "mcp_tool_args",
    }
)
_NORMALIZED_VIEWS = frozenset(
    {
        "sanitized_target",
        "for_matching",
        "for_matching:invisible_spaced",
        "leetspeak:for_matching",
        "vowel_fold:for_matching",
        "for_matching:base64_decoded",
        "for_matching:hex_decoded",
        "dlp_normalized",
    }
)
_OFFSETS_ALLOWED_VIEWS = frozenset({"sanitized_target", "dlp_normalized"})
_STRING_LIST_FIELDS = frozenset(
    {
        "policy_sources",
        "ratified_rule_ids",
        "authorizer_signatures",
        "exemplar_ids",
    }
)
_SOURCE_SPAN_FIELDS: dict[str, bool] = {
    "source_id": True,
    "source_kind": True,
    "normalized_view": True,
    "pipelock_binary_digest": True,
    "rules_bundle_digest": True,
    "transform_profile": True,
    "policy_hash": True,
    "rule_id": True,
    "bundle": False,
    "bundle_version": False,
    "char_offset": False,
    "char_length": False,
    "match_hash": True,
    "match_hash_alg": True,
    "match_class": True,
    "redacted_sample": False,
}
_SPAN_REQUIRED_STRINGS = (
    "source_id",
    "source_kind",
    "normalized_view",
    "pipelock_binary_digest",
    "rules_bundle_digest",
    "transform_profile",
    "policy_hash",
    "rule_id",
    "match_hash",
    "match_hash_alg",
    "match_class",
)


def _schema_for(payload_kind: str) -> dict[str, bool] | None:
    return {
        "proxy_decision": _PROXY_DECISION_FIELDS,
        "contract_ratified": _CONTRACT_RATIFIED_FIELDS,
        "contract_promote_intent": _CONTRACT_PROMOTE_INTENT_FIELDS,
        "contract_promote_committed": _CONTRACT_PROMOTE_COMMITTED_FIELDS,
        "contract_rollback_authorized": _CONTRACT_ROLLBACK_AUTHORIZED_FIELDS,
        "contract_rollback_committed": _CONTRACT_ROLLBACK_COMMITTED_FIELDS,
        "contract_demoted": _CONTRACT_DEMOTED_FIELDS,
        "contract_expired": _CONTRACT_EXPIRED_FIELDS,
        "contract_drift": _CONTRACT_DRIFT_FIELDS,
        "shadow_delta": _SHADOW_DELTA_FIELDS,
        "opportunity_missing": _OPPORTUNITY_MISSING_FIELDS,
        "key_rotation": _KEY_ROTATION_FIELDS,
        "contract_redaction_request": _CONTRACT_REDACTION_REQUEST_FIELDS,
    }.get(payload_kind)


def _sha256_wire(value: Any, label: str, *, lowercase: bool = True) -> str | None:
    hex_pattern = _LOWER_HEX64 if lowercase else _HEX64
    if (
        not isinstance(value, str)
        or not value.startswith(_SHA256_PREFIX)
        or hex_pattern.fullmatch(value[len(_SHA256_PREFIX) :]) is None
    ):
        alphabet = "lowercase hex" if lowercase else "hex"
        return f"{label} must be sha256:<64 {alphabet}>"
    return None


def _uint64(value: Any, label: str) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > _UINT64_MAX:
        return f"{label} must be a uint64"
    return None


def _string_list(value: Any, label: str) -> str | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return f"{label} must be a list of strings"
    return None


def _strict_leaf_types(payload: dict[str, Any], context: str = "payload") -> str | None:
    for field, value in payload.items():
        if field in _INT_FIELDS or field == "missed_windows":
            if value is None:
                continue
            if err := _uint64(value, f"{context} {field}"):
                return err
        elif field in _STRING_LIST_FIELDS or field in {"aggregation", "source_spans"}:
            continue
        elif field == "ratification_decision_per_rule":
            if not isinstance(value, dict) or not all(
                isinstance(item, str) for item in value.values()
            ):
                return f"{context} ratification_decision_per_rule values must be strings"
        elif value is not None and not isinstance(value, str):
            return f"{context} {field} must be a string"
    for field in _STRING_LIST_FIELDS:
        if field not in payload:
            continue
        # encoding/json marshals a nil slice as null and unmarshals that null
        # back to a nil slice. exemplar_ids has no omitempty, and a nil slice
        # has length 0, so a zero delta_sample_count is valid.
        if field == "exemplar_ids" and payload[field] is None:
            continue
        if err := _string_list(payload[field], f"{context} {field}"):
            return err
    return None


def _rfc3339_rank(value: str) -> tuple[datetime, int] | None:
    if not _is_valid_rfc3339(value):
        return None
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    match = re.match(
        r"^(?P<prefix>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
        r"(?:\.(?P<frac>\d{1,9}))?"
        r"(?P<offset>[+-]\d{2}:\d{2})$",
        candidate,
    )
    if match is None:
        return None
    frac = match.group("frac") or ""
    nanos = int((frac + "000000000")[:9]) if frac else 0
    try:
        instant = datetime.fromisoformat(f"{match.group('prefix')}{match.group('offset')}")
    except ValueError:
        return None
    return instant, nanos


def _offsets_allowed(view: str) -> bool:
    return view in _OFFSETS_ALLOWED_VIEWS or (
        view.startswith(_DLP_NORMALIZED_PREFIX) and len(view) > len(_DLP_NORMALIZED_PREFIX)
    )


def _view_allowed(view: str) -> bool:
    return view in _NORMALIZED_VIEWS or (
        view.startswith(_DLP_NORMALIZED_PREFIX) and len(view) > len(_DLP_NORMALIZED_PREFIX)
    )


def _transform_profile_allowed(profile: str) -> bool:
    if not profile.startswith(_TRANSFORM_PREFIX) or len(profile) == len(_TRANSFORM_PREFIX):
        return False
    return all("0" <= char <= "9" for char in profile[len(_TRANSFORM_PREFIX) :])


def _validate_source_span(span: Any, index: int) -> str | None:
    label = f"source_spans[{index}]"
    if not isinstance(span, dict):
        return f"{label} must be an object"
    if err := _check_fields(span, _SOURCE_SPAN_FIELDS, context=label):
        return err
    for name in _SPAN_REQUIRED_STRINGS:
        value = span.get(name)
        if not isinstance(value, str) or value == "":
            return f"{label} {name} is required"
    for name in ("bundle", "bundle_version", "redacted_sample"):
        if name in span and span[name] is not None and not isinstance(span[name], str):
            return f"{label} {name} must be a string"
    if span["source_kind"] not in _SOURCE_KINDS:
        return f"{label} source_kind {span['source_kind']!r} is not allowed"
    view = span["normalized_view"]
    if not _view_allowed(view):
        return f"{label} normalized_view {view!r} is not allowed"
    for name in ("pipelock_binary_digest", "rules_bundle_digest", "policy_hash"):
        if err := _sha256_wire(span[name], f"{label} {name}", lowercase=name == "policy_hash"):
            return err
    if not _transform_profile_allowed(span["transform_profile"]):
        return f"{label} transform_profile {span['transform_profile']!r} is not allowed"
    if span["match_hash_alg"] != "hmac-sha256":
        return f"{label} match_hash_alg {span['match_hash_alg']!r} is not allowed"
    digest = span["match_hash"][len(_HMAC_MATCH_PREFIX) :]
    if not span["match_hash"].startswith(_HMAC_MATCH_PREFIX) or _HEX64.fullmatch(digest) is None:
        return f"{label} match_hash must be hmac-sha256:<64 hex>"
    has_offset = "char_offset" in span and span["char_offset"] is not None
    has_length = "char_length" in span and span["char_length"] is not None
    if has_offset != has_length:
        missing = "char_length" if has_offset else "char_offset"
        return f"{label} {missing} is required"
    if has_offset:
        offset = span["char_offset"]
        length = span["char_length"]
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
            or offset > _INT64_MAX
        ):
            return f"{label} char_offset must be a non-negative integer"
        if (
            isinstance(length, bool)
            or not isinstance(length, int)
            or length <= 0
            or length > _INT64_MAX
        ):
            return f"{label} char_length must be a positive integer"
        if not _offsets_allowed(view):
            return f"{label} char_offset is not allowed for normalized_view {view!r}"
    return None


def _validate_shadow_aggregation_current(agg: Any) -> str | None:
    if not isinstance(agg, dict):
        return "payload aggregation must be an object"
    fields = dict(_SHADOW_DELTA_AGGREGATION_FIELDS)
    # A missing key and a JSON null both become a nil slice in Go, length 0.
    fields["exemplar_ids"] = False
    if err := _check_fields(agg, fields, context="aggregation"):
        return err
    if err := _strict_leaf_types(agg, "aggregation"):
        return err
    start = _rfc3339_rank(agg.get("window_start", ""))
    end = _rfc3339_rank(agg.get("window_end", ""))
    if start is None:
        return f"aggregation.window_start is not valid RFC 3339: {agg.get('window_start')!r}"
    if end is None:
        return f"aggregation.window_end is not valid RFC 3339: {agg.get('window_end')!r}"
    if end <= start:
        return "aggregation.window_end must be after window_start"
    if agg["lossless_count"] == 0:
        return "aggregation.lossless_count is required"
    exemplars = agg.get("exemplar_ids", [])
    if exemplars is None:
        exemplars = []
    if err := _string_list(exemplars, "aggregation.exemplar_ids"):
        return err
    if any(item == "" for item in exemplars):
        return "aggregation.exemplar_ids contains an empty id"
    if agg["delta_sample_count"] != len(exemplars):
        return "aggregation.delta_sample_count must equal the number of exemplar_ids"
    if agg["delta_sample_count"] > agg["lossless_count"]:
        return "aggregation.delta_sample_count exceeds lossless_count"
    return None


def _validate_proxy_decision_current(payload: dict[str, Any], *, spans: bool) -> str | None:
    schema = dict(_PROXY_DECISION_FIELDS)
    schema["live_verdict"] = False
    if spans:
        schema["source_spans"] = True
    if err := _check_fields(payload, schema):
        return err
    if err := _strict_leaf_types(payload):
        return err
    if err := _string_list(payload.get("policy_sources"), "payload policy_sources"):
        return err
    if not spans:
        return None
    source_spans = payload.get("source_spans")
    if not isinstance(source_spans, list) or not source_spans:
        return "payload source_spans is required"
    for index, span in enumerate(source_spans):
        if err := _validate_source_span(span, index):
            return err
    return None


def validate_current_payload(payload_kind: str, payload: Any) -> str | None:
    """Validate a current-schema payload the way Go ``EvidenceReceipt.Validate`` does.

    The older ``verify_evidence`` path keeps its own checker. This one is the
    current envelope, including ``proxy_decision_with_spans`` and the
    shadow-delta aggregation rules in ``registry.go``.
    """
    if not isinstance(payload, dict):
        return "payload must be a JSON object"
    if payload_kind == "proxy_decision":
        return _validate_proxy_decision_current(payload, spans=False)
    if payload_kind == "proxy_decision_with_spans":
        return _validate_proxy_decision_current(payload, spans=True)
    if payload_kind == "shadow_delta":
        if err := _check_fields(payload, _SHADOW_DELTA_FIELDS):
            return err
        if err := _strict_leaf_types(payload):
            return err
        return _validate_shadow_aggregation_current(payload.get("aggregation"))
    schema = _schema_for(payload_kind)
    if schema is None:
        return f"no validator for payload_kind {payload_kind!r}"
    if err := _check_fields(payload, schema):
        return err
    if err := _strict_leaf_types(payload):
        return err
    return _validate_payload(payload_kind, payload)


def _verify_current_schema_evidence(
    receipt: dict[str, Any],
    public_key_hex: str | None,
    expected_signer_key_id: str | None,
    expected_key_purpose: str | None,
) -> EvidenceVerifyResult:
    if not public_key_hex:
        return EvidenceVerifyResult(
            valid=False,
            error="public_key_hex is required to verify EvidenceReceipt v2 signatures",
        )
    from ._evidence_chain import verify_receipt

    err = verify_receipt(receipt, public_key_hex, expected_signer_key_id)
    signature = receipt.get("signature")
    purpose = signature.get("key_purpose") if isinstance(signature, dict) else None
    signer_key_id = signature.get("signer_key_id") if isinstance(signature, dict) else None
    if err is None and expected_key_purpose and purpose != expected_key_purpose:
        err = f"key_purpose {purpose!r} does not match expected {expected_key_purpose!r}"
    if err is not None:
        return EvidenceVerifyResult(valid=False, error=err)
    return EvidenceVerifyResult(
        valid=True,
        event_id=receipt.get("event_id") if isinstance(receipt.get("event_id"), str) else None,
        record_type=receipt.get("record_type")
        if isinstance(receipt.get("record_type"), str)
        else None,
        payload_kind=receipt.get("payload_kind")
        if isinstance(receipt.get("payload_kind"), str)
        else None,
        signer_key_id=signer_key_id if isinstance(signer_key_id, str) else None,
        key_purpose=purpose if isinstance(purpose, str) else None,
        chain_seq=receipt.get("chain_seq") if isinstance(receipt.get("chain_seq"), int) else None,
        chain_prev_hash=receipt.get("chain_prev_hash")
        if isinstance(receipt.get("chain_prev_hash"), str)
        else None,
        timestamp=receipt.get("timestamp") if isinstance(receipt.get("timestamp"), str) else None,
    )


def verify_evidence(
    receipt: dict[str, Any],
    public_key_hex: str | None = None,
    expected_signer_key_id: str | None = None,
    expected_key_purpose: str | None = None,
) -> EvidenceVerifyResult:
    """Verify a single EvidenceReceipt v2 envelope.

    Args:
        receipt: Pre-parsed receipt dict.
        public_key_hex: Optional trust anchor. When supplied, the signer's
            public key (resolved from the signer_key_id) must match.
            For standalone verification, pass the hex-encoded 32-byte Ed25519
            public key directly.
        expected_signer_key_id: If set, receipt's signer_key_id must match.
        expected_key_purpose: If set, receipt's key_purpose must match.
            When not set, the authority matrix is still enforced.

    Returns:
        An :class:`EvidenceVerifyResult`.
    """
    if (
        isinstance(receipt, dict)
        and receipt.get("record_type") == _RECORD_TYPE_EVIDENCE_V2
        and "canonicalization" in receipt
    ):
        return _verify_current_schema_evidence(
            receipt,
            public_key_hex,
            expected_signer_key_id,
            expected_key_purpose,
        )

    # Envelope structural checks.
    record_type = receipt.get("record_type")
    if record_type != _RECORD_TYPE_EVIDENCE_V2:
        return EvidenceVerifyResult(
            valid=False,
            error=f"unsupported record_type {record_type!r} (expected {_RECORD_TYPE_EVIDENCE_V2!r})",
        )

    version = receipt.get("receipt_version")
    if version != _RECEIPT_VERSION_V2:
        return EvidenceVerifyResult(
            valid=False,
            error=f"unsupported receipt_version {version} (expected {_RECEIPT_VERSION_V2})",
        )

    # Unknown field rejection at envelope level.
    unknown_envelope = set(receipt.keys()) - _ENVELOPE_FIELDS
    if unknown_envelope:
        return EvidenceVerifyResult(
            valid=False,
            error=f"unknown envelope fields: {sorted(unknown_envelope)}",
        )

    event_id = receipt.get("event_id", "")
    if not event_id:
        return EvidenceVerifyResult(valid=False, error="event_id is required")

    timestamp = receipt.get("timestamp", "")
    if not timestamp:
        return EvidenceVerifyResult(valid=False, error="timestamp is required")
    if not _is_valid_rfc3339(timestamp):
        return EvidenceVerifyResult(
            valid=False,
            error=f"invalid RFC 3339 timestamp: {timestamp!r}",
        )

    payload_kind = receipt.get("payload_kind", "")
    if payload_kind not in PAYLOAD_KINDS:
        return EvidenceVerifyResult(
            valid=False,
            error=f"unknown payload_kind: {payload_kind!r}",
        )

    # Signature proof structural checks.
    sig_proof = receipt.get("signature")
    if not isinstance(sig_proof, dict):
        return EvidenceVerifyResult(valid=False, error="missing or invalid signature proof")

    unknown_sig = set(sig_proof.keys()) - _SIGNATURE_FIELDS
    if unknown_sig:
        return EvidenceVerifyResult(
            valid=False,
            error=f"unknown signature fields: {sorted(unknown_sig)}",
        )

    signer_key_id = sig_proof.get("signer_key_id", "")
    if not signer_key_id:
        return EvidenceVerifyResult(valid=False, error="signature.signer_key_id is required")

    key_purpose = sig_proof.get("key_purpose", "")
    if not key_purpose:
        return EvidenceVerifyResult(valid=False, error="signature.key_purpose is required")

    # Authority matrix check.
    required_purpose = PAYLOAD_AUTHORITY.get(payload_kind)
    if required_purpose and key_purpose != required_purpose:
        return EvidenceVerifyResult(
            valid=False,
            error=(
                f"key_purpose mismatch: payload_kind={payload_kind!r} "
                f"requires {required_purpose!r}, got {key_purpose!r}"
            ),
        )

    # Caller-supplied purpose check.
    if expected_key_purpose and key_purpose != expected_key_purpose:
        return EvidenceVerifyResult(
            valid=False,
            error=f"key_purpose {key_purpose!r} does not match expected {expected_key_purpose!r}",
        )

    algorithm = sig_proof.get("algorithm", "")
    if algorithm != "ed25519":
        return EvidenceVerifyResult(
            valid=False,
            error=f"unsupported signature algorithm: {algorithm!r}",
        )

    sig_value = sig_proof.get("signature", "")
    if not isinstance(sig_value, str) or not sig_value.startswith(_SIGNATURE_PREFIX):
        return EvidenceVerifyResult(
            valid=False,
            error=f"invalid signature format: missing {_SIGNATURE_PREFIX} prefix",
        )

    sig_hex = sig_value[len(_SIGNATURE_PREFIX) :]
    # Go encoding/hex.DecodeString rejects whitespace; bytes.fromhex ignores it.
    if re.fullmatch(r"[0-9a-fA-F]*", sig_hex) is None:
        return EvidenceVerifyResult(
            valid=False, error="decoding signature: invalid hexadecimal encoding"
        )
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError as exc:
        return EvidenceVerifyResult(valid=False, error=f"decoding signature: {exc}")
    if len(sig_bytes) != _SIGNATURE_LEN:
        return EvidenceVerifyResult(
            valid=False,
            error=f"invalid signature length: got {len(sig_bytes)}, want {_SIGNATURE_LEN}",
        )

    # Caller-supplied signer_key_id check.
    if expected_signer_key_id and signer_key_id != expected_signer_key_id:
        return EvidenceVerifyResult(
            valid=False,
            error=(
                f"signer_key_id {signer_key_id!r} does not match "
                f"expected {expected_signer_key_id!r}"
            ),
        )

    # Payload validation (strict unknown-field rejection).
    payload = receipt.get("payload")
    err = _validate_payload(payload_kind, payload)
    if err:
        return EvidenceVerifyResult(valid=False, error=err)

    # Fail closed when no verification key is provided. v2 envelopes do
    # not embed a signer public key, so callers MUST supply one. Accepting
    # a structurally-valid receipt without verifying its signature would
    # let an attacker pass any envelope through verify_evidence().
    if not public_key_hex:
        return EvidenceVerifyResult(
            valid=False,
            error="public_key_hex is required to verify EvidenceReceipt v2 signatures",
        )

    if re.fullmatch(r"[0-9a-fA-F]*", public_key_hex) is None:
        return EvidenceVerifyResult(
            valid=False, error="decoding public_key: invalid hexadecimal encoding"
        )
    try:
        pub_key_bytes = bytes.fromhex(public_key_hex)
    except ValueError as exc:
        return EvidenceVerifyResult(valid=False, error=f"decoding public_key: {exc}")
    if len(pub_key_bytes) != _PUBLIC_KEY_LEN:
        return EvidenceVerifyResult(
            valid=False,
            error=f"invalid public_key length: got {len(pub_key_bytes)}, want {_PUBLIC_KEY_LEN}",
        )

    try:
        preimage = _signable_preimage(receipt)
    except (JCSError, InvalidReceiptError) as exc:
        return EvidenceVerifyResult(valid=False, error=f"computing preimage: {exc}")

    try:
        Ed25519PublicKey.from_public_bytes(pub_key_bytes).verify(sig_bytes, preimage)
    except InvalidSignature:
        return EvidenceVerifyResult(valid=False, error="signature verification failed")

    return EvidenceVerifyResult(
        valid=True,
        event_id=event_id,
        record_type=record_type,
        payload_kind=payload_kind,
        signer_key_id=signer_key_id,
        key_purpose=key_purpose,
        chain_seq=receipt.get("chain_seq"),
        chain_prev_hash=receipt.get("chain_prev_hash"),
        timestamp=timestamp,
    )


def _signable_preimage(receipt: dict[str, Any]) -> bytes:
    """Compute the JCS-canonical signable preimage for an EvidenceReceipt v2.

    Recipe: clone receipt, zero out signature, JCS-canonicalize the result.
    The signature object is replaced with a zeroed-out structure (all fields
    present but empty/default) to match Go's behavior where the zero-value
    struct is marshalled.
    """
    clone = dict(receipt)
    clone["signature"] = {
        "signer_key_id": "",
        "key_purpose": "",
        "algorithm": "",
        "signature": "",
    }
    # Re-parse through strict parser to get integer-preserving tree,
    # then canonicalize.
    raw = json.dumps(clone, separators=(",", ":"), ensure_ascii=False)
    tree = parse_json_strict(raw)
    return canonicalize(tree)


def evidence_receipt_hash(receipt: dict[str, Any]) -> str:
    """Compute the SHA-256 hex digest of the JCS-canonical full receipt.

    Used for chain linkage in v2 receipt chains.
    """
    raw = json.dumps(receipt, separators=(",", ":"), ensure_ascii=False)
    tree = parse_json_strict(raw)
    canonical = canonicalize(tree)
    return hashlib.sha256(canonical).hexdigest()


# ---- Payload validation ----


def _validate_payload(payload_kind: str, payload: Any) -> str | None:
    """Validate payload structure for a given payload_kind.

    Returns an error string on failure, None on success.
    """
    if payload is None:
        return "payload is required"
    if not isinstance(payload, dict):
        return "payload must be a JSON object"

    validator = _PAYLOAD_VALIDATORS.get(payload_kind)
    if validator is None:
        return f"no validator for payload_kind {payload_kind!r}"

    return validator(payload)


# Fields documented as integer / uint counts in the Go reference. A string
# carrying "5" must NOT pass validation because the Go side parses these as
# typed integers and the JCS preimage byte-shape differs (`5` vs `"5"`).
# Cross-implementation drift bug surface: keep this list in sync with
# internal/contract/receipt/payload.go field types in pipelock.
_INT_FIELDS: frozenset[str] = frozenset(
    {
        "current_generation",
        "target_generation",
        "lossless_count",
        "delta_sample_count",
    }
)


def _check_fields(
    payload: dict[str, Any],
    schema: dict[str, bool],
    context: str = "",
) -> str | None:
    """Check for unknown fields, required fields, and basic field types.

    schema maps field_name -> required. Unknown fields are rejected.
    Required string fields must be non-empty. Required list/dict fields
    must be non-empty. Fields named in ``_INT_FIELDS`` must arrive as
    Python ``int`` (not str), because the Go reference emits them as
    typed integers and the JCS preimage byte-shape differs.

    NOTE: the type guard is currently limited to integer-shaped count
    fields. Full per-field type schemas (string vs list-of-string vs
    nested object shape) are tracked as a v0.3 follow-up.
    """
    known = set(schema.keys())
    unknown = set(payload.keys()) - known
    if unknown:
        prefix = f"{context}: " if context else ""
        return f"{prefix}unknown payload fields: {sorted(unknown)}"

    for field, required in schema.items():
        value = payload.get(field)
        if field in _INT_FIELDS and value is not None and not isinstance(value, int):
            # Reject bool too: bool is a subclass of int in Python so
            # isinstance(True, int) is True, but bool in a count slot is
            # a typing bug. None is allowed — handled by required-check.
            if isinstance(value, bool) or not isinstance(value, int):
                return f"payload field {field!r} must be an integer, got {type(value).__name__}"
        if not required:
            continue
        if value is None:
            return f"payload missing required field: {field}"
        if isinstance(value, str) and value == "":
            return f"payload missing required field: {field}"
        if isinstance(value, (list, dict)) and len(value) == 0:
            return f"payload missing required field: {field}"

    return None


def _validate_proxy_decision(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _PROXY_DECISION_FIELDS)
    if err:
        return err
    ps = payload.get("policy_sources")
    if not isinstance(ps, list):
        return "payload policy_sources must be a list"
    return None


def _validate_contract_ratified(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _CONTRACT_RATIFIED_FIELDS)
    if err:
        return err
    rdpr = payload.get("ratification_decision_per_rule")
    if not isinstance(rdpr, dict):
        return "payload ratification_decision_per_rule must be an object"
    return None


def _validate_contract_promote_intent(payload: dict[str, Any]) -> str | None:
    return _check_fields(payload, _CONTRACT_PROMOTE_INTENT_FIELDS)


def _validate_contract_promote_committed(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _CONTRACT_PROMOTE_COMMITTED_FIELDS)
    if err:
        return err
    outcome = payload.get("validation_outcome", "")
    if outcome not in _VALID_VALIDATION_OUTCOMES:
        return f"payload validation_outcome must be 'accepted' or 'rejected', got {outcome!r}"
    if outcome == "rejected":
        reason = payload.get("reject_reason", "")
        if not reason:
            return "payload reject_reason is required when validation_outcome is 'rejected'"
    return None


def _validate_contract_rollback_authorized(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _CONTRACT_ROLLBACK_AUTHORIZED_FIELDS)
    if err:
        return err
    sigs = payload.get("authorizer_signatures")
    if not isinstance(sigs, list):
        return "payload authorizer_signatures must be a list"
    return None


def _validate_contract_rollback_committed(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _CONTRACT_ROLLBACK_COMMITTED_FIELDS)
    if err:
        return err
    outcome = payload.get("validation_outcome", "")
    if outcome not in _VALID_VALIDATION_OUTCOMES:
        return f"payload validation_outcome must be 'accepted' or 'rejected', got {outcome!r}"
    if outcome == "rejected":
        reason = payload.get("reject_reason", "")
        if not reason:
            return "payload reject_reason is required when validation_outcome is 'rejected'"
    return None


def _validate_contract_demoted(payload: dict[str, Any]) -> str | None:
    return _check_fields(payload, _CONTRACT_DEMOTED_FIELDS)


def _validate_contract_expired(payload: dict[str, Any]) -> str | None:
    return _check_fields(payload, _CONTRACT_EXPIRED_FIELDS)


def _validate_contract_drift(payload: dict[str, Any]) -> str | None:
    return _check_fields(payload, _CONTRACT_DRIFT_FIELDS)


def _validate_shadow_delta(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _SHADOW_DELTA_FIELDS)
    if err:
        return err
    agg = payload.get("aggregation")
    if not isinstance(agg, dict):
        return "payload aggregation must be an object"
    return _validate_shadow_delta_aggregation(agg)


def _validate_shadow_delta_aggregation(agg: dict[str, Any]) -> str | None:
    err = _check_fields(agg, _SHADOW_DELTA_AGGREGATION_FIELDS, context="aggregation")
    if err:
        return err
    # Validate window timestamps.
    ws = agg.get("window_start", "")
    we = agg.get("window_end", "")
    if not _is_valid_rfc3339(ws):
        return f"aggregation.window_start is not valid RFC 3339: {ws!r}"
    if not _is_valid_rfc3339(we):
        return f"aggregation.window_end is not valid RFC 3339: {we!r}"
    return None


def _validate_opportunity_missing(payload: dict[str, Any]) -> str | None:
    return _check_fields(payload, _OPPORTUNITY_MISSING_FIELDS)


def _validate_key_rotation(payload: dict[str, Any]) -> str | None:
    return _check_fields(payload, _KEY_ROTATION_FIELDS)


def _validate_contract_redaction_request(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _CONTRACT_REDACTION_REQUEST_FIELDS)
    if err:
        return err
    rk = payload.get("request_kind", "")
    if rk not in _VALID_REQUEST_KINDS:
        return (
            f"payload request_kind must be 'withdraw_public_proof' or "
            f"'local_erasure_tombstone', got {rk!r}"
        )
    return None


_PAYLOAD_VALIDATORS: dict[str, Callable[[dict[str, Any]], str | None]] = {
    "proxy_decision": _validate_proxy_decision,
    "contract_ratified": _validate_contract_ratified,
    "contract_promote_intent": _validate_contract_promote_intent,
    "contract_promote_committed": _validate_contract_promote_committed,
    "contract_rollback_authorized": _validate_contract_rollback_authorized,
    "contract_rollback_committed": _validate_contract_rollback_committed,
    "contract_demoted": _validate_contract_demoted,
    "contract_expired": _validate_contract_expired,
    "contract_drift": _validate_contract_drift,
    "shadow_delta": _validate_shadow_delta,
    "opportunity_missing": _validate_opportunity_missing,
    "key_rotation": _validate_key_rotation,
    "contract_redaction_request": _validate_contract_redaction_request,
}
