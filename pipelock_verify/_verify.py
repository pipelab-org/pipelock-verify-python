"""Core receipt and chain verification."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._canonical import (
    _ACTION_RECORD_FIELDS,
    _GROUP_BINDING_FIELDS,
    _KEY_TRANSITION_FIELDS,
    _RECEIPT_FIELDS,
    _REDACTION_FIELDS,
    _SESSION_CLOSE_FIELDS,
    _SESSION_CONTROL_FIELDS,
    _SESSION_HEARTBEAT_FIELDS,
    _SESSION_OPEN_FIELDS,
    _SHIELD_FIELDS,
    _TAINT_SOURCE_FIELDS,
    canonicalize_action_record,
    canonicalize_receipt,
    raw_json_value,
)
from ._common import InvalidReceiptError as InvalidReceiptError
from ._common import _is_valid_rfc3339 as _is_valid_rfc3339
from ._common import loads_no_duplicate_keys
from ._evidence_chain import is_current_schema, verify_evidence_chain
from ._evidence_chain import verify_receipt as _verify_current_evidence
from ._rotation import RotationEndorsement, verify_rotation_endorsement

# Wire format constants — keep in sync with internal/receipt/receipt.go.
_RECEIPT_VERSION = 1
_ACTION_RECORD_VERSION = 1
_SIGNATURE_PREFIX = "ed25519:"
_GENESIS_HASH = "genesis"

# Ed25519 sizes (RFC 8032): 32-byte public key, 64-byte signature.
_PUBLIC_KEY_LEN = 32
_SIGNATURE_LEN = 64

# Flight-recorder entry type for receipts. Matches
# internal/receipt/emitter.go recorderEntryType.
_RECORDER_ENTRY_TYPE = "action_receipt"
# Entry type that wraps a v2 EvidenceReceipt in its detail.
_EVIDENCE_ENTRY_TYPE = "evidence_receipt"
_SESSION_OPEN_GENESIS_PREFIX = "g1:"
_SESSION_OPEN_GENESIS_LABEL = "pipelock.receipt.session_open.v1"
_UINT64_MAX = 2**64 - 1
_INT64_MAX = 2**63 - 1
_JSON_DECODER = json.JSONDecoder()

# Valid action_type enum values. Matches the allActionTypes map in
# internal/receipt/action.go. A verifier that does not enforce this set
# will accept Go-rejected receipts (e.g. action_type: "bogus"), which
# breaks cross-implementation agreement. Order mirrors the Go source.
_VALID_ACTION_TYPES = frozenset(
    {
        "read",
        "derive",
        "write",
        "delegate",
        "authorize",
        "spend",
        "commit",
        "actuate",
        "unclassified",
    }
)

_V1_RECEIPT_FIELDS = frozenset(name for name, _, _ in _RECEIPT_FIELDS) | {"ext"}
_ACTION_RECORD_FIELD_NAMES = frozenset(name for name, _, _ in _ACTION_RECORD_FIELDS)
_REDACTION_FIELD_NAMES = frozenset(name for name, _, _ in _REDACTION_FIELDS)
_SHIELD_FIELD_NAMES = frozenset(name for name, _, _ in _SHIELD_FIELDS)
_TAINT_SOURCE_FIELD_NAMES = frozenset(name for name, _, _ in _TAINT_SOURCE_FIELDS)
_KEY_TRANSITION_FIELD_NAMES = frozenset(name for name, _, _ in _KEY_TRANSITION_FIELDS)
_SESSION_CONTROL_FIELD_NAMES = frozenset(name for name, _, _ in _SESSION_CONTROL_FIELDS)
_SESSION_OPEN_FIELD_NAMES = frozenset(name for name, _, _ in _SESSION_OPEN_FIELDS)
_GROUP_BINDING_FIELD_NAMES = frozenset(name for name, _, _ in _GROUP_BINDING_FIELDS)
_SESSION_HEARTBEAT_FIELD_NAMES = frozenset(name for name, _, _ in _SESSION_HEARTBEAT_FIELDS)
_SESSION_CLOSE_FIELD_NAMES = frozenset(name for name, _, _ in _SESSION_CLOSE_FIELDS)


@dataclass
class VerifyResult:
    """Outcome of verifying a single receipt.

    ``valid`` is the only field guaranteed to be set. Descriptive fields
    are populated on success (and may be populated on some failures) for
    diagnostic output. ``error`` holds a short reason string on failure.
    """

    valid: bool
    error: str | None = None
    action_id: str | None = None
    action_type: str | None = None
    verdict: str | None = None
    target: str | None = None
    transport: str | None = None
    signer_key: str | None = None
    chain_seq: int | None = None
    chain_prev_hash: str | None = None
    timestamp: str | None = None


@dataclass
class ChainResult:
    """Outcome of verifying a receipt chain.

    Mirrors ``receipt.ChainResult`` in the Go implementation: on break,
    ``broken_at_seq`` identifies where the chain failed, and ``error``
    describes why. On success, ``root_hash`` is the hash of the final
    receipt, suitable for publishing as a transcript root.
    """

    valid: bool
    error: str | None = None
    broken_at_seq: int | None = None
    receipt_count: int = 0
    final_seq: int | None = None
    root_hash: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    # Wrapped v2 EvidenceReceipt entries, verified as their own chain.
    evidence_count: int = 0
    evidence_root_hash: str | None = None
    evidence_signer_key_id: str | None = None
    evidence_key_pinned: bool = False


def verify(
    source: str | bytes | dict[str, Any],
    public_key_hex: str | None = None,
    *,
    expected_signer_key_id: str | None = None,
) -> VerifyResult:
    """Verify a single action receipt.

    Args:
        source: Receipt as a JSON string, UTF-8 bytes, or a pre-parsed dict.
        public_key_hex: Optional trust anchor. When supplied, the receipt's
            ``signer_key`` field must match this value (hex-encoded 32-byte
            Ed25519 public key). When omitted, the embedded ``signer_key``
            is trusted. Required for v2 evidence receipts.
        expected_signer_key_id: v2 evidence receipts only. When given, the
            receipt's ``signature.signer_key_id`` must equal it. Supplying it
            for a v1 receipt is an error, because v1 receipts carry no key ID.

    Returns:
        A :class:`VerifyResult`. ``result.valid`` is ``True`` only when the
        signature verifies and every structural check passes.
    """
    try:
        parsed = _parse_receipt(source)
    except json.JSONDecodeError as exc:
        return VerifyResult(valid=False, error=f"parsing receipt: {exc}")
    except InvalidReceiptError as exc:
        return VerifyResult(valid=False, error=str(exc))

    # Transparently unwrap a flight-recorder entry wrapper if present so
    # callers can feed either bare receipt JSON or an entry dump.
    try:
        receipt = _extract_evidence(parsed)
        if receipt is None:
            receipt = _extract_receipt(parsed)
    except (InvalidReceiptError, json.JSONDecodeError) as exc:
        return VerifyResult(valid=False, error=str(exc))
    if receipt is None:
        return VerifyResult(
            valid=False, error="flight-recorder entry does not carry an action receipt"
        )

    # Version routing: dispatch on record_type field.
    record_type = receipt.get("record_type")
    if record_type == "evidence_receipt_v2" and is_current_schema(receipt):
        if not public_key_hex:
            return VerifyResult(
                valid=False,
                error="a public key is required to verify EvidenceReceipt v2 signatures",
            )
        err = _verify_current_evidence(receipt, public_key_hex, expected_signer_key_id)
        signature = receipt.get("signature")
        return VerifyResult(
            valid=err is None,
            error=err,
            action_id=receipt.get("event_id") if err is None else None,
            action_type=receipt.get("payload_kind") if err is None else None,
            signer_key=signature.get("signer_key_id") if isinstance(signature, dict) else None,
            chain_seq=receipt.get("chain_seq") if err is None else None,
            chain_prev_hash=receipt.get("chain_prev_hash") if err is None else None,
            timestamp=receipt.get("timestamp") if err is None else None,
        )
    if record_type == "evidence_receipt_v2":
        from ._evidence import verify_evidence as _verify_v2

        v2_result = _verify_v2(
            receipt,
            public_key_hex=public_key_hex,
            expected_signer_key_id=expected_signer_key_id,
        )
        # Wrap EvidenceVerifyResult into a VerifyResult for backward compat.
        return VerifyResult(
            valid=v2_result.valid,
            error=v2_result.error,
            action_id=v2_result.event_id,
            action_type=v2_result.payload_kind,
            verdict=None,
            target=None,
            transport=None,
            signer_key=v2_result.signer_key_id,
            chain_seq=v2_result.chain_seq,
            chain_prev_hash=v2_result.chain_prev_hash,
            timestamp=v2_result.timestamp,
        )
    if record_type is not None and record_type not in ("action_receipt_v1", None):
        return VerifyResult(
            valid=False,
            error=f"unknown record_type: {record_type!r}",
        )
    if expected_signer_key_id is not None:
        return VerifyResult(
            valid=False,
            error=(
                "expected signer key ID applies to v2 evidence receipts only; "
                "pin a v1 receipt signer with the public key"
            ),
        )

    return _verify_receipt_dict(receipt, public_key_hex)


def verify_chain(
    jsonl_path: str | Path,
    public_key_hex: str | None = None,
    *,
    session_id: str = "proxy",
    rotation_endorsements: Sequence[RotationEndorsement | dict[str, Any] | str | bytes] = (),
    expected_signer_key_id: str | None = None,
) -> ChainResult:
    """Verify a receipt chain from a flight recorder JSONL file.

    Args:
        jsonl_path: Path to a JSONL file with one receipt per line. Empty
            lines are ignored.
        public_key_hex: Optional trust anchor. When omitted, the
            ``signer_key`` of the first receipt is taken as the expected
            key and every subsequent receipt must share it. This matches
            the Go ``VerifyChain`` signer-consistency check.
        session_id: Signed recorder session expected by each endorsement.
        rotation_endorsements: Old-key-signed successor authorizations for
            the chain's rotation boundaries. Supplying endorsements requires ``public_key_hex``;
            the pinned key remains the root of trust.
        expected_signer_key_id: When given, every wrapped v2 evidence
            receipt's ``signature.signer_key_id`` must equal it. It is an
            error to supply it for a file with no evidence receipts.

    Wrapped v2 evidence receipts (recorder entries of type
    ``evidence_receipt``) are verified as a separate chain: signature,
    ``chain_seq``, ``chain_prev_hash`` and signer consistency. With
    ``public_key_hex`` their ``signer_key_id`` must be that key; without it
    the first evidence receipt's ``signer_key_id`` is used as the key.

    Returns:
        A :class:`ChainResult`. On failure, ``broken_at_seq`` and ``error``
        locate the first receipt that failed.
    """
    try:
        receipts, evidence = _read_jsonl_entries(Path(jsonl_path))
    except FileNotFoundError as exc:
        return ChainResult(valid=False, error=f"reading file: {exc}")
    except json.JSONDecodeError as exc:
        return ChainResult(valid=False, error=f"parsing JSONL: {exc}")
    except InvalidReceiptError as exc:
        # _read_jsonl_entries raises this when a line parses as JSON but doesn't
        # look like a receipt or a flight-recorder entry. Surface it as a
        # normal failure result instead of propagating a raw exception.
        return ChainResult(valid=False, error=f"parsing JSONL: {exc}")

    try:
        verified_endorsements = [
            verify_rotation_endorsement(endorsement) for endorsement in rotation_endorsements
        ]
    except (InvalidReceiptError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return ChainResult(valid=False, error=str(exc))

    if expected_signer_key_id is not None and not evidence:
        return ChainResult(
            valid=False,
            error="expected signer key ID given but the file has no evidence receipts",
        )

    result = _verify_chain_list(
        receipts,
        public_key_hex,
        session_id=session_id,
        rotation_endorsements=verified_endorsements,
    )
    if not result.valid or not evidence:
        return result

    evidence_result = verify_evidence_chain(evidence, public_key_hex, expected_signer_key_id)
    if not evidence_result.valid:
        return ChainResult(
            valid=False,
            error=evidence_result.error,
            broken_at_seq=evidence_result.broken_at_seq,
            receipt_count=result.receipt_count,
            evidence_count=evidence_result.count,
        )
    result.evidence_count = evidence_result.count
    result.evidence_root_hash = evidence_result.root_hash
    result.evidence_signer_key_id = evidence_result.signer_key_id
    result.evidence_key_pinned = evidence_result.key_pinned
    return result


# ---- internals ----


def _parse_receipt(source: str | bytes | dict[str, Any]) -> dict[str, Any]:
    if isinstance(source, dict):
        return source
    if isinstance(source, bytes):
        source = source.decode("utf-8")
    if not isinstance(source, str):
        raise InvalidReceiptError(
            f"unsupported source type {type(source).__name__}; expected str, bytes, or dict"
        )
    parsed = loads_no_duplicate_keys(source)
    if not isinstance(parsed, dict):
        raise InvalidReceiptError("receipt must be a JSON object")
    _attach_raw_ext(parsed, source)
    return parsed


def _find_top_level_raw_member(text: str, member: str) -> str | None:
    """Return the raw JSON value for a top-level object member, if present."""

    length = len(text)
    index = 0
    while index < length and text[index] in " \t\r\n":
        index += 1
    if index >= length or text[index] != "{":
        return None
    index += 1

    while True:
        while index < length and text[index] in " \t\r\n":
            index += 1
        if index >= length or text[index] == "}":
            return None
        key, index = _JSON_DECODER.raw_decode(text, index)
        if not isinstance(key, str):
            return None
        while index < length and text[index] in " \t\r\n":
            index += 1
        if index >= length or text[index] != ":":
            return None
        index += 1
        while index < length and text[index] in " \t\r\n":
            index += 1
        value_start = index
        _value, index = _JSON_DECODER.raw_decode(text, index)
        if key == member:
            return text[value_start:index]
        while index < length and text[index] in " \t\r\n":
            index += 1
        if index < length and text[index] == ",":
            index += 1
            continue
        return None


def _attach_receipt_raw_ext(receipt: dict[str, Any], receipt_text: str) -> None:
    raw_ext = _find_top_level_raw_member(receipt_text, "ext")
    if raw_ext is not None:
        receipt["ext"] = raw_json_value(raw_ext)


def _attach_raw_ext(parsed: dict[str, Any], source_text: str) -> None:
    """Preserve Go json.RawMessage bytes for receipt ext when source JSON exists.

    Go emits ``Receipt.Ext`` verbatim (compacted) into the bytes ``ReceiptHash``
    digests, so the chain hash commits to the producer's exact ext bytes: key
    order, number spelling such as ``1e+06``, and escaping all survive. Parsing
    ext and re-serializing it would silently change those bytes and diverge from
    Go on receipts that carry ext, so the raw source slice is kept whenever the
    caller gave us the original JSON text.

    A caller that passes an ALREADY-PARSED receipt (the ``dict`` entry points,
    rather than a path or a JSON string) has no source bytes left to preserve,
    so ext is re-serialized from the parsed value and the chain hash can differ
    from Go for exotic-but-equivalent spellings. That direction is fail-closed:
    such a chain is reported broken rather than accepted, and an attacker gains
    nothing, because altering ext's parsed VALUE changes this verifier's hash
    too. Verify from a path or the raw JSON text when ext byte fidelity matters.
    """

    if "action_record" in parsed and "signature" in parsed:
        _attach_receipt_raw_ext(parsed, source_text)
        return

    if not ("type" in parsed and "detail" in parsed and isinstance(parsed.get("detail"), dict)):
        return
    raw_detail = _find_top_level_raw_member(source_text, "detail")
    if raw_detail is not None:
        _attach_receipt_raw_ext(parsed["detail"], raw_detail)


def _extract_evidence(parsed: dict[str, Any]) -> dict[str, Any] | None:
    """Return the detail of an ``evidence_receipt`` recorder entry, else None."""
    if parsed.get("type") != _EVIDENCE_ENTRY_TYPE:
        return None
    detail = parsed.get("detail")
    if isinstance(detail, (str, bytes)):
        detail = loads_no_duplicate_keys(detail)
    # Go decodeEvidenceReceiptDetail rejects absent/null detail; its typed
    # decoder also rejects arrays and scalars instead of skipping the entry.
    if not isinstance(detail, dict):
        raise InvalidReceiptError("evidence detail must be a JSON object")
    if detail.get("record_type") != "evidence_receipt_v2":
        raise InvalidReceiptError("evidence detail must carry an EvidenceReceipt v2")
    return detail


def _extract_receipt(parsed: dict[str, Any]) -> dict[str, Any] | None:
    """Pull a receipt dict out of a parsed JSONL line.

    Accepts two formats:

    1. **Bare receipt** — the top-level object already has ``action_record``
       and ``signature``. Returned as-is.
    2. **Flight-recorder entry** — a wrapper with ``type == "action_receipt"``
       and the receipt sitting in ``detail`` (either as an object or as a
       JSON-encoded string, since Go emits it via ``json.RawMessage``).

    Returns ``None`` for flight-recorder entries whose type is not a
    receipt (checkpoints, other event types) so the reader can skip them.
    Wrapped evidence receipts are taken out earlier by ``_extract_evidence``.
    """
    # Flight-recorder entry.
    if "type" in parsed and "detail" in parsed:
        if parsed.get("type") != _RECORDER_ENTRY_TYPE:
            return None
        detail = parsed["detail"]
        if isinstance(detail, dict):
            return detail
        if isinstance(detail, (str, bytes)):
            decoded = loads_no_duplicate_keys(detail)
            if not isinstance(decoded, dict):
                raise InvalidReceiptError("flight-recorder detail JSON did not decode to an object")
            raw_detail = detail.decode("utf-8") if isinstance(detail, bytes) else detail
            _attach_receipt_raw_ext(decoded, raw_detail)
            return decoded
        raise InvalidReceiptError(
            f"flight-recorder detail has unexpected type {type(detail).__name__}"
        )

    # Bare v1 receipt (ActionReceipt).
    if "action_record" in parsed and "signature" in parsed:
        return parsed

    # Bare v2 receipt (EvidenceReceipt): identified by record_type field.
    if "record_type" in parsed and "payload" in parsed:
        return parsed

    raise InvalidReceiptError("unrecognized JSONL line: not a receipt or flight-recorder entry")


def _read_jsonl_entries(path: Path) -> tuple[list[dict[str, Any]], list[Any]]:
    """Split a JSONL file into v1 receipts and wrapped v2 evidence receipts."""
    text = path.read_text(encoding="utf-8")
    receipts: list[dict[str, Any]] = []
    evidence: list[Any] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            parsed = loads_no_duplicate_keys(line)
        except json.JSONDecodeError as exc:
            raise json.JSONDecodeError(f"line {lineno}: {exc.msg}", exc.doc, exc.pos) from exc
        if not isinstance(parsed, dict):
            raise json.JSONDecodeError(f"line {lineno}: JSONL entry must be a JSON object", line, 0)
        try:
            detail = _extract_evidence(parsed)
        except json.JSONDecodeError as exc:
            raise InvalidReceiptError(f"line {lineno}: evidence detail: {exc}") from exc
        if detail is not None:
            evidence.append(detail)
            continue
        _attach_raw_ext(parsed, line)
        receipt = _extract_receipt(parsed)
        if receipt is None:
            # Non-receipt recorder entry (checkpoint, other event). Skip
            # instead of failing the whole chain — matches Go ExtractReceipts.
            continue
        receipts.append(receipt)
    return receipts, evidence


def _reject_unknown_fields(
    obj: dict[str, Any],
    allowed: frozenset[str],
    where: str,
) -> str | None:
    unknown = sorted(set(obj) - allowed)
    if unknown:
        return f"{where} carries unknown signed field(s): {unknown}"
    return None


def _require_string(obj: dict[str, Any], name: str, where: str) -> str | None:
    if name in obj and not isinstance(obj[name], str):
        return f"{where} {name} must be a string"
    return None


def _require_uint64(obj: dict[str, Any], name: str, where: str) -> str | None:
    if name not in obj:
        return None
    value = obj[name]
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > _UINT64_MAX:
        return f"{where} {name} must be a uint64"
    return None


def _require_bool(obj: dict[str, Any], name: str, where: str) -> str | None:
    if name in obj and not isinstance(obj[name], bool):
        return f"{where} {name} must be a boolean"
    return None


def _require_int64(obj: dict[str, Any], name: str, where: str) -> str | None:
    if name not in obj:
        return None
    value = obj[name]
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < -_INT64_MAX - 1
        or value > _INT64_MAX
    ):
        return f"{where} {name} must be an integer"
    return None


def _validate_redaction_shape(action_record: dict[str, Any]) -> str | None:
    if "redaction" not in action_record or action_record.get("redaction") is None:
        return None
    redaction = action_record["redaction"]
    if not isinstance(redaction, dict):
        return "redaction must be an object"
    if err := _reject_unknown_fields(redaction, _REDACTION_FIELD_NAMES, "redaction"):
        return err
    for name in ("profile", "provider", "parser"):
        if err := _require_string(redaction, name, "redaction"):
            return err
    if err := _require_int64(redaction, "total_redactions", "redaction"):
        return err
    if "by_class" in redaction and redaction["by_class"] is not None:
        by_class = redaction["by_class"]
        if not isinstance(by_class, dict):
            return "redaction by_class must be an object"
        for key, value in by_class.items():
            if not isinstance(key, str):
                return "redaction by_class keys must be strings"
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < -_INT64_MAX - 1
                or value > _INT64_MAX
            ):
                return "redaction by_class values must be int64"
    return _require_bool(redaction, "cache_boundary_kept", "redaction")


def _validate_shield_shape(action_record: dict[str, Any]) -> str | None:
    if "shield" not in action_record or action_record.get("shield") is None:
        return None
    shield = action_record["shield"]
    if not isinstance(shield, dict):
        return "shield must be an object"
    if err := _reject_unknown_fields(shield, _SHIELD_FIELD_NAMES, "shield"):
        return err
    if err := _require_string(shield, "pipeline", "shield"):
        return err
    for name in (
        "total_rewrites",
        "extension_probes",
        "tracking_beacons",
        "agent_traps",
        "svg_foreign_objects",
        "svg_event_handlers",
        "svg_external_references",
        "svg_hidden_text",
        "svg_animation_injections",
        "body_bytes",
        "scanned_bytes",
        "adaptive_signals_recorded",
        "adaptive_signal_max_per_body",
    ):
        if err := _require_int64(shield, name, "shield"):
            return err
    for name in ("fingerprint_shim_injected", "partial"):
        if err := _require_bool(shield, name, "shield"):
            return err
    return None


def _validate_taint_sources_shape(action_record: dict[str, Any]) -> str | None:
    if (
        "recent_taint_sources" not in action_record
        or action_record.get("recent_taint_sources") is None
    ):
        return None
    sources = action_record["recent_taint_sources"]
    if not isinstance(sources, list):
        return "recent_taint_sources must be a list"
    for index, source in enumerate(sources):
        where = f"recent_taint_sources[{index}]"
        if not isinstance(source, dict):
            return f"{where} must be an object"
        if err := _reject_unknown_fields(source, _TAINT_SOURCE_FIELD_NAMES, where):
            return err
        for name in ("url", "kind", "timestamp", "receipt_id", "match_reason"):
            if err := _require_string(source, name, where):
                return err
        if "level" in source:
            level = source["level"]
            if not isinstance(level, int) or isinstance(level, bool) or level < 0 or level > 255:
                return f"{where} level must be a uint8"
    return None


def _validate_key_transition_shape(action_record: dict[str, Any]) -> str | None:
    if "key_transition" not in action_record or action_record.get("key_transition") is None:
        return None
    marker = action_record["key_transition"]
    if not isinstance(marker, dict):
        return "key_transition must be an object"
    if err := _reject_unknown_fields(marker, _KEY_TRANSITION_FIELD_NAMES, "key_transition"):
        return err
    for name in ("prior_signer_key", "prior_chain_hash"):
        if err := _require_string(marker, name, "key_transition"):
            return err
    return _require_uint64(marker, "prior_chain_seq", "key_transition")


def _validate_session_payload_shape(
    payload: Any,
    allowed_fields: frozenset[str],
    string_fields: tuple[str, ...],
    uint64_fields: tuple[str, ...],
    where: str,
    *,
    int64_fields: tuple[str, ...] = (),
) -> str | None:
    if not isinstance(payload, dict):
        return f"{where} must be an object"
    if err := _reject_unknown_fields(payload, allowed_fields, where):
        return err
    for name in string_fields:
        if err := _require_string(payload, name, where):
            return err
    for name in uint64_fields:
        if err := _require_uint64(payload, name, where):
            return err
    for name in int64_fields:
        if err := _require_int64(payload, name, where):
            return err
    return None


def _validate_group_binding_shape(open_payload: dict[str, Any]) -> str | None:
    # Go decodes a null or absent group_binding into a nil pointer: an
    # ungrouped (legacy single-chain) session. A present binding is signed
    # whole; group membership and completeness are not checked per chain.
    binding = open_payload.get("group_binding")
    if binding is None:
        return None
    if isinstance(binding, dict):
        # A null typed field decodes to its Go zero value; see _canonical.
        binding = {
            k: v for k, v in binding.items() if v is not None or k not in _GROUP_BINDING_FIELD_NAMES
        }
    return _validate_session_payload_shape(
        binding,
        _GROUP_BINDING_FIELD_NAMES,
        (
            "group_id",
            "session_id",
            "open_manifest_sha256",
            "signer_key",
            "previous_group_id",
            "previous_open_manifest_sha256",
        ),
        (),
        "session_open group_binding",
        int64_fields=("shard_index",),
    )


def _validate_session_control_shape(action_record: dict[str, Any]) -> str | None:
    if "session_control" not in action_record or action_record.get("session_control") is None:
        return None
    ctrl = action_record["session_control"]
    if not isinstance(ctrl, dict):
        return "session_control must be an object"
    if err := _reject_unknown_fields(ctrl, _SESSION_CONTROL_FIELD_NAMES, "session_control"):
        return err

    kind = ctrl.get("kind")
    if not isinstance(kind, str):
        return "session_control kind must be a string"

    payload_names = ("open", "heartbeat", "close")
    present_payloads = [name for name in payload_names if ctrl.get(name) is not None]
    if len(present_payloads) != 1:
        return "session_control must carry exactly one payload"

    if kind == "session_open":
        if present_payloads != ["open"]:
            return "session_open kind missing open payload"
        if err := _validate_session_payload_shape(
            ctrl["open"],
            _SESSION_OPEN_FIELD_NAMES,
            (
                "run_nonce",
                "open_nonce",
                "recorder_session",
                "policy_hash",
                "signer_key_epoch",
                "prior_chain_head",
                "genesis_hash",
                "genesis_anchor_head",
                "genesis_anchor_log",
                "posture_capsule_sha256",
                "posture_signer_key_id",
                "containment_nonce",
                "contained_uid",
            ),
            ("chain_open_seq", "prior_chain_seq"),
            "session_open",
            int64_fields=("heartbeat_seconds",),
        ):
            return err
        return _validate_group_binding_shape(ctrl["open"])
    if kind == "heartbeat":
        if present_payloads != ["heartbeat"]:
            return "heartbeat kind missing heartbeat payload"
        return _validate_session_payload_shape(
            ctrl["heartbeat"],
            _SESSION_HEARTBEAT_FIELD_NAMES,
            ("run_nonce", "open_nonce", "chain_head", "heartbeat_time"),
            ("beat", "chain_seq_head", "fsync_errors_gated", "durability_blocks"),
            "session_heartbeat",
        )
    if kind == "session_close":
        if present_payloads != ["close"]:
            return "session_close kind missing close payload"
        return _validate_session_payload_shape(
            ctrl["close"],
            _SESSION_CLOSE_FIELD_NAMES,
            ("run_nonce", "open_nonce", "root_hash", "close_reason"),
            ("final_seq", "receipt_count", "fsync_errors_gated", "durability_blocks"),
            "session_close",
        )
    return "unknown session_control kind"


def _validate_v1_receipt_shape(
    receipt: dict[str, Any], action_record: dict[str, Any]
) -> str | None:
    if err := _reject_unknown_fields(receipt, _V1_RECEIPT_FIELDS, "receipt"):
        return err
    if err := _reject_unknown_fields(action_record, _ACTION_RECORD_FIELD_NAMES, "action_record"):
        return err
    if err := _require_string(action_record, "chain_prev_hash", "action_record"):
        return err
    if err := _require_uint64(action_record, "chain_seq", "action_record"):
        return err
    if err := _require_string(action_record, "run_nonce", "action_record"):
        return err
    if err := _validate_redaction_shape(action_record):
        return err
    if err := _validate_shield_shape(action_record):
        return err
    if err := _validate_taint_sources_shape(action_record):
        return err
    if err := _validate_key_transition_shape(action_record):
        return err
    return _validate_session_control_shape(action_record)


def _verify_receipt_dict(
    receipt: dict[str, Any],
    expected_key_hex: str | None,
) -> VerifyResult:
    version = receipt.get("version")
    if version != _RECEIPT_VERSION:
        return VerifyResult(
            valid=False,
            error=(f"unsupported receipt version {version} (expected {_RECEIPT_VERSION})"),
        )

    action_record = receipt.get("action_record")
    if not isinstance(action_record, dict):
        return VerifyResult(valid=False, error="missing or invalid action_record")

    if shape_error := _validate_v1_receipt_shape(receipt, action_record):
        return VerifyResult(valid=False, error=f"unmarshal receipt: {shape_error}")

    ar_version = action_record.get("version")
    if ar_version != _ACTION_RECORD_VERSION:
        return VerifyResult(
            valid=False,
            error=(
                f"unsupported action_record version {ar_version} "
                f"(expected {_ACTION_RECORD_VERSION})"
            ),
        )

    # Match internal/receipt/action.go Validate() exactly. Go's error order
    # and messages are part of the cross-implementation contract:
    #
    #   1. action_id presence          -> "action_id is required"
    #   2. action_type enum membership -> 'invalid action_type "<value>"'
    #      (rejects both empty "" and any non-enum value with the same
    #      wording; the required-field sweep does NOT cover action_type)
    #   3. timestamp presence          -> "timestamp is required"
    #   4. target presence             -> "target is required"
    #   5. verdict presence            -> "verdict is required"
    #   6. transport presence          -> "transport is required"
    #
    # Timestamp validity is enforced BEFORE the signature check because Go
    # parses the receipt into a typed struct first; a malformed timestamp
    # there fails json.Unmarshal and never reaches signature verification.
    # Python parses into a dict, so we have to replay the same check
    # manually or an attacker can ship "timestamp": "not-a-time" with a
    # valid signature over the canonical garbage and Python will accept it.
    if not action_record.get("action_id"):
        return VerifyResult(valid=False, error="invalid action record: action_id is required")

    action_type = action_record.get("action_type", "")
    if action_type not in _VALID_ACTION_TYPES:
        return VerifyResult(
            valid=False,
            error=f'invalid action record: invalid action_type "{action_type}"',
        )

    timestamp = action_record.get("timestamp")
    if not timestamp:
        return VerifyResult(valid=False, error="invalid action record: timestamp is required")
    if not _is_valid_rfc3339(timestamp):
        # Go surfaces this as a json.Unmarshal error; Python surfaces it as
        # its own diagnostic so the fix point is obvious. The net effect —
        # "signed receipt with a bogus timestamp is rejected" — matches.
        return VerifyResult(
            valid=False,
            error=(f'unmarshal receipt: invalid RFC 3339 timestamp "{timestamp}"'),
        )

    for required in ("target", "verdict", "transport"):
        if not action_record.get(required):
            return VerifyResult(
                valid=False,
                error=f"invalid action record: {required} is required",
            )

    signature_str = receipt.get("signature", "")
    if not signature_str:
        return VerifyResult(valid=False, error="receipt has no signature")
    if not isinstance(signature_str, str) or not signature_str.startswith(_SIGNATURE_PREFIX):
        return VerifyResult(
            valid=False,
            error=f"invalid signature format: missing {_SIGNATURE_PREFIX} prefix",
        )

    signer_key_hex = receipt.get("signer_key", "")
    if not signer_key_hex:
        return VerifyResult(valid=False, error="receipt has no signer_key")

    if expected_key_hex and signer_key_hex != expected_key_hex:
        return VerifyResult(
            valid=False,
            error=(f"signer_key {signer_key_hex} does not match expected key {expected_key_hex}"),
        )

    sig_hex = signature_str[len(_SIGNATURE_PREFIX) :]
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError as exc:
        return VerifyResult(valid=False, error=f"decoding signature: {exc}")
    if len(sig_bytes) != _SIGNATURE_LEN:
        return VerifyResult(
            valid=False,
            error=(f"invalid signature length: got {len(sig_bytes)}, want {_SIGNATURE_LEN}"),
        )

    try:
        pub_key_bytes = bytes.fromhex(signer_key_hex)
    except ValueError as exc:
        return VerifyResult(valid=False, error=f"decoding signer_key: {exc}")
    if len(pub_key_bytes) != _PUBLIC_KEY_LEN:
        return VerifyResult(
            valid=False,
            error=(f"invalid signer_key length: got {len(pub_key_bytes)}, want {_PUBLIC_KEY_LEN}"),
        )

    canonical = canonicalize_action_record(action_record)
    signing_hash = hashlib.sha256(canonical).digest()

    try:
        Ed25519PublicKey.from_public_bytes(pub_key_bytes).verify(sig_bytes, signing_hash)
    except InvalidSignature:
        return VerifyResult(valid=False, error="signature verification failed")

    return VerifyResult(
        valid=True,
        action_id=action_record.get("action_id"),
        action_type=action_record.get("action_type"),
        verdict=action_record.get("verdict"),
        target=action_record.get("target"),
        transport=action_record.get("transport"),
        signer_key=signer_key_hex,
        chain_seq=action_record.get("chain_seq"),
        chain_prev_hash=action_record.get("chain_prev_hash"),
        timestamp=action_record.get("timestamp"),
    )


def _compute_receipt_hash(receipt: dict[str, Any]) -> str:
    """Chain linkage hash: SHA-256 hex of canonical receipt envelope.

    Matches ``receipt.ReceiptHash`` in ``internal/receipt/chain.go``.
    """
    canonical = canonicalize_receipt(receipt)
    return hashlib.sha256(canonical).hexdigest()


def _compute_session_open_genesis(open_payload: dict[str, Any]) -> str:
    """Return Go's bound session-open genesis hash for a SessionOpen payload."""

    h = hashlib.sha256()

    def frame(data: bytes) -> None:
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)

    def string_field(name: str) -> bytes:
        value = open_payload.get(name, "")
        if not isinstance(value, str):
            raise InvalidReceiptError(f"session_open {name} must be a string")
        return value.encode("utf-8")

    frame(_SESSION_OPEN_GENESIS_LABEL.encode("utf-8"))
    frame(string_field("run_nonce"))
    frame(string_field("open_nonce"))
    frame(string_field("recorder_session"))
    frame(string_field("policy_hash"))
    frame(string_field("signer_key_epoch"))

    heartbeat_seconds = open_payload.get("heartbeat_seconds", 0)
    if not isinstance(heartbeat_seconds, int) or isinstance(heartbeat_seconds, bool):
        raise InvalidReceiptError("session_open heartbeat_seconds must be an integer")
    if heartbeat_seconds > _INT64_MAX:
        raise InvalidReceiptError("session_open heartbeat_seconds must be an integer")
    if heartbeat_seconds < 0:
        heartbeat_seconds = 0
    frame(heartbeat_seconds.to_bytes(8, "big"))

    frame(string_field("genesis_anchor_head"))
    frame(string_field("genesis_anchor_log"))
    frame(string_field("posture_capsule_sha256"))
    frame(string_field("containment_nonce"))
    frame(string_field("contained_uid"))

    return _SESSION_OPEN_GENESIS_PREFIX + h.hexdigest()


def _session_control_open(action_record: dict[str, Any]) -> dict[str, Any] | None:
    return _session_control_payload(action_record, "session_open", "open")


def _session_control_heartbeat(action_record: dict[str, Any]) -> dict[str, Any] | None:
    return _session_control_payload(action_record, "heartbeat", "heartbeat")


def _session_control_close(action_record: dict[str, Any]) -> dict[str, Any] | None:
    return _session_control_payload(action_record, "session_close", "close")


def _session_control_payload(
    action_record: dict[str, Any],
    kind: str,
    payload_name: str,
) -> dict[str, Any] | None:
    ctrl = action_record.get("session_control")
    if not isinstance(ctrl, dict) or ctrl.get("kind") != kind:
        return None
    payload = ctrl.get(payload_name)
    if isinstance(payload, dict):
        return payload
    return None


def _validate_first_prev_hash(action_record: dict[str, Any], actual_prev: str) -> str | None:
    if not actual_prev.startswith(_SESSION_OPEN_GENESIS_PREFIX):
        if actual_prev == _GENESIS_HASH and _session_control_open(action_record) is not None:
            return "session_open on legacy genesis must use bound g1 chain_prev_hash"
        if actual_prev == _GENESIS_HASH and action_record.get("run_nonce"):
            return "run_nonce first receipt is not a matching session_open"
        return None

    open_payload = _session_control_open(action_record)
    if open_payload is None:
        return "g1 chain_prev_hash requires SessionControl.Open"

    seq = action_record.get("chain_seq")
    if seq != 0:
        return "bound session_open genesis must be chain_seq 0"

    try:
        computed = _compute_session_open_genesis(open_payload)
    except InvalidReceiptError as exc:
        return str(exc)

    if actual_prev != computed:
        return "session_open genesis hash mismatch"
    if open_payload.get("genesis_hash") != computed:
        return "session_open genesis_hash mismatch"
    if open_payload.get("chain_open_seq") != seq:
        return "session_open chain_open_seq does not match receipt chain_seq"
    if open_payload.get("prior_chain_head", "") or open_payload.get("prior_chain_seq", 0) != 0:
        return "bound genesis session_open must not carry prior chain tail"

    return None


def _validate_restart_open(
    action_record: dict[str, Any],
    open_payload: dict[str, Any],
    prior_head: str,
    prior_seq: int,
) -> str | None:
    actual_prev = action_record.get("chain_prev_hash", "")
    if actual_prev.startswith(_SESSION_OPEN_GENESIS_PREFIX):
        return "restart session_open must not use g1 chain_prev_hash"
    if open_payload.get("genesis_hash", ""):
        return "restart session_open must not carry genesis_hash"
    if open_payload.get("chain_open_seq", 0) != action_record.get("chain_seq"):
        return "session_open chain_open_seq does not match receipt chain_seq"
    if open_payload.get("prior_chain_head", "") != prior_head:
        return "session_open prior_chain_head does not match prior tail hash"
    if open_payload.get("prior_chain_seq", 0) != prior_seq:
        return "session_open prior_chain_seq does not match prior tail seq"
    return None


def _validate_session_control_state(
    action_record: dict[str, Any],
    run_nonces: dict[str, str],
    closed_runs: dict[str, bool],
    active_run: str,
    active_open: str,
    prev_hash: str,
    segment_receipt_count: int,
) -> tuple[str | None, str, str]:
    ctrl = action_record.get("session_control")
    open_payload = _session_control_open(action_record)
    heartbeat = _session_control_heartbeat(action_record)
    close = _session_control_close(action_record)
    run_nonce = action_record.get("run_nonce", "")

    if not run_nonce:
        if ctrl is not None:
            return "session_control receipt missing run_nonce", active_run, active_open
        return None, active_run, active_open

    if open_payload is None:
        open_nonce = run_nonces.get(run_nonce)
        if open_nonce is None:
            return "run_nonce first receipt is not a matching session_open", active_run, active_open
        if closed_runs.get(run_nonce, False):
            return "record observed after session_close", active_run, active_open

        if heartbeat is not None:
            if heartbeat.get("run_nonce", "") != run_nonce:
                return (
                    "heartbeat run_nonce does not match receipt run_nonce",
                    active_run,
                    active_open,
                )
            if active_run == "" or active_open == "":
                return "heartbeat has no active session_open", active_run, active_open
            if heartbeat.get("run_nonce", "") != active_run:
                return (
                    "heartbeat run_nonce does not match active session_open",
                    active_run,
                    active_open,
                )
            if heartbeat.get("open_nonce", "") != open_nonce:
                return "heartbeat open_nonce does not match session_open", active_run, active_open
            if heartbeat.get("open_nonce", "") != active_open:
                return (
                    "heartbeat open_nonce does not match active session_open",
                    active_run,
                    active_open,
                )
            if heartbeat.get("chain_head", "") != prev_hash:
                return "heartbeat chain_head mismatch", active_run, active_open
            if heartbeat.get("chain_seq_head", 0) != action_record.get("chain_seq", 0) - 1:
                return "heartbeat chain_seq_head mismatch", active_run, active_open

        if close is not None:
            if close.get("run_nonce", "") != run_nonce:
                return (
                    "session_close run_nonce does not match receipt run_nonce",
                    active_run,
                    active_open,
                )
            if active_run == "" or active_open == "":
                return "session_close has no active session_open", active_run, active_open
            if close.get("run_nonce", "") != active_run:
                return (
                    "session_close run_nonce does not match active session_open",
                    active_run,
                    active_open,
                )
            if close.get("open_nonce", "") != open_nonce:
                return (
                    "session_close open_nonce does not match session_open",
                    active_run,
                    active_open,
                )
            if close.get("open_nonce", "") != active_open:
                return (
                    "session_close open_nonce does not match active session_open",
                    active_run,
                    active_open,
                )
            if close.get("root_hash", "") != prev_hash:
                return "session_close root_hash mismatch", active_run, active_open
            if close.get("final_seq", 0) != action_record.get("chain_seq"):
                return "session_close final_seq mismatch", active_run, active_open
            if close.get("receipt_count", 0) != segment_receipt_count + 1:
                return "session_close receipt_count mismatch", active_run, active_open
            closed_runs[run_nonce] = True
            return None, "", ""

        return None, active_run, active_open

    if open_payload.get("run_nonce", "") != run_nonce:
        return "session_open run_nonce does not match receipt run_nonce", active_run, active_open
    open_nonce = open_payload.get("open_nonce", "")
    if open_nonce == "":
        return "session_open open_nonce is empty", active_run, active_open
    if run_nonce in run_nonces:
        return "duplicate session_open for run_nonce", active_run, active_open
    run_nonces[run_nonce] = open_nonce
    closed_runs[run_nonce] = False
    return None, open_payload.get("run_nonce", ""), open_nonce


def _verify_chain_list(
    receipts: list[dict[str, Any]],
    public_key_hex: str | None,
    *,
    session_id: str = "proxy",
    rotation_endorsements: Sequence[RotationEndorsement] = (),
) -> ChainResult:
    if not receipts:
        return ChainResult(valid=True, receipt_count=0)

    # v2 chain verification is not implemented. v2 envelopes are surfaced
    # via verify_evidence() one at a time. If a chain contains
    # any v2 receipt we fail closed rather than silently treating it as
    # v1, which would falsely fail every v2 chain. Mixed v1/v2 chains
    # are blocked for the same reason: chain-hash bridging across v1
    # and v2 record types is not yet specified.
    for i, receipt in enumerate(receipts):
        if receipt.get("record_type") == "evidence_receipt_v2":
            # Prefer the receipt's declared chain_seq so the failure marker
            # matches the auditor's view of the sequence. Fall back to the
            # list index if the field is absent or not an int (the receipt
            # is being rejected anyway, so further validation is pointless).
            declared = receipt.get("chain_seq")
            broken = declared if isinstance(declared, int) and not isinstance(declared, bool) else i
            return ChainResult(
                valid=False,
                broken_at_seq=broken,
                error=(
                    "v2 chain verification is not implemented; "
                    "verify v2 receipts individually with verify_evidence()"
                ),
            )

    action_records: list[dict[str, Any]] = []
    for i, receipt in enumerate(receipts):
        action_record = receipt.get("action_record")
        if not isinstance(action_record, dict):
            return ChainResult(
                valid=False,
                broken_at_seq=i,
                error=f"seq {i}: missing or invalid action_record",
            )
        action_records.append(action_record)

    if rotation_endorsements:
        if public_key_hex is None or not public_key_hex.strip():
            return ChainResult(
                valid=False,
                error="rotation endorsement verification requires at least one trusted root key",
            )
        if not session_id.strip():
            return ChainResult(
                valid=False,
                error="rotation endorsement verification requires a recorder session ID",
            )
        first_boundary = next(
            (
                index
                for index, action_record in enumerate(action_records[1:], start=1)
                if action_record.get("key_transition") is not None
            ),
            len(receipts),
        )
        root_open_found = False
        for index, action_record in enumerate(action_records):
            open_payload = _session_control_open(action_record)
            if open_payload is None:
                continue
            recorder_session = open_payload.get("recorder_session", "")
            if recorder_session != session_id:
                return ChainResult(
                    valid=False,
                    error=(
                        f"signed recorder session {recorder_session!r} does not match "
                        f"endorsement session {session_id!r}"
                    ),
                )
            if index < first_boundary:
                root_open_found = True
        if not root_open_found:
            return ChainResult(
                valid=False,
                error="root receipt segment has no signed session_open recorder binding",
            )

    # When no key is pinned, lock to the first receipt's signer_key so an
    # attacker can't splice receipts from a second signer into the chain.
    expected_key = str(public_key_hex or receipts[0].get("signer_key", "")).lower()

    prev_hash: str | None = None
    prior_segment_seq: int | None = None
    segment_start_index = 0
    segment_base_seq = 0
    run_nonces: dict[str, str] = {}
    closed_runs: dict[str, bool] = {}
    active_run = ""
    active_open = ""
    segment_receipt_count = 0
    used_endorsements: set[int] = set()
    for i, receipt in enumerate(receipts):
        ar = action_records[i]
        seq = ar.get("chain_seq", i)
        marker = ar.get("key_transition")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0 or seq > _UINT64_MAX:
            return ChainResult(
                valid=False,
                broken_at_seq=i,
                error=f"seq {i}: signature: chain_seq must be a uint64",
            )

        if i == 0:
            if marker is not None:
                return ChainResult(
                    valid=False,
                    broken_at_seq=seq,
                    error=(
                        "seq "
                        f"{seq}: chain starts at a key_transition segment without the prior segment"
                    ),
                )
            if seq != 0:
                return ChainResult(
                    valid=False,
                    broken_at_seq=seq,
                    error=f"seq {seq}: root receipt segment must start at chain_seq 0",
                )
            segment_base_seq = 0
        elif marker is not None:
            if seq != 0:
                return ChainResult(
                    valid=False,
                    broken_at_seq=seq,
                    error=f"seq {seq}: key_transition marker on a non-genesis receipt (seq != 0)",
                )
            if not isinstance(marker, dict):
                return ChainResult(
                    valid=False,
                    broken_at_seq=seq,
                    error=f"seq {seq}: key_transition is not an object",
                )
            if prev_hash is None or marker.get("prior_chain_hash") != prev_hash:
                return ChainResult(
                    valid=False,
                    broken_at_seq=seq,
                    error=(
                        f"seq {seq}: key_transition prior_chain_hash does not match "
                        "actual prior tail hash"
                    ),
                )
            if ar.get("chain_prev_hash") != prev_hash:
                return ChainResult(
                    valid=False,
                    broken_at_seq=seq,
                    error=(
                        f"seq {seq}: segment-genesis chain_prev_hash does not match prior tail hash"
                    ),
                )
            if marker.get("prior_signer_key") != expected_key:
                return ChainResult(
                    valid=False,
                    broken_at_seq=seq,
                    error=(
                        f"seq {seq}: key_transition prior_signer_key does not match "
                        "prior segment key"
                    ),
                )
            if marker.get("prior_chain_seq") != prior_segment_seq:
                return ChainResult(
                    valid=False,
                    broken_at_seq=seq,
                    error=(
                        f"seq {seq}: key_transition prior_chain_seq does not match "
                        "prior segment final seq"
                    ),
                )
            successor = str(receipt.get("signer_key", "")).lower()
            prior_ar = action_records[i - 1]
            matches = [
                endorsement_index
                for endorsement_index, endorsement in enumerate(rotation_endorsements)
                if endorsement_index not in used_endorsements
                and endorsement.session_id == session_id
                and endorsement.prior_signer_key == expected_key
                and endorsement.prior_final_seq == prior_ar.get("chain_seq")
                and endorsement.prior_tail_hash == prev_hash
                and endorsement.new_signer_key == successor
            ]
            if len(matches) > 1:
                return ChainResult(
                    valid=False,
                    broken_at_seq=seq,
                    error="multiple rotation endorsements match one receipt boundary",
                )
            if matches:
                used_endorsements.add(matches[0])
            if not matches:
                return ChainResult(
                    valid=False,
                    broken_at_seq=seq,
                    error="rotation endorsement does not match receipt boundary",
                )
            expected_key = successor
            segment_start_index = i
            segment_base_seq = 0
            segment_receipt_count = 0
        elif seq == 0:
            return ChainResult(
                valid=False,
                broken_at_seq=seq,
                error=f"seq {seq}: unexpected seq 0 without a key_transition boundary",
            )

        result = _verify_receipt_dict(receipt, expected_key)
        if not result.valid:
            return ChainResult(
                valid=False,
                broken_at_seq=seq,
                error=f"seq {seq}: signature: {result.error}",
            )

        expected_seq = segment_base_seq + (i - segment_start_index)
        if seq != expected_seq:
            return ChainResult(
                valid=False,
                broken_at_seq=seq,
                error=f"seq gap: expected {expected_seq}, got {seq}",
            )

        actual_prev = ar.get("chain_prev_hash", "")
        if i == 0:
            anchor_error = _validate_first_prev_hash(ar, actual_prev)
            if anchor_error is not None:
                return ChainResult(
                    valid=False,
                    broken_at_seq=seq,
                    error=f"seq {seq}: {anchor_error}",
                )
            expected_prev = (
                actual_prev
                if actual_prev.startswith(_SESSION_OPEN_GENESIS_PREFIX)
                else _GENESIS_HASH
            )
        else:
            expected_prev = prev_hash
            open_payload = _session_control_open(ar)
            if open_payload is not None:
                if prev_hash is None:
                    return ChainResult(
                        valid=False,
                        broken_at_seq=seq,
                        error=f"seq {seq}: session_open continuation has no prior segment",
                    )
                restart_error = _validate_restart_open(
                    ar,
                    open_payload,
                    prev_hash,
                    action_records[i - 1].get("chain_seq", i - 1),
                )
                if restart_error is not None:
                    return ChainResult(
                        valid=False,
                        broken_at_seq=seq,
                        error=f"seq {seq}: {restart_error}",
                    )

        if actual_prev != expected_prev:
            return ChainResult(
                valid=False,
                broken_at_seq=seq,
                error=f"seq {seq}: chain_prev_hash mismatch",
            )

        state_error, active_run, active_open = _validate_session_control_state(
            ar,
            run_nonces,
            closed_runs,
            active_run,
            active_open,
            expected_prev,
            segment_receipt_count,
        )
        if state_error is not None:
            return ChainResult(
                valid=False,
                broken_at_seq=seq,
                error=f"seq {seq}: {state_error}",
            )

        prev_hash = _compute_receipt_hash(receipt)
        prior_segment_seq = seq
        segment_receipt_count += 1

    if len(used_endorsements) != len(rotation_endorsements):
        return ChainResult(
            valid=False,
            error="unused rotation endorsement does not match a required boundary",
        )

    first_ar = action_records[0]
    last_ar = action_records[-1]
    return ChainResult(
        valid=True,
        receipt_count=len(receipts),
        final_seq=last_ar.get("chain_seq"),
        root_hash=prev_hash,
        start_time=first_ar.get("timestamp"),
        end_time=last_ar.get("timestamp"),
    )
