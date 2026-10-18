"""Chain-mode and single-mode checks for current-schema EvidenceReceipt v2.

``tests/conformance/current/`` holds the Go golden vectors from pipelock
``internal/contract/testdata/golden/`` (signed with the RFC 8032 section 7.1
test-1 key) and an unmodified flight-recorder file written by pipelock 3.7.0,
which carries both an ActionReceipt v1 chain and a wrapped EvidenceReceipt v2
chain. Tamper cases edit copies of these files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pipelock_verify import verify, verify_chain, verify_evidence
from pipelock_verify.__main__ import main
from pipelock_verify._evidence_chain import receipt_hash, signable_preimage

CURRENT = Path(__file__).parent / "conformance" / "current"
CONFORMANCE = Path(__file__).parent / "conformance"
GOLDEN_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
RECORDER = CURRENT / "recorder-3.7.0.jsonl"
# Public key of the recorder run in recorder-3.7.0.jsonl.
RECORDER_KEY = "c737cbb2c00cea2ea8f57127e13560b7b266b4fff433dff9a36778097001cbd5"
# Evidence root hash reported by pipelock 3.7.0 verify-receipt for that file.
RECORDER_EVIDENCE_ROOT = "0cd91c7ee48217d2a70f0dce7da9b4c0d2c26cfb26480d74fc29234051d2e12f"
GOLDEN = [
    "valid_evidence_receipt_promote_committed.json",
    "valid_evidence_receipt_proxy_decision.json",
    "valid_evidence_receipt_proxy_decision_with_spans.json",
    "valid_evidence_receipt_shadow_delta.json",
]


def _golden(name: str = "valid_evidence_receipt_proxy_decision.json") -> dict[str, Any]:
    return json.loads((CURRENT / name).read_text())


def _entries() -> list[dict[str, Any]]:
    return [json.loads(line) for line in RECORDER.read_text().splitlines() if line]


def _evidence_indexes(entries: list[dict[str, Any]]) -> list[int]:
    return [i for i, e in enumerate(entries) if e["type"] == "evidence_receipt"]


def _write(tmp_path: Path, entries: list[dict[str, Any]]) -> Path:
    path = tmp_path / "recorder.jsonl"
    path.write_text("".join(json.dumps(e) + "\n" for e in entries))
    return path


def _sign(receipt: dict[str, Any], key: Ed25519PrivateKey) -> None:
    receipt["signature"]["signature"] = "ed25519:" + key.sign(signable_preimage(receipt)).hex()


def _key_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes_raw().hex()


# ---- Go golden vectors (single mode) ----


# Go EvidenceReceipt.Validate rejects this signed fixture: delta_sample_count
# is 7 and exemplar_ids has 2 entries (registry.go validateShadowDeltaAggregation).
_SCHEMA_INVALID_GOLDEN = "valid_evidence_receipt_shadow_delta.json"


@pytest.mark.parametrize("name", GOLDEN)
def test_go_golden_vector_verifies(name: str) -> None:
    result = verify(json.dumps(_golden(name)), GOLDEN_KEY)
    if name == _SCHEMA_INVALID_GOLDEN:
        assert not result.valid
        assert "delta_sample_count" in (result.error or "")
        return
    assert result.valid, result.error
    assert result.signer_key == GOLDEN_KEY


def test_current_schema_verify_evidence_accepts_proxy_golden() -> None:
    result = verify_evidence(_golden(), public_key_hex=GOLDEN_KEY)
    assert result.valid, result.error
    assert result.payload_kind == "proxy_decision"


@pytest.mark.parametrize("name", GOLDEN)
def test_go_golden_vector_payload_tamper_fails(name: str) -> None:
    receipt = _golden(name)
    receipt["payload"]["tampered"] = True
    result = verify(receipt, GOLDEN_KEY)
    assert not result.valid
    assert "unknown payload fields" in (result.error or "")


def test_single_requires_key_for_current_schema() -> None:
    result = verify(_golden(), None)
    assert not result.valid
    assert "public key is required" in (result.error or "")


def test_single_wrong_key_fails() -> None:
    result = verify(_golden(), "00" * 32)
    assert not result.valid


@pytest.mark.parametrize("whitespace", [" ", "\t", "\n", "\r"])
def test_signature_hex_whitespace_fails_closed(whitespace: str) -> None:
    receipt = _golden()
    sig = receipt["signature"]["signature"]
    receipt["signature"]["signature"] = sig[:10] + whitespace + sig[10:]
    result = verify(receipt, GOLDEN_KEY)
    assert not result.valid
    assert "decoding signature" in (result.error or "")


def test_public_key_hex_whitespace_fails_closed() -> None:
    receipt = _golden()
    key = GOLDEN_KEY[:2] + " " + GOLDEN_KEY[2:]
    receipt["signature"]["signer_key_id"] = key
    result = verify(receipt, key)
    assert not result.valid
    assert "decoding public key" in (result.error or "")


def test_single_signer_key_id_is_bound_to_key() -> None:
    # The signature object is not signed, so only the binding catches this.
    receipt = _golden()
    receipt["signature"]["signer_key_id"] = "ab" * 32
    result = verify(receipt, GOLDEN_KEY)
    assert not result.valid
    assert "does not match the verifying key" in (result.error or "")


def test_single_key_purpose_must_match_authority() -> None:
    receipt = _golden()
    receipt["signature"]["key_purpose"] = "contract-activation-signing"
    result = verify(receipt, GOLDEN_KEY)
    assert not result.valid
    assert "not authorized" in (result.error or "")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda r: r.pop("policy_hash"), "policy_hash is required"),
        (lambda r: r.__setitem__("crit", []), "crit must include 'canonicalization'"),
        (lambda r: r["crit"].append("source_spans"), "not allowed"),
        (lambda r: r["crit"].append("canonicalization"), "duplicate"),
        (lambda r: r["canonicalization"].__setitem__("jcs_version", "x"), "canonicalization"),
        (lambda r: r.__setitem__("extra", 1), "unknown envelope fields"),
        (lambda r: r.__setitem__("principal", ""), "principal must be a non-empty"),
        (lambda r: r.__setitem__("payload_kind", "defer_opened"), "unknown payload_kind"),
        (lambda r: r["signature"].__setitem__("extra", ""), "signature must carry exactly"),
        (lambda r: r.__setitem__("receipt_version", True), "receipt_version"),
    ],
)
def test_single_structure_rejections(mutate: Any, message: str) -> None:
    receipt = _golden()
    mutate(receipt)
    result = verify(receipt, GOLDEN_KEY)
    assert not result.valid
    assert message in (result.error or "")


def test_spans_kind_requires_source_spans_crit() -> None:
    receipt = _golden("valid_evidence_receipt_proxy_decision_with_spans.json")
    receipt["crit"] = ["canonicalization"]
    result = verify(receipt, GOLDEN_KEY)
    assert not result.valid
    assert "source_spans" in (result.error or "")


def test_secret_egress_kind_fails_closed() -> None:
    receipt = _golden()
    receipt["payload_kind"] = "secret_egress_decision_v1"
    receipt["crit"] = ["canonicalization", "secret_egress_decision_v1"]
    result = verify(receipt, GOLDEN_KEY)
    assert not result.valid
    assert "not supported" in (result.error or "")


def test_wrapped_evidence_entry_verifies_in_single_mode() -> None:
    entry = _entries()[_evidence_indexes(_entries())[0]]
    assert verify(entry, RECORDER_KEY).valid


@pytest.mark.parametrize("detail", [None, [], 1, True, "null", "[]", "1", "true", "{"])
def test_malformed_evidence_detail_fails_closed(tmp_path: Path, detail: Any) -> None:
    entries = _entries()
    entry = entries[_evidence_indexes(entries)[1]]
    entry["detail"] = detail
    single = verify(entry, RECORDER_KEY)
    assert not single.valid
    assert single.error
    chain = verify_chain(_write(tmp_path, entries), RECORDER_KEY)
    assert not chain.valid
    assert "evidence detail" in (chain.error or "")


def test_missing_evidence_detail_fails_closed(tmp_path: Path) -> None:
    entries = _entries()
    entry = entries[_evidence_indexes(entries)[1]]
    del entry["detail"]
    assert not verify(entry, RECORDER_KEY).valid
    chain = verify_chain(_write(tmp_path, entries), RECORDER_KEY)
    assert not chain.valid
    assert "evidence detail" in (chain.error or "")


def test_v1_receipt_in_evidence_wrapper_fails_closed(tmp_path: Path) -> None:
    receipt = json.loads((CONFORMANCE / "valid-single.json").read_text())
    assert verify(receipt).valid
    entry = {"type": "evidence_receipt", "detail": receipt}
    single = verify(entry)
    assert not single.valid
    assert "must carry an EvidenceReceipt v2" in (single.error or "")
    chain = verify_chain(_write(tmp_path, [entry]))
    assert not chain.valid
    assert "must carry an EvidenceReceipt v2" in (chain.error or "")


# ---- recorder chain mode ----


def test_recorder_chain_verifies_evidence() -> None:
    for key in (RECORDER_KEY, None):
        result = verify_chain(RECORDER, key)
        assert result.valid, result.error
        assert result.receipt_count == 5
        assert result.evidence_count == 2
        assert result.evidence_root_hash == RECORDER_EVIDENCE_ROOT
        assert result.evidence_signer_key_id == RECORDER_KEY
        assert result.evidence_key_pinned is (key is not None)


def _tamper_payload(d: dict[str, Any]) -> None:
    d["payload"]["target"] += "x"


def _flip_signature(d: dict[str, Any]) -> None:
    sig = d["signature"]["signature"]
    d["signature"]["signature"] = sig[:-1] + ("1" if sig[-1] == "0" else "0")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (_tamper_payload, "signature verification failed"),
        (_flip_signature, "signature verification failed"),
        (lambda d: d["signature"].__setitem__("signer_key_id", "0" * 64), "signer_key_id"),
        (
            lambda d: d["signature"].__setitem__("key_purpose", "contract-activation-signing"),
            "not authorized",
        ),
        (lambda d: d.__setitem__("chain_prev_hash", "0" * 64), "chain_prev_hash"),
        (lambda d: d.__setitem__("chain_seq", 5), "chain_seq 5"),
        (lambda d: d.pop("canonicalization"), "missing envelope fields"),
    ],
)
@pytest.mark.parametrize("key", [RECORDER_KEY, None])
def test_recorder_tampered_evidence_fails(
    tmp_path: Path, mutate: Any, message: str, key: str | None
) -> None:
    entries = _entries()
    mutate(entries[_evidence_indexes(entries)[1]]["detail"])
    result = verify_chain(_write(tmp_path, entries), key)
    assert not result.valid
    assert result.broken_at_seq == 1
    assert (result.error or "").startswith("evidence seq 1: ")
    assert message in (result.error or "")


def test_recorder_tampered_evidence_cli_exit_code(tmp_path: Path, capsys: Any) -> None:
    entries = _entries()
    _tamper_payload(entries[_evidence_indexes(entries)[1]]["detail"])
    path = _write(tmp_path, entries)
    assert main([str(path), "--key", RECORDER_KEY]) == 1
    out = capsys.readouterr().out
    assert "CHAIN BROKEN" in out
    assert "evidence seq 1: signature verification failed" in out


def test_recorder_wrong_key_fails(tmp_path: Path) -> None:
    result = verify_chain(RECORDER, "11" * 32)
    assert not result.valid


def test_recorder_dropped_evidence_fails(tmp_path: Path) -> None:
    entries = _entries()
    del entries[_evidence_indexes(entries)[0]]
    result = verify_chain(_write(tmp_path, entries), RECORDER_KEY)
    assert not result.valid
    assert "chain_seq 1 does not match position 0" in (result.error or "")


def test_resigned_chain_needs_pinned_key(tmp_path: Path) -> None:
    """A chain re-signed under another key is self-consistent, so only --key catches it."""
    other = Ed25519PrivateKey.generate()
    entries = _entries()
    prev = "genesis"
    for i in _evidence_indexes(entries):
        detail = entries[i]["detail"]
        detail["chain_prev_hash"] = prev
        detail["signature"]["signer_key_id"] = _key_hex(other)
        _sign(detail, other)
        prev = receipt_hash(detail)
    path = _write(tmp_path, entries)
    unpinned = verify_chain(path)
    assert unpinned.valid, unpinned.error
    assert unpinned.evidence_key_pinned is False
    pinned = verify_chain(path, RECORDER_KEY)
    assert not pinned.valid


def test_mixed_evidence_signers_fail(tmp_path: Path) -> None:
    other = Ed25519PrivateKey.generate()
    entries = _entries()
    detail = entries[_evidence_indexes(entries)[1]]["detail"]
    detail["signature"]["signer_key_id"] = _key_hex(other)
    _sign(detail, other)
    result = verify_chain(_write(tmp_path, entries))
    assert not result.valid
    assert "does not match the verifying key" in (result.error or "")


def test_string_detail_is_accepted(tmp_path: Path) -> None:
    entries = _entries()
    for i in _evidence_indexes(entries):
        entries[i]["detail"] = json.dumps(entries[i]["detail"])
    result = verify_chain(_write(tmp_path, entries), RECORDER_KEY)
    assert result.valid, result.error
    assert result.evidence_count == 2


def test_old_schema_evidence_in_chain_fails(tmp_path: Path) -> None:
    old = json.loads((CONFORMANCE / "valid-evidence-proxy-decision.json").read_text())
    entry = {"v": 2, "seq": 0, "type": "evidence_receipt", "detail": old}
    result = verify_chain(_write(tmp_path, [entry]), GOLDEN_KEY)
    assert not result.valid
    assert "missing envelope fields" in (result.error or "")


def test_evidence_only_file_is_not_empty(tmp_path: Path, capsys: Any) -> None:
    entries = [e for e in _entries() if e["type"] == "evidence_receipt"]
    path = _write(tmp_path, entries)
    assert main([str(path), "--key", RECORDER_KEY]) == 0
    out = capsys.readouterr().out
    assert "Receipts:  0" in out
    assert "Evidence:  2" in out


# ---- --expected-signer-key-id ----


def test_chain_expected_signer_key_id() -> None:
    assert verify_chain(RECORDER, expected_signer_key_id=RECORDER_KEY).valid
    result = verify_chain(RECORDER, expected_signer_key_id="ab" * 32)
    assert not result.valid
    assert "does not match expected" in (result.error or "")


def test_chain_expected_signer_key_id_without_evidence_fails() -> None:
    result = verify_chain(CONFORMANCE / "valid-chain.jsonl", expected_signer_key_id="x")
    assert not result.valid
    assert "no evidence receipts" in (result.error or "")


def test_single_old_schema_expected_signer_key_id() -> None:
    path = CONFORMANCE / "valid-evidence-proxy-decision.json"
    raw = path.read_bytes()
    assert verify(raw, GOLDEN_KEY, expected_signer_key_id="receipt-signing-test").valid
    result = verify(raw, GOLDEN_KEY, expected_signer_key_id="someone-else")
    assert not result.valid
    assert "does not match expected" in (result.error or "")


def test_single_current_schema_expected_signer_key_id() -> None:
    assert verify(_golden(), GOLDEN_KEY, expected_signer_key_id=GOLDEN_KEY).valid
    result = verify(_golden(), GOLDEN_KEY, expected_signer_key_id="ab" * 32)
    assert not result.valid
    assert "does not match expected" in (result.error or "")


def test_single_v1_rejects_expected_signer_key_id() -> None:
    raw = (CONFORMANCE / "valid-single.json").read_bytes()
    result = verify(raw, expected_signer_key_id="anything")
    assert not result.valid
    assert "v2 evidence receipts only" in (result.error or "")


@pytest.mark.parametrize(
    ("argv", "code"),
    [
        (["--mode", "single", "--key", GOLDEN_KEY], 0),
        (["--mode", "single", "--key", GOLDEN_KEY, "--expected-signer-key-id", "wrong"], 1),
        (
            [
                "--mode",
                "single",
                "--key",
                GOLDEN_KEY,
                "--expected-signer-key-id",
                "receipt-signing-test",
            ],
            0,
        ),
    ],
)
def test_cli_single_expected_signer_key_id(argv: list[str], code: int, capsys: Any) -> None:
    path = CONFORMANCE / "valid-evidence-proxy-decision.json"
    assert main([str(path), *argv]) == code
    if code:
        assert "does not match expected" in capsys.readouterr().out


def test_cli_chain_expected_signer_key_id(capsys: Any) -> None:
    assert main([str(RECORDER), "--expected-signer-key-id", RECORDER_KEY]) == 0
    assert main([str(RECORDER), "--expected-signer-key-id", "ab" * 32]) == 1
    assert "does not match expected" in capsys.readouterr().out


def test_readme_opening_states_what_is_checked() -> None:
    lines = (Path(__file__).parent.parent / "README.md").read_text().splitlines()
    opening = next(line for line in lines if line.startswith("**Python verifier"))
    assert "flight-recorder wrapping" not in opening
    assert "`evidence_receipt` entries" in opening
    assert "payload schema" in opening
    assert "secret_egress_decision_v1" in opening
    assert "entry hash chain and its other entry types are not checked" in opening


def _resign(receipt: dict[str, Any], key: Ed25519PrivateKey) -> None:
    receipt["signature"]["signer_key_id"] = _key_hex(key)
    _sign(receipt, key)


def test_resigned_schema_invalid_payloads_fail() -> None:
    """A fresh signature must not make a payload Go Validate rejects look valid."""
    key = Ed25519PrivateKey.generate()
    pub = _key_hex(key)
    cases: list[tuple[str, dict[str, Any], str]] = []

    empty = _golden()
    empty["payload"] = {}
    cases.append(("empty", empty, "action_type"))

    unknown = _golden()
    unknown["payload"]["injected"] = True
    cases.append(("unknown", unknown, "unknown payload fields"))

    spans = _golden("valid_evidence_receipt_proxy_decision_with_spans.json")
    spans["payload"]["source_spans"] = []
    cases.append(("empty spans", spans, "source_spans"))

    bad_kind = _golden("valid_evidence_receipt_proxy_decision_with_spans.json")
    bad_kind["payload"]["source_spans"][0]["source_kind"] = "file"
    cases.append(("bad source kind", bad_kind, "source_kind"))

    bad_offset = _golden("valid_evidence_receipt_proxy_decision_with_spans.json")
    bad_offset["payload"]["source_spans"][0]["normalized_view"] = "for_matching"
    cases.append(("offset view", bad_offset, "char_offset"))

    counted = _golden("valid_evidence_receipt_shadow_delta.json")
    cases.append(("shadow count", counted, "delta_sample_count"))

    for name, receipt, message in cases:
        _resign(receipt, key)
        result = verify(receipt, pub)
        assert not result.valid, name
        assert message in (result.error or ""), name


def test_resigned_live_verdict_and_upper_match_hash_pass() -> None:
    key = Ed25519PrivateKey.generate()
    pub = _key_hex(key)
    live = _golden()
    live["payload"]["live_verdict"] = "block"
    _resign(live, key)
    assert verify(live, pub).valid

    spans = _golden("valid_evidence_receipt_proxy_decision_with_spans.json")
    match = spans["payload"]["source_spans"][0]["match_hash"]
    prefix, digest = match.split(":", 1)
    spans["payload"]["source_spans"][0]["match_hash"] = prefix + ":" + digest.upper()
    _resign(spans, key)
    result = verify(spans, pub)
    assert result.valid, result.error


def test_legacy_signature_whitespace_fails_closed() -> None:
    receipt = json.loads((CONFORMANCE / "valid-evidence-proxy-decision.json").read_text())
    sig = receipt["signature"]["signature"]
    receipt["signature"]["signature"] = sig[:10] + " " + sig[10:]
    result = verify_evidence(receipt, public_key_hex=GOLDEN_KEY)
    assert not result.valid
    assert "decoding signature" in (result.error or "")


@pytest.mark.parametrize("value", [0, 1, 2**64 - 1])
def test_current_drift_numeric_windows(value: int) -> None:
    key = Ed25519PrivateKey.generate()
    receipt = _golden()
    receipt["payload_kind"] = "contract_drift"
    receipt["payload"] = {
        "contract_hash": "contract",
        "rule_id": "rule",
        "drift_kind": "negative",
        "missed_windows": value,
    }
    _resign(receipt, key)
    result = verify(receipt, _key_hex(key))
    assert result.valid, result.error


@pytest.mark.parametrize("value", ["1", -1, True, 2**64])
def test_current_drift_rejects_invalid_windows(value: Any) -> None:
    key = Ed25519PrivateKey.generate()
    receipt = _golden()
    receipt["payload_kind"] = "contract_drift"
    receipt["payload"] = {
        "contract_hash": "contract",
        "rule_id": "rule",
        "drift_kind": "negative",
        "missed_windows": value,
    }
    _resign(receipt, key)
    result = verify(receipt, _key_hex(key))
    assert not result.valid
    assert "missed_windows" in (result.error or "")


@pytest.mark.parametrize("value", [["accepted"], {"value": "accepted"}])
def test_current_outcome_wrong_type_returns_error(value: Any) -> None:
    key = Ed25519PrivateKey.generate()
    receipt = _golden("valid_evidence_receipt_promote_committed.json")
    receipt["payload"]["validation_outcome"] = value
    _resign(receipt, key)
    result = verify_evidence(receipt, public_key_hex=_key_hex(key))
    assert not result.valid
    assert "validation_outcome" in (result.error or "")


def test_current_span_uppercase_artifact_digests() -> None:
    key = Ed25519PrivateKey.generate()
    receipt = _golden("valid_evidence_receipt_proxy_decision_with_spans.json")
    for field in ("pipelock_binary_digest", "rules_bundle_digest"):
        receipt["payload"]["source_spans"][0][field] = "sha256:" + "AB" * 32
    _resign(receipt, key)
    result = verify(receipt, _key_hex(key))
    assert result.valid, result.error


@pytest.mark.parametrize("field", ["char_offset", "char_length"])
def test_current_span_rejects_overflowing_offsets(field: str) -> None:
    key = Ed25519PrivateKey.generate()
    receipt = _golden("valid_evidence_receipt_proxy_decision_with_spans.json")
    receipt["payload"]["source_spans"][0][field] = 2**63
    _resign(receipt, key)
    result = verify(receipt, _key_hex(key))
    assert not result.valid
    assert field in (result.error or "")


def test_current_shadow_null_exemplars_match_zero_count() -> None:
    """Go json.Marshal writes a nil exemplar slice as null, and Validate accepts count 0."""
    key = Ed25519PrivateKey.generate()
    receipt = _golden("valid_evidence_receipt_shadow_delta.json")
    receipt["payload"]["aggregation"]["exemplar_ids"] = None
    receipt["payload"]["aggregation"]["delta_sample_count"] = 0
    _resign(receipt, key)
    result = verify(receipt, _key_hex(key))
    assert result.valid, result.error


def test_current_shadow_null_exemplars_still_fail_nonzero_count() -> None:
    key = Ed25519PrivateKey.generate()
    receipt = _golden("valid_evidence_receipt_shadow_delta.json")
    receipt["payload"]["aggregation"]["exemplar_ids"] = None
    _resign(receipt, key)
    result = verify(receipt, _key_hex(key))
    assert not result.valid
    assert "delta_sample_count" in (result.error or "")
