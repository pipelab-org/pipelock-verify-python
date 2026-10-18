"""Command-line interface for ``python -m pipelock_verify``.

Verifies a single receipt JSON file or a flight recorder JSONL chain.
Exit code 0 on success, 1 on failure. Pipelock releases that add end-of-chain
proofs also exit 3 from ``pipelock verify-receipt`` for a valid chain whose end
is not proven; this CLI has no such state.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from ._common import InvalidReceiptError
from ._rotation import load_rotation_endorsement
from ._verify import ChainResult, VerifyResult, verify, verify_chain


def _detect_mode(path: Path) -> str:
    """Return ``"chain"`` for JSONL files, ``"single"`` otherwise."""
    if path.suffix.lower() == ".jsonl":
        return "chain"
    return "single"


def _print_single(result: VerifyResult, path: Path) -> None:
    if not result.valid:
        print(f"FAILED: {path}: {result.error}")
        return
    print(f"OK: {path}")
    if result.action_id:
        print(f"  Action ID:   {result.action_id}")
    if result.action_type:
        print(f"  Action Type: {result.action_type}")
    if result.verdict:
        print(f"  Verdict:     {result.verdict}")
    if result.target:
        print(f"  Target:      {result.target}")
    if result.transport:
        print(f"  Transport:   {result.transport}")
    if result.timestamp:
        print(f"  Timestamp:   {result.timestamp}")
    if result.signer_key:
        print(f"  Signer:      {result.signer_key}")
    if result.chain_seq is not None:
        print(f"  Chain seq:   {result.chain_seq}")
    if result.chain_prev_hash:
        print(f"  Chain prev:  {result.chain_prev_hash}")


def _print_chain(result: ChainResult, path: Path) -> None:
    if not result.valid:
        print(f"CHAIN BROKEN: {path}")
        if result.error:
            print(f"  Error:    {result.error}")
        if result.broken_at_seq is not None:
            print(f"  Broke at: seq {result.broken_at_seq}")
        return
    print(f"CHAIN VALID: {path}")
    print(f"  Receipts:  {result.receipt_count}")
    if result.evidence_count:
        pin = "pinned" if result.evidence_key_pinned else "from first receipt, not pinned"
        print(f"  Evidence:  {result.evidence_count} (signatures and links verified)")
        print(f"  Evidence key: {result.evidence_signer_key_id} ({pin})")
        print(f"  Evidence root: {result.evidence_root_hash}")
    if result.final_seq is not None:
        print(f"  Final seq: {result.final_seq}")
    if result.root_hash:
        print(f"  Root hash: {result.root_hash}")
    if result.start_time:
        print(f"  Start:     {result.start_time}")
    if result.end_time:
        print(f"  End:       {result.end_time}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pipelock_verify",
        description=(
            "Verify Pipelock action receipts. "
            "Pass a single receipt JSON file or a JSONL flight recorder "
            "chain. Exit 0 on success, 1 on failure."
        ),
    )
    parser.add_argument(
        "path",
        type=Path,
        help="receipt JSON file (single) or JSONL file (chain)",
    )
    parser.add_argument(
        "--key",
        dest="public_key_hex",
        help=(
            "expected signer public key, hex-encoded. When omitted, the "
            "embedded signer_key is trusted; chain mode pins it to the "
            "first receipt and enforces consistency across the chain."
        ),
    )
    parser.add_argument(
        "--expected-signer-key-id",
        dest="expected_signer_key_id",
        help=(
            "v2 evidence receipts only: required signature.signer_key_id. "
            "A mismatch fails, as does using it with no evidence receipts."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=("single", "chain", "auto"),
        default="auto",
        help="force single or chain mode; default auto-detects from file suffix",
    )
    parser.add_argument(
        "--session-id",
        default="proxy",
        help="signed recorder session for rotation endorsements; default proxy",
    )
    parser.add_argument(
        "--rotation-endorsement",
        action="append",
        default=None,
        type=Path,
        metavar="FILE",
        help="old-key-signed rotation endorsement; repeat for each rotation boundary",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"pipelock-verify {__version__}",
    )

    args = parser.parse_args(argv)
    path: Path = args.path

    if not path.exists():
        print(f"FAILED: {path}: file not found", file=sys.stderr)
        return 1

    mode = args.mode if args.mode != "auto" else _detect_mode(path)

    if mode == "chain":
        try:
            endorsements = [
                load_rotation_endorsement(endorsement_path)
                for endorsement_path in (args.rotation_endorsement or [])
            ]
        except (InvalidReceiptError, UnicodeDecodeError) as exc:
            print(f"CHAIN BROKEN: {path}")
            print(f"  Error:    {exc}")
            return 1
        chain_result = verify_chain(
            path,
            args.public_key_hex,
            session_id=args.session_id,
            rotation_endorsements=endorsements,
            expected_signer_key_id=args.expected_signer_key_id,
        )
        # Empty files are rejected at the CLI layer to match the Go CLI's
        # behavior (internal/cli/signing/receipt.go returns an error when
        # the extracted receipt list is empty). The library function keeps
        # the permissive "empty is vacuously valid" shape that mirrors
        # Go's receipt.VerifyChain.
        if (
            chain_result.valid
            and chain_result.receipt_count == 0
            and chain_result.evidence_count == 0
        ):
            print(f"No receipts found in {path}")
            return 1
        _print_chain(chain_result, path)
        return 0 if chain_result.valid else 1

    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"FAILED: {path}: {exc}", file=sys.stderr)
        return 1

    single_result = verify(
        data, args.public_key_hex, expected_signer_key_id=args.expected_signer_key_id
    )
    _print_single(single_result, path)
    return 0 if single_result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
