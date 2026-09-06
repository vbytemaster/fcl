#!/usr/bin/env python3
"""Run and validate the one canonical Stage 6 promotion invocation."""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from check_stage6_acceptance import sha256_file, validate


def write_receipt(path: Path, receipt: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", required=True)
    parser.add_argument("--forge-fixture", required=True)
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--forge-root", required=True)
    parser.add_argument("--donors-root", required=True)
    parser.add_argument("--acceptance-manifest", required=True)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()

    root = Path(args.forge_root).resolve()
    build_dir = Path(args.build_dir).resolve()
    artifact_path = build_dir / "interop-artifacts.json"
    receipt_path = build_dir / "stage6-promotion-receipt.json"
    runner_argv = [
        str(Path(sys.executable).resolve()),
        str(Path(args.runner).resolve()),
        "--enabled", "1",
        "--forge-fixture", str(Path(args.forge_fixture).resolve()),
        "--source-dir", str(Path(args.source_dir).resolve()),
        "--build-dir", str(build_dir),
        "--forge-root", str(root),
        "--donors-root", str(Path(args.donors_root).resolve()),
        "--acceptance-manifest", str(Path(args.acceptance_manifest).resolve()),
    ]
    artifact_path.unlink(missing_ok=True)
    receipt_path.unlink(missing_ok=True)
    environment = os.environ.copy()
    environment["FORGE_ENABLE_LIBP2P_INTEROP"] = "1"
    started = time.time()
    result = subprocess.run(runner_argv, cwd=root, env=environment, check=False)
    finished = time.time()
    receipt = {
        "schema_version": 1,
        "runner_argv": runner_argv,
        "started_at_unix": started,
        "finished_at_unix": finished,
        "returncode": result.returncode,
        "artifact_path": str(artifact_path),
        "artifact_sha256": sha256_file(artifact_path) if artifact_path.is_file() else None,
    }
    write_receipt(receipt_path, receipt)

    errors, has_limitations = validate(
        root, Path(args.acceptance_manifest).resolve(), artifact_path, args.expected_head, receipt
    )
    if result.returncode != 0:
        print(f"FAILED: canonical runner exited with {result.returncode}; receipt={receipt_path}", file=sys.stderr)
        for error in errors:
            print(f"FAILED: {error}", file=sys.stderr)
        return result.returncode
    if errors:
        status = "FAILED" if "canonical runner failures must be exactly empty" in errors else "NOT_RUN"
        for error in errors:
            print(f"{status}: {error}", file=sys.stderr)
        return 1
    if has_limitations:
        print("PASS_WITH_DOCUMENTED_LIMITATIONS: canonical runner executed and was validated in this promotion")
    else:
        print("PASS: canonical runner executed and was validated in this promotion")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
