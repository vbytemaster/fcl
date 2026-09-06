#!/usr/bin/env python3
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional


ARTIFACT_SCHEMA = {
    "schema_version": 1,
    "claim_scope": "external_exact_head_artifact_only",
    "required_fields": [
        "schema_version",
        "head",
        "manifest_sha256",
        "runner_argv",
        "started_at_unix",
        "finished_at_unix",
        "capability_results",
    ],
    "result_required_fields": [
        "capability_id",
        "scenario_id",
        "profile",
        "transport_stack",
        "activation",
        "directions",
        "status",
        "evidence",
    ],
    "allowed_result_statuses": ["passed", "limited"],
    "passing_status": "passed",
    "registration_is_not_verdict": True,
}

CANONICAL_RUNNER = Path("tests/libp2p_interop/runner.py")
DIRECTIONS = {"forge_to_go", "go_to_forge", "forge_to_rust", "rust_to_forge"}
SHA256 = re.compile(r"[0-9a-f]{64}")
PROFILE_TRANSPORT_STACKS = {
    "native": {("quic",), ("tcp", "yamux")},
    "private_network": {("tcp", "yamux", "pnet")},
}


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> object:
    return json.loads(path.read_text(), object_pairs_hook=reject_duplicate_keys)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def required_scenarios(
    manifest: object,
) -> tuple[dict[tuple[str, str], tuple[set[str], str, str, tuple[str, ...], str]], list[str]]:
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return {}, ["manifest must be a JSON object"]
    registry = manifest.get("interop_acceptance_registry")
    if not isinstance(registry, dict) or set(registry) != {"artifact_schema", "capabilities"}:
        return {}, ["manifest interop_acceptance_registry has invalid shape"]
    if registry.get("artifact_schema") != ARTIFACT_SCHEMA:
        return {}, ["manifest artifact schema differs from the accepted schema"]
    capabilities = registry.get("capabilities")
    if not isinstance(capabilities, dict) or not capabilities:
        return {}, ["manifest acceptance capabilities must be a non-empty object"]

    required: dict[tuple[str, str], tuple[set[str], str, str, tuple[str, ...], str]] = {}
    for capability_id, entry in capabilities.items():
        if not isinstance(capability_id, str) or not capability_id:
            errors.append("manifest acceptance capability id is invalid")
            continue
        if not isinstance(entry, dict):
            errors.append(f"manifest {capability_id}: acceptance entry must be an object")
            continue
        scenarios = entry.get("scenarios")
        if not isinstance(scenarios, list) or not scenarios:
            errors.append(f"manifest {capability_id}: scenarios must be a non-empty array")
            continue
        has_limitation = isinstance(entry.get("limitation"), dict)
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                errors.append(f"manifest {capability_id}: scenario must be an object")
                continue
            scenario_id = scenario.get("id")
            profile = scenario.get("profile")
            transport_stack = scenario.get("transport_stack")
            activation = scenario.get("activation")
            directions = scenario.get("required_directions")
            status = scenario.get("expected_status")
            stack = tuple(transport_stack) if isinstance(transport_stack, list) else ()
            if (
                not isinstance(scenario_id, str)
                or not scenario_id
                or not isinstance(profile, str)
                or stack not in PROFILE_TRANSPORT_STACKS.get(profile, set())
                or activation != "enabled"
                or not isinstance(directions, list)
                or not directions
                or any(not isinstance(direction, str) or direction not in DIRECTIONS for direction in directions)
                or len(set(directions)) != len(directions)
                or status not in ARTIFACT_SCHEMA["allowed_result_statuses"]
                or (
                    status != "limited"
                    and status != ARTIFACT_SCHEMA["passing_status"]
                )
                or (status == "limited" and not has_limitation)
            ):
                errors.append(f"manifest {capability_id}: scenario is invalid")
                continue
            key = (capability_id, scenario_id)
            if key in required:
                errors.append(f"manifest {capability_id}: duplicate acceptance scenario {scenario_id}")
            else:
                required[key] = (set(directions), status, profile, stack, activation)
    return required, errors


def git_output(root: Path, *args: str) -> tuple[Optional[str], Optional[str]]:
    result = subprocess.run(
        ["git", "-C", str(root), *args], text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        return None, result.stderr.strip() or "git command failed"
    return result.stdout.strip(), None


def validate_git_state(root: Path, expected_head: str) -> tuple[Optional[int], list[str]]:
    errors: list[str] = []
    head, error = git_output(root, "rev-parse", "HEAD")
    if error is not None or head is None:
        return None, [f"cannot read checked-out git HEAD: {error}"]
    if head != expected_head:
        errors.append("checked-out git HEAD does not match the expected exact HEAD")
    status, error = git_output(root, "status", "--porcelain", "--untracked-files=no")
    if error is not None:
        errors.append(f"cannot read tracked git status: {error}")
    elif status:
        errors.append("checked-out tracked tree is dirty")
    timestamp, error = git_output(root, "show", "-s", "--format=%ct", "HEAD")
    if error is not None or timestamp is None:
        errors.append(f"cannot read git commit timestamp: {error}")
        return None, errors
    try:
        return int(timestamp), errors
    except ValueError:
        return None, [*errors, "git commit timestamp is invalid"]


def validate_runner_argv(root: Path, argv: object) -> list[str]:
    if not isinstance(argv, list) or not argv or any(
        not isinstance(argument, str) or not argument for argument in argv
    ):
        return ["artifact runner_argv must be a non-empty string array"]
    runner_path = Path(argv[0])
    if runner_path.is_absolute() or ".." in runner_path.parts or runner_path != CANONICAL_RUNNER:
        return ["artifact runner_argv must start with the canonical runner path under source root"]
    resolved = (root / runner_path).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return ["artifact runner path escapes source root"]
    if not resolved.is_file():
        return ["artifact runner path is unavailable under source root"]
    return []


def validate_proof(
    artifact_path: Path,
    proof: object,
    seen_proofs: set[Path],
) -> list[str]:
    if not isinstance(proof, dict) or set(proof) != {"path", "sha256"}:
        return ["evidence proof has invalid schema"]
    relative_path = proof.get("path")
    expected_hash = proof.get("sha256")
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or not isinstance(expected_hash, str)
        or SHA256.fullmatch(expected_hash) is None
    ):
        return ["evidence proof path or SHA-256 is invalid"]
    path = Path(relative_path)
    if path.is_absolute() or ".." in path.parts or path == Path("."):
        return ["evidence proof must use a non-empty relative artifact path"]
    resolved = (artifact_path.parent / path).resolve()
    try:
        resolved.relative_to(artifact_path.parent.resolve())
    except ValueError:
        return ["evidence proof escapes artifact directory"]
    if resolved == artifact_path.resolve():
        return ["evidence proof cannot reference the acceptance artifact itself"]
    if resolved in seen_proofs:
        return ["evidence proof is reused by multiple capability directions"]
    seen_proofs.add(resolved)
    if not resolved.is_file() or resolved.stat().st_size == 0:
        return [f"evidence proof is unavailable or empty: {relative_path}"]
    if sha256_file(resolved) != expected_hash:
        return [f"evidence proof SHA-256 differs: {relative_path}"]
    return []


def validate(
    root: Path, manifest_path: Path, artifact_path: Path, expected_head: str
) -> tuple[list[str], bool]:
    if not root.is_dir():
        return ["source root is unavailable"], False
    try:
        manifest = load_json(manifest_path)
        manifest_hash = sha256_file(manifest_path)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        return [f"manifest cannot be read: {error}"], False
    required, errors = required_scenarios(manifest)
    if errors:
        return errors, False
    commit_timestamp, git_errors = validate_git_state(root, expected_head)
    errors.extend(git_errors)
    if not artifact_path.is_file():
        return [*errors, "artifact is missing"], False
    try:
        artifact = load_json(artifact_path)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        return [*errors, f"artifact cannot be read: {error}"], False
    if not isinstance(artifact, dict) or set(artifact) != set(ARTIFACT_SCHEMA["required_fields"]):
        return [*errors, "artifact has invalid top-level schema"], False
    if artifact.get("schema_version") != ARTIFACT_SCHEMA["schema_version"]:
        errors.append("artifact schema_version is invalid")
    if artifact.get("head") != expected_head:
        errors.append("artifact head does not match the expected exact HEAD")
    if artifact.get("manifest_sha256") != manifest_hash:
        errors.append("artifact manifest SHA-256 does not match the checked manifest")
    errors.extend(validate_runner_argv(root, artifact.get("runner_argv")))
    started = artifact.get("started_at_unix")
    finished = artifact.get("finished_at_unix")
    now = int(time.time())
    if (
        type(started) is not int
        or type(finished) is not int
        or commit_timestamp is None
        or started < commit_timestamp
        or finished <= started
        or finished > now
    ):
        errors.append("artifact timestamps do not bind the checked-out commit interval")

    results = artifact.get("capability_results")
    if not isinstance(results, list):
        return [*errors, "capability_results must be an array"], False
    received: dict[tuple[str, str], dict[str, object]] = {}
    for result in results:
        if not isinstance(result, dict) or set(result) != set(ARTIFACT_SCHEMA["result_required_fields"]):
            errors.append("artifact capability result has invalid schema")
            continue
        capability_id = result.get("capability_id")
        scenario_id = result.get("scenario_id")
        if not isinstance(capability_id, str) or not capability_id or not isinstance(scenario_id, str) or not scenario_id:
            errors.append("artifact capability result has invalid identifiers")
            continue
        key = (capability_id, scenario_id)
        if key in received:
            errors.append(f"artifact has duplicate capability scenario {capability_id}/{scenario_id}")
            continue
        received[key] = result
    if set(received) != set(required):
        errors.append("artifact capability scenarios do not exactly match the acceptance registry")

    seen_proofs: set[Path] = set()
    has_documented_limitations = False
    for key, (expected_directions, expected_status, expected_profile, expected_stack, expected_activation) in required.items():
        result = received.get(key)
        if result is None:
            continue
        if result.get("profile") != expected_profile:
            errors.append(f"artifact {key[0]}/{key[1]} profile differs from registry")
        stack = result.get("transport_stack")
        if not isinstance(stack, list) or tuple(stack) != expected_stack:
            errors.append(f"artifact {key[0]}/{key[1]} transport stack differs from registry")
        if result.get("activation") != expected_activation:
            errors.append(f"artifact {key[0]}/{key[1]} activation differs from registry")
        directions = result.get("directions")
        if not isinstance(directions, dict) or set(directions) != expected_directions:
            errors.append(f"artifact {key[0]}/{key[1]} directions are incomplete")
            continue
        if any(not isinstance(status, str) or status not in ARTIFACT_SCHEMA["allowed_result_statuses"] for status in directions.values()):
            errors.append(f"artifact {key[0]}/{key[1]} has an unknown direction status")
        if any(status != expected_status for status in directions.values()):
            errors.append(f"artifact {key[0]}/{key[1]} direction status differs from registry")
        result_status = result.get("status")
        if not isinstance(result_status, str) or result_status not in ARTIFACT_SCHEMA["allowed_result_statuses"]:
            errors.append(f"artifact {key[0]}/{key[1]} has an unknown result status")
        elif result_status != expected_status:
            errors.append(f"artifact {key[0]}/{key[1]} status differs from registry")
        if expected_status == "limited":
            has_documented_limitations = True
        evidence = result.get("evidence")
        if not isinstance(evidence, dict) or set(evidence) != expected_directions:
            errors.append(f"artifact {key[0]}/{key[1]} evidence is incomplete")
            continue
        for direction in expected_directions:
            errors.extend(validate_proof(artifact_path, evidence[direction], seen_proofs))
    return errors, has_documented_limitations


def fixture_manifest(expected_status: str = "passed") -> dict[str, object]:
    entry: dict[str, object] = {
        "scenarios": [
            {
                "id": "test_scenario",
                "profile": "native",
                "transport_stack": ["tcp", "yamux"],
                "activation": "enabled",
                "required_directions": ["forge_to_go", "go_to_forge"],
                "expected_status": expected_status,
            }
        ]
    }
    if expected_status == "limited":
        entry["limitation"] = {"implementation": "rust"}
    return {
        "interop_acceptance_registry": {
            "artifact_schema": ARTIFACT_SCHEMA,
            "capabilities": {"test.protocol": entry},
        }
    }


def write_artifact(
    root: Path, manifest_path: Path, artifact_path: Path, head: str, status: str = "passed"
) -> None:
    proof_root = artifact_path.parent / "proofs"
    proof_root.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, dict[str, str]] = {}
    for direction in ("forge_to_go", "go_to_forge"):
        proof_path = proof_root / f"{direction}.txt"
        proof_path.write_text(f"{direction} {status}\n")
        evidence[direction] = {
            "path": proof_path.relative_to(artifact_path.parent).as_posix(),
            "sha256": sha256_file(proof_path),
        }
    timestamp = int(time.time())
    artifact = {
        "schema_version": 1,
        "head": head,
        "manifest_sha256": sha256_file(manifest_path),
        "runner_argv": [CANONICAL_RUNNER.as_posix(), "--fixture"],
        "started_at_unix": timestamp - 1,
        "finished_at_unix": timestamp,
        "capability_results": [
            {
                "capability_id": "test.protocol",
                "scenario_id": "test_scenario",
                "profile": "native",
                "transport_stack": ["tcp", "yamux"],
                "activation": "enabled",
                "directions": {"forge_to_go": status, "go_to_forge": status},
                "status": status,
                "evidence": evidence,
            }
        ],
    }
    artifact_path.write_text(json.dumps(artifact))


def git_call(root: Path, *args: str) -> None:
    result = subprocess.run(["git", "-C", str(root), *args], text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        runner_path = root / CANONICAL_RUNNER
        manifest_path = root / "manifest.json"
        artifact_path = root / "artifacts" / "artifact.json"
        runner_path.parent.mkdir(parents=True)
        runner_path.write_text("# fixture runner\n")
        manifest_path.write_text(json.dumps(fixture_manifest()))
        try:
            git_call(root, "init", "-q")
            git_call(root, "config", "user.email", "acceptance@example.invalid")
            git_call(root, "config", "user.name", "Acceptance")
            git_call(root, "add", "manifest.json", CANONICAL_RUNNER.as_posix())
            git_call(root, "commit", "-qm", "fixture")
            head, error = git_output(root, "rev-parse", "HEAD")
            if error is not None or head is None:
                raise RuntimeError(error or "missing fixture HEAD")
        except RuntimeError as error:
            print(f"self-test failed: cannot initialize git fixture: {error}", file=sys.stderr)
            return 1
        time.sleep(1.1)

        errors, _ = validate(root, manifest_path, artifact_path, head)
        if not errors:
            print("self-test failed: missing artifact was accepted", file=sys.stderr)
            return 1
        write_artifact(root, manifest_path, artifact_path, "stale-head")
        errors, _ = validate(root, manifest_path, artifact_path, head)
        if not errors:
            print("self-test failed: stale artifact was accepted", file=sys.stderr)
            return 1
        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["capability_results"] = []
        artifact_path.write_text(json.dumps(artifact))
        errors, _ = validate(root, manifest_path, artifact_path, head)
        if not errors:
            print("self-test failed: partial artifact was accepted", file=sys.stderr)
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        result = artifact["capability_results"][0]
        assert isinstance(result, dict)
        result["profile"] = "private_network"
        result["transport_stack"] = ["tcp", "yamux", "pnet"]
        artifact_path.write_text(json.dumps(artifact))
        errors, _ = validate(root, manifest_path, artifact_path, head)
        if not errors:
            print("self-test failed: profile/transport substitution was accepted", file=sys.stderr)
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        result = artifact["capability_results"][0]
        assert isinstance(result, dict)
        result["evidence"] = {"forge_to_go": "label-only", "go_to_forge": "label-only"}
        artifact_path.write_text(json.dumps(artifact))
        errors, _ = validate(root, manifest_path, artifact_path, head)
        if not errors:
            print("self-test failed: forged label-only proof was accepted", file=sys.stderr)
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        result = artifact["capability_results"][0]
        assert isinstance(result, dict)
        result["evidence"]["forge_to_go"] = {
            "path": "artifact.json",
            "sha256": "0" * 64,
        }
        artifact_path.write_text(json.dumps(artifact))
        errors, _ = validate(root, manifest_path, artifact_path, head)
        if not errors:
            print("self-test failed: self-referential proof was accepted", file=sys.stderr)
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        result = artifact["capability_results"][0]
        assert isinstance(result, dict)
        result["evidence"]["go_to_forge"] = result["evidence"]["forge_to_go"]
        artifact_path.write_text(json.dumps(artifact))
        errors, _ = validate(root, manifest_path, artifact_path, head)
        if not errors:
            print("self-test failed: reused proof was accepted", file=sys.stderr)
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["manifest_sha256"] = "0" * 64
        artifact_path.write_text(json.dumps(artifact))
        errors, _ = validate(root, manifest_path, artifact_path, head)
        if not errors:
            print("self-test failed: bad manifest hash was accepted", file=sys.stderr)
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        original_runner = runner_path.read_text()
        runner_path.write_text("# dirty fixture runner\n")
        errors, _ = validate(root, manifest_path, artifact_path, head)
        runner_path.write_text(original_runner)
        if not errors:
            print("self-test failed: dirty tracked tree was accepted", file=sys.stderr)
            return 1

        _, empty_errors = required_scenarios(
            {
                "interop_acceptance_registry": {
                    "artifact_schema": ARTIFACT_SCHEMA,
                    "capabilities": {"test.protocol": {"scenarios": []}},
                }
            }
        )
        if not empty_errors:
            print("self-test failed: empty scenario list was accepted", file=sys.stderr)
            return 1
        duplicate_path = root / "duplicate.json"
        duplicate_path.write_text('{"key": 1, "key": 2}')
        try:
            load_json(duplicate_path)
        except ValueError:
            pass
        else:
            print("self-test failed: duplicate JSON key was accepted", file=sys.stderr)
            return 1

        manifest_path.write_text(json.dumps(fixture_manifest("limited")))
        git_call(root, "add", "manifest.json")
        git_call(root, "commit", "-qm", "limited fixture")
        limited_head, error = git_output(root, "rev-parse", "HEAD")
        if error is not None or limited_head is None:
            print("self-test failed: missing limited fixture HEAD", file=sys.stderr)
            return 1
        time.sleep(1.1)
        write_artifact(root, manifest_path, artifact_path, limited_head, "limited")
        errors, has_limitations = validate(root, manifest_path, artifact_path, limited_head)
        if errors or not has_limitations:
            print("self-test failed: documented limited result was not distinguished", file=sys.stderr)
            return 1
    print(
        "stage6 acceptance checker self-test ok: missing, stale, partial, forged, "
        "profile substitution, self-reference, reuse, dirty tree, bad hash, empty scenarios and limited results covered"
    )
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) != 5:
        print(
            "usage: check_stage6_acceptance.py SOURCE_ROOT MANIFEST ARTIFACT EXPECTED_HEAD | --self-test",
            file=sys.stderr,
        )
        return 2
    errors, has_documented_limitations = validate(
        Path(sys.argv[1]).resolve(),
        Path(sys.argv[2]).resolve(),
        Path(sys.argv[3]).resolve(),
        sys.argv[4],
    )
    if errors:
        for error in errors:
            print(f"NOT_RUN: {error}", file=sys.stderr)
        return 1
    if has_documented_limitations:
        print("PASS_WITH_DOCUMENTED_LIMITATIONS: exact-head external acceptance artifact is complete")
    else:
        print("PASS: exact-head external acceptance artifact is complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
