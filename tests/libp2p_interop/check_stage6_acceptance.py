#!/usr/bin/env python3
import json
import sys
import tempfile
from pathlib import Path


ARTIFACT_SCHEMA = {
    "schema_version": 1,
    "claim_scope": "external_exact_head_artifact_only",
    "required_fields": [
        "schema_version",
        "head",
        "runner_command",
        "started_at_unix",
        "finished_at_unix",
        "capability_results",
        "artifact_paths",
    ],
    "result_required_fields": [
        "capability_id",
        "scenario_id",
        "directions",
        "status",
    ],
    "allowed_result_statuses": ["passed", "limited"],
    "passing_status": "passed",
    "registration_is_not_verdict": True,
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


def required_scenarios(manifest: object) -> tuple[dict[tuple[str, str], tuple[set[str], str]], list[str]]:
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
    required: dict[tuple[str, str], tuple[set[str], str]] = {}
    for capability_id, entry in capabilities.items():
        if not isinstance(capability_id, str) or not capability_id:
            errors.append("manifest acceptance capability id is invalid")
            continue
        if not isinstance(entry, dict) or not isinstance(entry.get("scenarios"), list):
            errors.append(f"manifest {capability_id}: scenarios must be an array")
            continue
        for scenario in entry["scenarios"]:
            if not isinstance(scenario, dict):
                errors.append(f"manifest {capability_id}: scenario must be an object")
                continue
            scenario_id = scenario.get("id")
            directions = scenario.get("required_directions")
            status = scenario.get("expected_status")
            if (
                not isinstance(scenario_id, str)
                or not scenario_id
                or not isinstance(directions, list)
                or not directions
                or any(
                    not isinstance(direction, str)
                    or direction not in {
                        "forge_to_go",
                        "go_to_forge",
                        "forge_to_rust",
                        "rust_to_forge",
                    }
                    for direction in directions
                )
                or len(set(directions)) != len(directions)
                or status not in ARTIFACT_SCHEMA["allowed_result_statuses"]
            ):
                errors.append(f"manifest {capability_id}: scenario is invalid")
                continue
            key = (capability_id, scenario_id)
            if key in required:
                errors.append(f"manifest {capability_id}: duplicate acceptance scenario {scenario_id}")
            else:
                required[key] = (set(directions), status)
    return required, errors


def validate(root: Path, manifest_path: Path, artifact_path: Path, expected_head: str) -> list[str]:
    errors: list[str] = []
    if not root.is_dir():
        return ["source root is unavailable"]
    try:
        manifest = load_json(manifest_path)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        return [f"manifest cannot be read: {error}"]
    required, manifest_errors = required_scenarios(manifest)
    errors.extend(manifest_errors)
    if not artifact_path.is_file():
        return [*errors, "artifact is missing"]
    try:
        artifact = load_json(artifact_path)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        return [*errors, f"artifact cannot be read: {error}"]
    if not isinstance(artifact, dict) or set(artifact) != set(ARTIFACT_SCHEMA["required_fields"]):
        return [*errors, "artifact has invalid top-level schema"]
    if artifact.get("schema_version") != ARTIFACT_SCHEMA["schema_version"]:
        errors.append("artifact schema_version is invalid")
    if artifact.get("head") != expected_head:
        errors.append("artifact head does not match the expected exact HEAD")
    if not isinstance(artifact.get("runner_command"), str) or not artifact["runner_command"].strip():
        errors.append("artifact runner_command is required")
    started = artifact.get("started_at_unix")
    finished = artifact.get("finished_at_unix")
    if type(started) is not int or type(finished) is not int or started > finished:
        errors.append("artifact timestamps are invalid")
    paths = artifact.get("artifact_paths")
    if not isinstance(paths, list) or not paths or any(
        not isinstance(path, str) or not path for path in paths
    ):
        errors.append("artifact_paths must be a non-empty string array")
    else:
        for artifact_reference in paths:
            resolved = Path(artifact_reference)
            if not resolved.is_absolute():
                resolved = artifact_path.parent / resolved
            if not resolved.is_file():
                errors.append(f"artifact path is unavailable: {artifact_reference}")

    results = artifact.get("capability_results")
    if not isinstance(results, list):
        return [*errors, "capability_results must be an array"]
    received: dict[tuple[str, str], dict[str, object]] = {}
    for result in results:
        if not isinstance(result, dict) or set(result) != set(ARTIFACT_SCHEMA["result_required_fields"]):
            errors.append("artifact capability result has invalid schema")
            continue
        capability_id = result.get("capability_id")
        scenario_id = result.get("scenario_id")
        if not isinstance(capability_id, str) or not isinstance(scenario_id, str):
            errors.append("artifact capability result has invalid identifiers")
            continue
        key = (capability_id, scenario_id)
        if key in received:
            errors.append(f"artifact has duplicate capability scenario {capability_id}/{scenario_id}")
            continue
        received[key] = result
    if set(received) != set(required):
        errors.append("artifact capability scenarios do not exactly match the acceptance registry")
    for key, (expected_directions, expected_status) in required.items():
        result = received.get(key)
        if result is None:
            continue
        directions = result.get("directions")
        if not isinstance(directions, dict) or set(directions) != expected_directions:
            errors.append(f"artifact {key[0]}/{key[1]} directions are incomplete")
            continue
        if any(status != expected_status for status in directions.values()):
            errors.append(f"artifact {key[0]}/{key[1]} direction status differs from registry")
        if result.get("status") != expected_status:
            errors.append(f"artifact {key[0]}/{key[1]} status differs from registry")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        manifest_path = root / "manifest.json"
        artifact_path = root / "artifact.json"
        log_path = root / "runner.log"
        log_path.write_text("complete\n")
        manifest = {
            "interop_acceptance_registry": {
                "artifact_schema": ARTIFACT_SCHEMA,
                "capabilities": {
                    "test.protocol": {
                        "scenarios": [
                            {
                                "id": "test_scenario",
                                "required_directions": ["forge_to_go", "go_to_forge"],
                                "expected_status": "passed",
                            }
                        ]
                    }
                },
            }
        }
        manifest_path.write_text(json.dumps(manifest))
        if not validate(root, manifest_path, artifact_path, "expected-head"):
            print("self-test failed: missing artifact was accepted", file=sys.stderr)
            return 1
        stale = {
            "schema_version": 1,
            "head": "stale-head",
            "runner_command": "runner --scenario test_scenario",
            "started_at_unix": 1,
            "finished_at_unix": 2,
            "capability_results": [],
            "artifact_paths": ["runner.log"],
        }
        artifact_path.write_text(json.dumps(stale))
        if not validate(root, manifest_path, artifact_path, "expected-head"):
            print("self-test failed: stale artifact was accepted", file=sys.stderr)
            return 1
        partial = {**stale, "head": "expected-head"}
        partial["capability_results"] = [
            {
                "capability_id": "test.protocol",
                "scenario_id": "test_scenario",
                "directions": {"forge_to_go": "passed"},
                "status": "passed",
            }
        ]
        artifact_path.write_text(json.dumps(partial))
        if not validate(root, manifest_path, artifact_path, "expected-head"):
            print("self-test failed: partial artifact was accepted", file=sys.stderr)
            return 1
        complete = {**partial}
        complete["capability_results"] = [
            {
                "capability_id": "test.protocol",
                "scenario_id": "test_scenario",
                "directions": {"forge_to_go": "passed", "go_to_forge": "passed"},
                "status": "passed",
            }
        ]
        artifact_path.write_text(json.dumps(complete))
        if validate(root, manifest_path, artifact_path, "expected-head"):
            print("self-test failed: complete artifact was rejected", file=sys.stderr)
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
        malformed_manifest = {
            "interop_acceptance_registry": {
                "artifact_schema": ARTIFACT_SCHEMA,
                "capabilities": {
                    "test.protocol": {
                        "scenarios": [
                            {
                                "id": [],
                                "required_directions": ["forge_to_go"],
                                "expected_status": "passed",
                            }
                        ]
                    }
                },
            }
        }
        manifest_path.write_text(json.dumps(malformed_manifest))
        if not validate(root, manifest_path, artifact_path, "expected-head"):
            print("self-test failed: malformed manifest was accepted", file=sys.stderr)
            return 1
    print(
        "stage6 acceptance checker self-test ok: "
        "missing, stale, partial, pass, duplicate and malformed JSON covered"
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
    errors = validate(
        Path(sys.argv[1]).resolve(),
        Path(sys.argv[2]).resolve(),
        Path(sys.argv[3]).resolve(),
        sys.argv[4],
    )
    if errors:
        for error in errors:
            print(f"NOT_RUN: {error}", file=sys.stderr)
        return 1
    print("PASS: exact-head external acceptance artifact is complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
