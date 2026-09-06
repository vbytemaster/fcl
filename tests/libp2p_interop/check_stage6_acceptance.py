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

from provenance import worktree_identity


ARTIFACT_SCHEMA = {
    "schema_version": 2,
    "claim_scope": "canonical_runner_exact_head_artifact_only",
    "required_fields": [
        "schema_version",
        "runner_argv",
        "started_at_unix",
        "finished_at_unix",
        "acceptance_manifest",
        "artifact_root",
        "fixture_provenance",
        "artifacts",
        "failures",
        "evidence_index",
    ],
    "raw_artifact_required_fields": [
        "dialer",
        "listener",
        "scenario",
        "runner_scenario_id",
        "acceptance_scenario_id",
        "profile",
        "transport_stack",
        "result",
        "listener_process",
    ],
    "evidence_index_required_fields": ["path", "size", "sha256"],
    "passing_status": "passed",
    "limited_status": "limited",
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
            runner_scenario_id = scenario.get("runner_scenario_id")
            profile = scenario.get("profile")
            transport_stack = scenario.get("transport_stack")
            activation = scenario.get("activation")
            directions = scenario.get("required_directions")
            status = scenario.get("expected_status")
            stack = tuple(transport_stack) if isinstance(transport_stack, list) else ()
            if (
                not isinstance(scenario_id, str)
                or not scenario_id
                or not isinstance(runner_scenario_id, str)
                or "/" not in runner_scenario_id
                or not isinstance(profile, str)
                or stack not in PROFILE_TRANSPORT_STACKS.get(profile, set())
                or activation != "enabled"
                or not isinstance(directions, list)
                or not directions
                or any(not isinstance(direction, str) or direction not in DIRECTIONS for direction in directions)
                or len(set(directions)) != len(directions)
                or status not in {ARTIFACT_SCHEMA["passing_status"], ARTIFACT_SCHEMA["limited_status"]}
                or (status == ARTIFACT_SCHEMA["limited_status"] and not has_limitation)
            ):
                errors.append(f"manifest {capability_id}: scenario is invalid")
                continue
            key = (capability_id, scenario_id)
            if key in required:
                errors.append(f"manifest {capability_id}: duplicate acceptance scenario {scenario_id}")
            else:
                required[key] = (set(directions), status, profile, stack, runner_scenario_id)
    return required, errors


def git_output(root: Path, *args: str) -> tuple[Optional[str], Optional[str]]:
    result = subprocess.run(
        ["git", "-C", str(root), *args], text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        return None, result.stderr.strip() or "git command failed"
    return result.stdout.strip(), None


def validate_git_state(root: Path, expected_head: str) -> tuple[Optional[float], list[str]]:
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
        return float(timestamp), errors
    except ValueError:
        return None, [*errors, "git commit timestamp is invalid"]


def is_timestamp(value: object) -> bool:
    return type(value) in {int, float}


def validate_runner_argv(root: Path, argv: object, manifest_path: Path) -> list[str]:
    if not isinstance(argv, list) or len(argv) < 2 or any(
        not isinstance(argument, str) or not argument for argument in argv
    ):
        return ["artifact runner_argv must record [sys.executable, *sys.argv]"]
    executable = Path(argv[0])
    if not executable.is_absolute():
        return ["artifact runner_argv must begin with an absolute sys.executable path"]
    runner_path = Path(argv[1])
    if runner_path.is_absolute():
        resolved = runner_path.resolve()
    else:
        if ".." in runner_path.parts or runner_path != CANONICAL_RUNNER:
            return ["artifact runner argv must name the canonical runner under source root"]
        resolved = (root / runner_path).resolve()
    if resolved != (root / CANONICAL_RUNNER).resolve() or not resolved.is_file():
        return ["artifact runner argv does not execute the canonical runner under source root"]
    try:
        manifest_index = argv.index("--acceptance-manifest")
        manifest_argument = Path(argv[manifest_index + 1]).resolve()
    except (ValueError, IndexError):
        return ["artifact runner argv does not record --acceptance-manifest"]
    if manifest_argument != manifest_path.resolve():
        return ["artifact runner argv acceptance manifest differs from the checked manifest"]
    return []


def validate_identity(value: object, expected_head: str, label: str) -> tuple[Optional[dict], list[str]]:
    if not isinstance(value, dict) or set(value) != {
        "head", "worktree_sha256", "dirty", "exact_identity"
    }:
        return None, [f"{label} has invalid worktree identity schema"]
    head = value.get("head")
    fingerprint = value.get("worktree_sha256")
    dirty = value.get("dirty")
    exact_identity = value.get("exact_identity")
    if (
        head != expected_head
        or not isinstance(fingerprint, str)
        or SHA256.fullmatch(fingerprint) is None
        or dirty is not False
        or exact_identity != f"git:{expected_head};worktree-sha256:{fingerprint}"
    ):
        return None, [f"{label} does not bind the clean expected worktree identity"]
    return value, []


def validate_fixture_provenance(value: object, expected_head: str, current_identity: dict) -> list[str]:
    if not isinstance(value, dict):
        return ["artifact fixture_provenance must be an object"]
    worktree = value.get("forge_worktree")
    if not isinstance(worktree, dict) or set(worktree) != {"start", "end", "changed_during_run"}:
        return ["artifact forge_worktree provenance has invalid schema"]
    start, errors = validate_identity(worktree.get("start"), expected_head, "artifact start worktree")
    end, end_errors = validate_identity(worktree.get("end"), expected_head, "artifact end worktree")
    errors.extend(end_errors)
    if worktree.get("changed_during_run") is not False:
        errors.append("artifact worktree changed_during_run must be false")
    if start is not None and end is not None and start != end:
        errors.append("artifact start and end worktree identities differ")
    if start is not None and start != current_identity:
        errors.append("artifact start worktree identity differs from the checked-out worktree")
    if end is not None and end != current_identity:
        errors.append("artifact end worktree identity differs from the checked-out worktree")
    build_info = value.get("fixture_build_info")
    if not isinstance(build_info, dict) or build_info.get("schema_version") != 2:
        errors.append("artifact fixture build_info provenance is missing")
        return errors
    forge = build_info.get("forge")
    compiler = build_info.get("compiler")
    build_profile = build_info.get("build_profile")
    if start is not None and forge != start:
        errors.append("artifact fixture build_info does not bind the start worktree identity")
    if forge != current_identity:
        errors.append("artifact fixture build_info differs from the checked-out worktree identity")
    if not isinstance(compiler, dict) or any(
        not isinstance(compiler.get(field), str) or not compiler[field]
        for field in ("path", "id", "version")
    ) or not isinstance(build_profile, str) or not build_profile:
        errors.append("artifact fixture build_info compiler or build profile is incomplete")
    return errors


def raw_evidence_paths(value: object) -> set[Path]:
    paths: set[Path] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in {"log_file", "result_file", "listener_result_file"} and isinstance(nested, str):
                paths.add(Path(nested))
            paths.update(raw_evidence_paths(nested))
    elif isinstance(value, list):
        for nested in value:
            paths.update(raw_evidence_paths(nested))
    return paths


def validate_evidence_index(
    artifact_path: Path, artifact_root: Path, artifacts: list[object], index: object
) -> tuple[dict[Path, str], list[str]]:
    errors: list[str] = []
    if not isinstance(index, list) or not index:
        return {}, ["artifact evidence_index must be a non-empty array"]
    indexed: dict[Path, str] = {}
    for entry in index:
        if not isinstance(entry, dict) or set(entry) != set(ARTIFACT_SCHEMA["evidence_index_required_fields"]):
            errors.append("artifact evidence index entry has invalid schema")
            continue
        relative = entry.get("path")
        size = entry.get("size")
        expected_hash = entry.get("sha256")
        path = Path(relative) if isinstance(relative, str) else Path()
        if (
            not isinstance(relative, str)
            or not relative
            or path.is_absolute()
            or ".." in path.parts
            or path == Path(".")
            or type(size) is not int
            or size <= 0
            or not isinstance(expected_hash, str)
            or SHA256.fullmatch(expected_hash) is None
        ):
            errors.append("artifact evidence index path, size or SHA-256 is invalid")
            continue
        resolved = (artifact_root / path).resolve()
        try:
            resolved.relative_to(artifact_root)
        except ValueError:
            errors.append("artifact evidence index path escapes artifact_root")
            continue
        if resolved == artifact_path.resolve() or resolved in indexed:
            errors.append("artifact evidence index reuses a proof path")
            continue
        if not resolved.is_file() or resolved.stat().st_size != size or sha256_file(resolved) != expected_hash:
            errors.append(f"artifact evidence index hash or size differs: {relative}")
            continue
        indexed[resolved] = relative

    references: set[Path] = set()
    for reference in raw_evidence_paths(artifacts):
        resolved = reference.resolve()
        try:
            resolved.relative_to(artifact_root)
        except ValueError:
            errors.append(f"raw runner evidence escapes artifact_root: {reference}")
            continue
        references.add(resolved)
    if references != set(indexed):
        errors.append("artifact evidence_index does not exactly cover raw runner logs and results")
    return indexed, errors


def direction_of(record: dict) -> Optional[str]:
    dialer = record.get("dialer")
    listener = record.get("listener")
    if not isinstance(dialer, str) or not isinstance(listener, str):
        return None
    direction = f"{dialer}_to_{listener}"
    return direction if direction in DIRECTIONS else None


def validate_successful_raw_record(
    record: object,
    expected_direction: str,
    expected_profile: str,
    expected_stack: tuple[str, ...],
    expected_runner_scenario: str,
    expected_acceptance_scenario: str,
    indexed_evidence: dict[Path, str],
    used_evidence: set[Path],
) -> list[str]:
    if not isinstance(record, dict):
        return ["raw runner record must be an object"]
    missing = [field for field in ARTIFACT_SCHEMA["raw_artifact_required_fields"] if field not in record]
    if missing:
        return [f"raw runner record is missing required fields: {missing}"]
    errors: list[str] = []
    if direction_of(record) != expected_direction:
        errors.append("raw runner direction differs from the capability requirement")
    if record.get("profile") != expected_profile:
        errors.append("raw runner profile differs from the capability requirement")
    stack = record.get("transport_stack")
    if not isinstance(stack, list) or tuple(stack) != expected_stack:
        errors.append("raw runner transport stack differs from the capability requirement")
    if record.get("runner_scenario_id") != expected_runner_scenario:
        errors.append("raw runner scenario differs from the capability requirement")
    if record.get("acceptance_scenario_id") != expected_acceptance_scenario:
        errors.append("raw runner acceptance scenario differs from the capability requirement")
    if record.get("scenario") != expected_runner_scenario.split("/", 1)[1]:
        errors.append("raw runner fixture scenario does not match runner_scenario_id")

    result = record.get("result")
    if not isinstance(result, dict) or result.get("status") != "ok":
        errors.append("raw runner result does not report status=ok")
        return errors
    result_file = result.get("result_file")
    attempts = result.get("attempts")
    if not isinstance(result_file, str) or not isinstance(attempts, list) or not attempts:
        errors.append("raw runner result lacks a result file or successful command attempts")
        return errors
    claim_paths = {Path(result_file).resolve()}
    for attempt in attempts:
        if not isinstance(attempt, dict) or type(attempt.get("exit_code")) is not int or attempt["exit_code"] != 0:
            errors.append("raw runner command attempt did not exit with code 0")
            continue
        log_file = attempt.get("log_file")
        if not isinstance(log_file, str):
            errors.append("raw runner command attempt lacks a log file")
        else:
            claim_paths.add(Path(log_file).resolve())

    listener = record.get("listener_process")
    terminal = listener.get("terminal_status") if isinstance(listener, dict) else None
    listener_log = listener.get("log_file") if isinstance(listener, dict) else None
    if not isinstance(listener_log, str) or not isinstance(terminal, dict) or terminal.get("exit_code") != 0:
        errors.append("raw runner listener lacks a clean terminal status")
    else:
        claim_paths.add(Path(listener_log).resolve())
    listener_result_file = record.get("listener_result_file")
    if listener_result_file is not None:
        if not isinstance(listener_result_file, str):
            errors.append("raw runner listener result file is malformed")
        else:
            claim_paths.add(Path(listener_result_file).resolve())

    for path in claim_paths:
        if path not in indexed_evidence:
            errors.append("raw runner evidence is absent from the verified evidence index")
        elif path in used_evidence:
            errors.append("raw runner evidence is reused by multiple capability directions")
        else:
            used_evidence.add(path)
    return errors


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
        return [*errors, "artifact has invalid canonical runner schema"], False
    if artifact.get("schema_version") != ARTIFACT_SCHEMA["schema_version"]:
        errors.append("artifact schema_version is invalid")
    errors.extend(validate_runner_argv(root, artifact.get("runner_argv"), manifest_path))
    started = artifact.get("started_at_unix")
    finished = artifact.get("finished_at_unix")
    now = time.time()
    if (
        not is_timestamp(started)
        or not is_timestamp(finished)
        or commit_timestamp is None
        or started < commit_timestamp
        or finished <= started
        or finished > now
    ):
        errors.append("artifact timestamps do not bind the checked-out commit interval")

    acceptance_manifest = artifact.get("acceptance_manifest")
    if not isinstance(acceptance_manifest, dict) or set(acceptance_manifest) != {"path", "sha256"}:
        errors.append("artifact acceptance_manifest has invalid schema")
    elif (
        not isinstance(acceptance_manifest.get("path"), str)
        or Path(acceptance_manifest["path"]).resolve() != manifest_path.resolve()
        or acceptance_manifest.get("sha256") != manifest_hash
    ):
        errors.append("artifact acceptance_manifest does not bind the checked manifest hash")

    try:
        current_identity = worktree_identity(root).as_json()
    except RuntimeError as error:
        errors.append(f"cannot fingerprint checked-out worktree: {error}")
        current_identity = {}
    errors.extend(validate_fixture_provenance(
        artifact.get("fixture_provenance"), expected_head, current_identity
    ))
    failures = artifact.get("failures")
    if not isinstance(failures, list) or failures:
        errors.append("canonical runner failures must be exactly empty")
    artifacts = artifact.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return [*errors, "canonical runner artifacts must be a non-empty array"], False
    root_value = artifact.get("artifact_root")
    if not isinstance(root_value, str) or not root_value or not Path(root_value).is_absolute():
        return [*errors, "artifact_root must be an absolute runner artifact directory"], False
    artifact_root = Path(root_value).resolve()
    if not artifact_root.is_dir():
        return [*errors, "artifact_root is unavailable"], False
    indexed_evidence, evidence_errors = validate_evidence_index(
        artifact_path, artifact_root, artifacts, artifact.get("evidence_index")
    )
    errors.extend(evidence_errors)

    used_records: set[int] = set()
    used_evidence: set[Path] = set()
    for (capability_id, scenario_id), (
        expected_directions,
        _expected_status,
        expected_profile,
        expected_stack,
        expected_runner_scenario,
    ) in required.items():
        for direction in expected_directions:
            matches = [
                index
                for index, record in enumerate(artifacts)
                if isinstance(record, dict)
                and record.get("acceptance_scenario_id") == scenario_id
                and direction_of(record) == direction
            ]
            if len(matches) != 1:
                errors.append(
                    f"{capability_id}/{scenario_id}/{direction} lacks one canonical raw runner record"
                )
                continue
            index = matches[0]
            if index in used_records:
                errors.append(
                    f"{capability_id}/{scenario_id}/{direction} reuses a raw runner record"
                )
                continue
            used_records.add(index)
            errors.extend(
                f"{capability_id}/{scenario_id}/{direction}: {error}"
                for error in validate_successful_raw_record(
                    artifacts[index],
                    direction,
                    expected_profile,
                    expected_stack,
                    expected_runner_scenario,
                    scenario_id,
                    indexed_evidence,
                    used_evidence,
                )
            )
    return errors, any(status == ARTIFACT_SCHEMA["limited_status"] for _, status, _, _, _ in required.values())


def fixture_manifest(expected_status: str = "passed") -> dict[str, object]:
    entry: dict[str, object] = {
        "scenarios": [
            {
                "id": "test_scenario",
                "runner_scenario_id": "tcp_noise/test_scenario",
                "profile": "native",
                "transport_stack": ["tcp", "yamux"],
                "activation": "enabled",
                "registration": "registered",
                "source_case_id": "test.case",
                "required_directions": ["forge_to_go", "go_to_forge"],
                "expected_status": expected_status,
            }
        ]
    }
    if expected_status == ARTIFACT_SCHEMA["limited_status"]:
        entry["limitation"] = {"implementation": "rust"}
    return {
        "interop_acceptance_registry": {
            "artifact_schema": ARTIFACT_SCHEMA,
            "capabilities": {"test.protocol": entry},
        }
    }


def fixture_identity(root: Path, head: str) -> dict[str, object]:
    identity = worktree_identity(root).as_json()
    if head == identity["head"]:
        return identity
    fingerprint = identity["worktree_sha256"]
    return {
        "head": head,
        "worktree_sha256": fingerprint,
        "dirty": False,
        "exact_identity": f"git:{head};worktree-sha256:{fingerprint}",
    }


def build_evidence_index(root: Path, artifacts: list[dict]) -> list[dict]:
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(raw_evidence_paths(artifacts), key=lambda value: str(value))
    ]


def write_artifact(root: Path, manifest_path: Path, artifact_path: Path, head: str) -> None:
    artifact_root = artifact_path.parent / "interop-run"
    artifact_root.mkdir(parents=True, exist_ok=True)
    timestamp = max(time.time(), float(subprocess.check_output(
        ["git", "-C", str(root), "show", "-s", "--format=%ct", "HEAD"], text=True
    ).strip()))
    artifacts: list[dict] = []
    for dialer, listener in (("forge", "go"), ("go", "forge")):
        stem = f"{dialer}-to-{listener}"
        result_file = artifact_root / f"{stem}.json"
        command_log = artifact_root / f"{stem}-dial.log"
        listener_log = artifact_root / f"{stem}-listen.log"
        result_file.write_text('{"status":"ok"}\n')
        command_log.write_text("dial finished\n")
        listener_log.write_text("listener stopped\n")
        artifacts.append({
            "dialer": dialer,
            "listener": listener,
            "scenario": "test_scenario",
            "runner_scenario_id": "tcp_noise/test_scenario",
            "acceptance_scenario_id": "test_scenario",
            "profile": "native",
            "transport_stack": ["tcp", "yamux"],
            "transport": "tcp",
            "result": {
                "status": "ok",
                "result_file": str(result_file),
                "attempts": [{
                    "command": ["fixture", "dial"],
                    "log_file": str(command_log),
                    "exit_code": 0,
                }],
            },
            "listener_process": {
                "command": ["fixture", "listen"],
                "log_file": str(listener_log),
                "terminal_status": {"exit_code": 0, "termination": "graceful"},
            },
        })
    identity = fixture_identity(root, head)
    artifact = {
        "schema_version": 2,
        "runner_argv": [
            sys.executable,
            CANONICAL_RUNNER.as_posix(),
            "--enabled",
            "ON",
            "--acceptance-manifest",
            str(manifest_path.resolve()),
        ],
        "started_at_unix": timestamp,
        "finished_at_unix": time.time(),
        "acceptance_manifest": {"path": str(manifest_path.resolve()), "sha256": sha256_file(manifest_path)},
        "artifact_root": str(artifact_root.resolve()),
        "fixture_provenance": {
            "forge_worktree": {"start": identity, "end": identity, "changed_during_run": False},
            "fixture_build_info": {
                "schema_version": 2,
                "forge": identity,
                "compiler": {"path": "/fixture/clang", "id": "Clang", "version": "22.1.8"},
                "build_profile": "default",
            },
        },
        "artifacts": artifacts,
        "failures": [],
        "evidence_index": build_evidence_index(artifact_root, artifacts),
    }
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(artifact))


def git_call(root: Path, *args: str) -> None:
    result = subprocess.run(["git", "-C", str(root), *args], text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")


def expect_rejected(root: Path, manifest_path: Path, artifact_path: Path, head: str, label: str) -> bool:
    errors, _ = validate(root, manifest_path, artifact_path, head)
    if errors:
        return True
    print(f"self-test failed: {label} was accepted", file=sys.stderr)
    return False


def self_test() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        runner_path = root / CANONICAL_RUNNER
        manifest_path = root / "manifest.json"
        artifact_path = root / "artifacts" / "interop-artifacts.json"
        runner_path.parent.mkdir(parents=True)
        runner_path.write_text("# fixture runner\n")
        (root / ".gitignore").write_text("artifacts/\n__pycache__/\n")
        manifest_path.write_text(json.dumps(fixture_manifest()))
        try:
            git_call(root, "init", "-q")
            git_call(root, "config", "user.email", "acceptance@example.invalid")
            git_call(root, "config", "user.name", "Acceptance")
            git_call(root, "add", ".gitignore", "manifest.json", CANONICAL_RUNNER.as_posix())
            git_call(root, "commit", "-qm", "fixture")
            head, error = git_output(root, "rev-parse", "HEAD")
            if error is not None or head is None:
                raise RuntimeError(error or "missing fixture HEAD")
        except RuntimeError as error:
            print(f"self-test failed: cannot initialize git fixture: {error}", file=sys.stderr)
            return 1

        if not expect_rejected(root, manifest_path, artifact_path, head, "missing artifact"):
            return 1
        write_artifact(root, manifest_path, artifact_path, "stale-head")
        if not expect_rejected(root, manifest_path, artifact_path, head, "stale head"):
            return 1
        write_artifact(root, manifest_path, artifact_path, head)
        errors, has_limitations = validate(root, manifest_path, artifact_path, head)
        if errors or has_limitations:
            print("self-test failed: canonical runner artifact was not accepted", file=sys.stderr)
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["artifacts"][0]["result"]["attempts"][0]["exit_code"] = 1
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "nonzero command attempt"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["failures"] = ["fixture failure"]
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "runner failures"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["artifacts"][0]["profile"] = "private_network"
        artifact["artifacts"][0]["transport_stack"] = ["tcp", "yamux", "pnet"]
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "wrong profile"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["evidence_index"] = artifact["evidence_index"][1:]
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "missing evidence"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["evidence_index"][0]["sha256"] = "0" * 64
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "bad evidence hash"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["artifacts"][1]["result"]["result_file"] = artifact["artifacts"][0]["result"]["result_file"]
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "reused evidence"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["capability_results"] = []
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "hand-authored capability results"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        original_runner = runner_path.read_text()
        runner_path.write_text("# dirty fixture runner\n")
        rejected = expect_rejected(root, manifest_path, artifact_path, head, "dirty tracked tree")
        runner_path.write_text(original_runner)
        if not rejected:
            return 1

        _, empty_errors = required_scenarios({
            "interop_acceptance_registry": {
                "artifact_schema": ARTIFACT_SCHEMA,
                "capabilities": {"test.protocol": {"scenarios": []}},
            }
        })
        if not empty_errors:
            print("self-test failed: empty scenario list was accepted", file=sys.stderr)
            return 1
        duplicate_path = root / "artifacts" / "duplicate.json"
        duplicate_path.write_text('{"key": 1, "key": 2}')
        try:
            load_json(duplicate_path)
        except ValueError:
            pass
        else:
            print("self-test failed: duplicate JSON key was accepted", file=sys.stderr)
            return 1

        manifest_path.write_text(json.dumps(fixture_manifest(ARTIFACT_SCHEMA["limited_status"])))
        git_call(root, "add", "manifest.json")
        git_call(root, "commit", "-qm", "limited fixture")
        limited_head, error = git_output(root, "rev-parse", "HEAD")
        if error is not None or limited_head is None:
            print("self-test failed: missing limited fixture HEAD", file=sys.stderr)
            return 1
        write_artifact(root, manifest_path, artifact_path, limited_head)
        errors, has_limitations = validate(root, manifest_path, artifact_path, limited_head)
        if errors or not has_limitations:
            print("self-test failed: documented limitation was not distinguished", file=sys.stderr)
            return 1
    print(
        "stage6 acceptance checker self-test ok: canonical schema, missing, stale, nonzero, failures, "
        "wrong profile, missing and bad evidence, reuse, dirty tree, empty scenarios and limitations covered"
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
        print("PASS_WITH_DOCUMENTED_LIMITATIONS: canonical runner acceptance artifact is complete")
    else:
        print("PASS: canonical runner acceptance artifact is complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
