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
        "effective_configuration",
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
RUNNER_FLAGS = (
    "--enabled",
    "--forge-fixture",
    "--source-dir",
    "--build-dir",
    "--forge-root",
    "--donors-root",
    "--acceptance-manifest",
)
ENABLED_VALUES = {"1", "ON", "on", "true", "TRUE", "yes", "YES"}
CAPABILITY_LISTENER_FEATURES = {
    "protocol.autonat_v1_client": "autonatv1",
    "protocol.autonat_v1_service": "autonatv1",
    "protocol.autonat_v2_client": "autonatv2",
    "protocol.autonat_v2_service": "autonatv2",
    "relay.circuit_v2_service": "relay",
}
PRIVATE_NETWORK_TRANSPORT = "tcp-pnet"
PRIVATE_NETWORK_PSK_DEPENDENCY = "security.private_network_psk"
PRIVATE_EGRESS_POLICY_DEPENDENCY = "reachability.private_internet_policy"
PRIVATE_EGRESS_POLICY_VALUE = "allow-internet"
PRIVATE_PNET_RESULT_FIELDS = ("pnet_enabled", "negotiated_pnet", "pnet_fingerprint")
PNET_FINGERPRINT_DOMAIN = b"forge-p2p-stage6-pnet-fingerprint-v1\x00"


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


def pnet_fingerprint(pnet_key_file: Path) -> str:
    """Return the public fingerprint of the exact private-network PSK bytes."""
    return hashlib.sha256(PNET_FINGERPRINT_DOMAIN + pnet_key_file.read_bytes()).hexdigest()


def required_scenarios(
    manifest: object,
) -> tuple[dict[tuple[str, str], tuple[set[str], str, str, tuple[str, ...], str, tuple[str, ...]]], list[str]]:
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

    required: dict[tuple[str, str], tuple[set[str], str, str, tuple[str, ...], str, tuple[str, ...]]] = {}
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
            requires = scenario.get("requires_capabilities", [])
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
                or not isinstance(requires, list)
                or any(not isinstance(capability, str) or not capability for capability in requires)
                or len(set(requires)) != len(requires)
                or status not in {ARTIFACT_SCHEMA["passing_status"], ARTIFACT_SCHEMA["limited_status"]}
                or (status == ARTIFACT_SCHEMA["limited_status"] and not has_limitation)
            ):
                errors.append(f"manifest {capability_id}: scenario is invalid")
                continue
            key = (capability_id, scenario_id)
            if key in required:
                errors.append(f"manifest {capability_id}: duplicate acceptance scenario {scenario_id}")
            else:
                required[key] = (
                    set(directions), status, profile, stack, runner_scenario_id, tuple(requires)
                )
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


def absolute_path(value: object) -> Optional[Path]:
    if not isinstance(value, str) or not value:
        return None
    path = Path(value)
    return path.resolve() if path.is_absolute() else None


def validate_runner_inputs(root: Path, artifact_path: Path, artifact_root: Path, manifest_path: Path,
                           provenance: object) -> tuple[dict[str, Path], list[str]]:
    if not isinstance(provenance, dict):
        return {}, ["artifact fixture_provenance must be an object"]
    inputs = provenance.get("runner_inputs")
    if not isinstance(inputs, dict) or set(inputs) != {
        "source_dir", "build_dir", "forge_root", "donors_root", "acceptance_manifest"
    }:
        return {}, ["artifact runner input provenance has invalid schema"]
    paths = {key: absolute_path(inputs.get(key)) for key in inputs}
    if any(path is None for path in paths.values()):
        return {}, ["artifact runner input provenance contains a non-absolute path"]
    resolved = {key: path for key, path in paths.items() if path is not None}
    build_dir = resolved["build_dir"]
    if (
        resolved["source_dir"] != (root / CANONICAL_RUNNER).parent.resolve()
        or resolved["forge_root"] != root.resolve()
        or resolved["acceptance_manifest"] != manifest_path.resolve()
        or not resolved["donors_root"].is_dir()
        or artifact_root != build_dir / "interop-run"
        or artifact_path.resolve() != build_dir / "interop-artifacts.json"
    ):
        return {}, ["artifact runner input provenance does not bind canonical roots and artifact paths"]
    return resolved, []


def validate_runner_argv(root: Path, argv: object, manifest_path: Path, inputs: dict[str, Path],
                         binary_paths: dict[str, Path]) -> list[str]:
    if not isinstance(argv, list) or len(argv) != 2 + 2 * len(RUNNER_FLAGS) or any(
        not isinstance(argument, str) or not argument for argument in argv
    ):
        return ["artifact runner_argv must record the complete canonical runner invocation"]
    if Path(argv[0]).resolve() != Path(sys.executable).resolve():
        return ["artifact runner_argv executable differs from the current resolved sys.executable"]
    runner_path = Path(argv[1])
    resolved_runner = runner_path.resolve() if runner_path.is_absolute() else (root / runner_path).resolve()
    if resolved_runner != (root / CANONICAL_RUNNER).resolve() or not resolved_runner.is_file():
        return ["artifact runner argv does not execute the canonical runner under source root"]
    if tuple(argv[2::2]) != RUNNER_FLAGS:
        return ["artifact runner argv flags differ from the canonical live runner mode"]
    values = dict(zip(RUNNER_FLAGS, argv[3::2]))
    if values["--enabled"] not in ENABLED_VALUES:
        return ["artifact runner argv does not prove an enabled live execution"]
    expected = {
        "--forge-fixture": binary_paths.get("forge"),
        "--source-dir": inputs.get("source_dir"),
        "--build-dir": inputs.get("build_dir"),
        "--forge-root": root.resolve(),
        "--donors-root": inputs.get("donors_root"),
        "--acceptance-manifest": manifest_path.resolve(),
    }
    for flag, expected_path in expected.items():
        if expected_path is None or absolute_path(values[flag]) != expected_path:
            return [f"artifact runner argv {flag} differs from canonical runner inputs"]
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


def validate_execution_provenance(value: object, expected_head: str,
                                  current_identity: dict) -> tuple[dict[str, Path], list[str]]:
    errors = validate_fixture_provenance(value, expected_head, current_identity)
    if not isinstance(value, dict):
        return {}, errors
    tools = value.get("tools")
    python_tool = tools.get("python") if isinstance(tools, dict) else None
    expected_python = Path(sys.executable).resolve()
    if not isinstance(python_tool, dict) or set(python_tool) != {"path", "version_output"}:
        errors.append("artifact Python tool provenance has invalid schema")
    elif absolute_path(python_tool.get("path")) != expected_python:
        errors.append("artifact Python tool provenance differs from current sys.executable")
    else:
        try:
            current_version = subprocess.check_output([str(expected_python), "--version"], text=True).strip()
        except OSError as error:
            errors.append(f"cannot read current Python tool provenance: {error}")
        else:
            if python_tool.get("version_output") != current_version:
                errors.append("artifact Python tool version provenance differs from current sys.executable")

    binaries = value.get("binaries")
    if not isinstance(binaries, dict) or set(binaries) != {"forge", "go", "rust"}:
        errors.append("artifact binary provenance must cover forge, go and rust exactly")
        return {}, errors
    paths: dict[str, Path] = {}
    for implementation, binary in binaries.items():
        path = absolute_path(binary.get("path")) if isinstance(binary, dict) else None
        digest = binary.get("sha256") if isinstance(binary, dict) else None
        if (
            path is None
            or not path.is_file()
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
            or sha256_file(path) != digest
        ):
            errors.append(f"artifact {implementation} binary path or SHA-256 provenance is invalid")
        else:
            paths[implementation] = path
    return paths, errors


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


def raw_result_payloads(value: object):
    if isinstance(value, dict):
        if isinstance(value.get("result_file"), str):
            yield value
        for nested in value.values():
            yield from raw_result_payloads(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from raw_result_payloads(nested)


def validate_all_result_evidence(artifacts: list[object], indexed_evidence: dict[Path, str],
                                 artifact_root: Path) -> list[str]:
    errors: list[str] = []
    for index, record in enumerate(artifacts):
        if not isinstance(record, dict):
            continue
        for result in raw_result_payloads(record):
            result_path = path_within(result["result_file"], artifact_root)
            if result_path is None or result_path not in indexed_evidence:
                errors.append(f"raw runner record {index} result evidence is absent from the verified index")
            else:
                payload, payload_errors = load_evidence_json(result_path, f"raw runner record {index} result file")
                errors.extend(payload_errors)
                expected = {key: value for key, value in result.items() if key not in {"result_file", "attempts"}}
                if payload is not None and payload != expected:
                    errors.append(f"raw runner record {index} result file does not match its raw payload")
        listener_file = record.get("listener_result_file")
        if listener_file is not None:
            listener_path = path_within(listener_file, artifact_root)
            if listener_path is None or listener_path not in indexed_evidence:
                errors.append(f"raw runner record {index} listener result evidence is absent from the verified index")
            else:
                payload, payload_errors = load_evidence_json(
                    listener_path, f"raw runner record {index} listener result file"
                )
                errors.extend(payload_errors)
                if payload is not None and payload != record.get("listener_result"):
                    errors.append(f"raw runner record {index} listener result file does not match its raw payload")
    return errors


def direction_of(record: dict) -> Optional[str]:
    dialer = record.get("dialer")
    listener = record.get("listener")
    if not isinstance(dialer, str) or not isinstance(listener, str):
        return None
    direction = f"{dialer}_to_{listener}"
    return direction if direction in DIRECTIONS else None


def command_options(command: object, action: str) -> tuple[dict[str, str], list[str]]:
    if not isinstance(command, list) or len(command) < 2 or any(
        not isinstance(value, str) or not value for value in command
    ):
        return {}, ["command is not a non-empty string array"]
    if command[1] != action or (len(command) - 2) % 2:
        return {}, [f"command is not a {action} command with flag/value pairs"]
    options: dict[str, str] = {}
    for index in range(2, len(command), 2):
        flag, value = command[index], command[index + 1]
        if not flag.startswith("--") or flag in options:
            return {}, ["command has a duplicate or malformed option"]
        options[flag] = value
    return options, []


def path_within(path: object, root: Path) -> Optional[Path]:
    resolved = absolute_path(path)
    if resolved is None:
        return None
    try:
        resolved.relative_to(root)
    except ValueError:
        return None
    return resolved


def failure_text(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    return any(
        isinstance(value.get(key), str) and value[key].strip()
        for key in ("error", "failure", "failure_class", "timeout_class")
    )


def load_evidence_json(path: Path, label: str) -> tuple[Optional[dict], list[str]]:
    try:
        payload = load_json(path)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        return None, [f"{label} is not valid JSON: {error}"]
    if not isinstance(payload, dict):
        return None, [f"{label} must be a JSON object"]
    if failure_text(payload):
        return None, [f"{label} contains contradictory failure text"]
    return payload, []


def validate_result_semantics(result: dict, record: dict) -> list[str]:
    errors: list[str] = []
    if result.get("implementation") != record.get("dialer") or result.get("role") != "dialer":
        errors.append("raw runner result does not identify the recorded dialer role")
    if result.get("scenario") != record.get("scenario"):
        errors.append("raw runner result scenario differs from the raw runner record")
    scenario = record.get("scenario")
    if scenario == "ping" and not (
        type(result.get("rtt_ms")) is int and result["rtt_ms"] >= 0
    ) and result.get("ping_ok") is not True:
        errors.append("raw Ping result lacks an RTT or successful Ping evidence")
    if scenario == "identify" and not (
        result.get("signed_peer_record") is True
        and (
            type(result.get("protocol_count")) is int and result["protocol_count"] > 0
            or type(result.get("payload_bytes")) is int and result["payload_bytes"] > 0
        )
    ):
        errors.append("raw Identify result lacks signed-peer-record protocol evidence")
    if isinstance(scenario, str) and scenario.startswith("dht_") and result.get("negotiated_protocol") != "/ipfs/kad/1.0.0":
        errors.append("raw DHT result lacks the Amino Kademlia negotiated protocol")
    if isinstance(scenario, str) and scenario.startswith("rendezvous_") and result.get("negotiated_protocol") != "/rendezvous/1.0.0":
        errors.append("raw Rendezvous result lacks the negotiated protocol")
    return errors


def launcher_execution_description(options: dict[str, str], payload: dict) -> dict[str, object]:
    """Return the non-secret execution inputs/results that a raw record may repeat."""
    description: dict[str, object] = {"transport": options.get("--transport")}
    if "--pnet-key-file" in options:
        description["pnet_key_file"] = options["--pnet-key-file"]
    if "--private-egress-policy" in options:
        description["private_egress_policy"] = options["--private-egress-policy"]
    for field in PRIVATE_PNET_RESULT_FIELDS:
        if field in payload:
            description[field] = payload[field]
    for field in ("private_egress_policy", "egress_policy_enforced"):
        if field in payload:
            description[field] = payload[field]
    return description


def validate_effective_configuration(record: dict, expected_profile: str,
                                     expected_stack: tuple[str, ...], dial_options: dict[str, str],
                                     listener_options: dict[str, str], dial_payload: dict,
                                     listener_payload: Optional[dict]) -> list[str]:
    """Ensure the summary is a projection of commands/results, never manifest authority."""
    configuration = record.get("effective_configuration")
    expected = {
        "activation": "enabled",
        "profile": expected_profile,
        "transport_stack": list(expected_stack),
        "dialer": launcher_execution_description(dial_options, dial_payload),
        "listener": launcher_execution_description(listener_options, listener_payload or {}),
    }
    if configuration != expected:
        return ["raw runner effective configuration does not match launcher inputs and result evidence"]
    return []


def validate_private_network_proofs(capability_id: str, expected_requires: tuple[str, ...],
                                    dial_options: dict[str, str], listener_options: dict[str, str],
                                    dial_payload: dict, listener_payload: Optional[dict],
                                    artifact_root: Path, indexed_evidence: dict[Path, str]) -> list[str]:
    """Map private-profile dependencies to command and endpoint result proof."""
    errors: list[str] = []
    unmapped_dependencies = set(expected_requires) - {
        PRIVATE_NETWORK_PSK_DEPENDENCY,
        PRIVATE_EGRESS_POLICY_DEPENDENCY,
    }
    if unmapped_dependencies:
        errors.append(
            f"private network dependencies lack command/result proof mappings: {sorted(unmapped_dependencies)}"
        )
    if dial_options.get("--transport") != PRIVATE_NETWORK_TRANSPORT or (
        listener_options.get("--transport") != PRIVATE_NETWORK_TRANSPORT
    ):
        errors.append("private network commands must use --transport tcp-pnet, not ordinary tcp")
    dial_key = absolute_path(dial_options.get("--pnet-key-file"))
    listener_key = absolute_path(listener_options.get("--pnet-key-file"))
    if (
        dial_key is None
        or listener_key is None
        or dial_key != listener_key
        or not dial_key.is_file()
    ):
        errors.append("private network commands must reference the same existing --pnet-key-file")
    else:
        try:
            dial_key.relative_to(artifact_root)
        except ValueError:
            pass
        else:
            errors.append("private-network key material must stay outside the artifact evidence directory")
        if dial_key in indexed_evidence:
            errors.append("private-network key material must not be serialized or hashed as artifact evidence")
    expected_fingerprint = pnet_fingerprint(dial_key) if dial_key is not None and dial_key.is_file() else None
    for label, payload in (("dialer", dial_payload), ("listener", listener_payload)):
        if not isinstance(payload, dict):
            errors.append(f"private network {label} lacks a parsed result payload")
            continue
        if payload.get("pnet_enabled") is not True or payload.get("negotiated_pnet") is not True:
            errors.append(f"private network {label} result does not confirm enabled PNET negotiation")
        fingerprint = payload.get("pnet_fingerprint")
        if not isinstance(fingerprint, str) or SHA256.fullmatch(fingerprint) is None:
            errors.append(f"private network {label} result lacks a stable non-secret PNET fingerprint")
        elif fingerprint != expected_fingerprint:
            errors.append(f"private network {label} fingerprint does not match the configured PSK bytes")
    if isinstance(listener_payload, dict) and dial_payload.get("pnet_fingerprint") != listener_payload.get("pnet_fingerprint"):
        errors.append("private network endpoints do not report the same PNET fingerprint")

    requires_egress = PRIVATE_EGRESS_POLICY_DEPENDENCY in expected_requires
    is_private_autonat = capability_id.startswith("protocol.autonat_")
    if is_private_autonat and not requires_egress:
        errors.append("private AutoNAT acceptance must require reachability.private_internet_policy")
    if requires_egress:
        for label, options, payload in (
            ("dialer", dial_options, dial_payload),
            ("listener", listener_options, listener_payload),
        ):
            if options.get("--private-egress-policy") != PRIVATE_EGRESS_POLICY_VALUE:
                errors.append(f"private Internet policy requires {label} --private-egress-policy")
                continue
            if not isinstance(payload, dict) or (
                payload.get("private_egress_policy") != PRIVATE_EGRESS_POLICY_VALUE
                or payload.get("egress_policy_enforced") is not True
            ):
                errors.append(f"private Internet policy lacks {label} executable result evidence")
    return errors


def validate_successful_raw_record(
    record: object,
    capability_id: str,
    expected_direction: str,
    expected_profile: str,
    expected_stack: tuple[str, ...],
    expected_runner_scenario: str,
    expected_acceptance_scenario: str,
    expected_requires: tuple[str, ...],
    indexed_evidence: dict[Path, str],
    used_evidence: set[Path],
    binary_paths: dict[str, Path],
    artifact_root: Path,
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
    result_path = path_within(result_file, artifact_root)
    if result_path is None:
        errors.append("raw runner result file escapes the artifact directory")
        return errors
    payload, payload_errors = load_evidence_json(result_path, "raw runner result file")
    errors.extend(payload_errors)
    raw_payload = {key: value for key, value in result.items() if key not in {"result_file", "attempts"}}
    if payload is not None and payload != raw_payload:
        errors.append("raw runner result file does not match the recorded raw result payload")
    if failure_text(result):
        errors.append("raw runner result contains contradictory failure text")
    errors.extend(validate_result_semantics(result, record))
    claim_paths = {result_path}
    dial_options: dict[str, str] = {}
    for attempt in attempts:
        if not isinstance(attempt, dict) or type(attempt.get("exit_code")) is not int or attempt["exit_code"] != 0:
            errors.append("raw runner command attempt did not exit with code 0")
            continue
        if attempt.get("kind") != "dial" or attempt.get("scenario_id") != record.get("scenario") or failure_text(attempt):
            errors.append("raw runner command attempt has contradictory execution status")
            continue
        command = attempt.get("command")
        if not isinstance(command, list) or not command or absolute_path(command[0]) != binary_paths.get(record.get("dialer")):
            errors.append("raw runner dial command executable differs from recorded dialer binary")
            continue
        options, command_errors = command_options(command, "dial")
        errors.extend(command_errors)
        required_options = {"--scenario", "--peer-id", "--addr", "--result-file", "--store-dir", "--transport"}
        optional_options = {"--payload", "--target-peer-id"}
        if expected_profile == "private_network":
            required_options.add("--pnet-key-file")
            optional_options.add("--private-egress-policy")
        if set(options) - (required_options | optional_options) or not required_options <= set(options):
            errors.append("raw runner dial command has an invalid option schema")
        elif (
            options["--scenario"] != record.get("scenario")
            or path_within(options["--result-file"], artifact_root) != result_path
            or path_within(options["--store-dir"], artifact_root) is None
            or not options["--peer-id"]
            or not options["--addr"]
            or options["--transport"] != record.get("transport")
        ):
            errors.append("raw runner dial command does not match its recorded result")
        else:
            dial_options = options
        log_file = attempt.get("log_file")
        if not isinstance(log_file, str):
            errors.append("raw runner command attempt lacks a log file")
        else:
            claim_paths.add(Path(log_file).resolve())

    listener_options: dict[str, str] = {}
    listener_payload: Optional[dict] = None
    listener = record.get("listener_process")
    terminal = listener.get("terminal_status") if isinstance(listener, dict) else None
    listener_log = listener.get("log_file") if isinstance(listener, dict) else None
    if not isinstance(listener_log, str) or not isinstance(terminal, dict) or terminal.get("exit_code") != 0:
        errors.append("raw runner listener lacks a clean terminal status")
    else:
        claim_paths.add(Path(listener_log).resolve())
        command = listener.get("command") if isinstance(listener, dict) else None
        if not isinstance(command, list) or not command or absolute_path(command[0]) != binary_paths.get(record.get("listener")):
            errors.append("raw runner listener command executable differs from recorded listener binary")
        else:
            options, command_errors = command_options(command, "listen")
            errors.extend(command_errors)
            required_options = {"--ready-file", "--stop-file", "--store-dir", "--features", "--transport", "--scenario"}
            optional_options = {"--result-file", "--seed-file", "--seed-peer-id", "--seed-addr", "--expected-messages"}
            if expected_profile == "private_network":
                required_options.update({"--pnet-key-file", "--result-file"})
                optional_options.add("--private-egress-policy")
            if set(options) - (required_options | optional_options) or not required_options <= set(options):
                errors.append("raw runner listener command has an invalid option schema")
            elif (
                options["--scenario"] != record.get("scenario")
                or options["--transport"] != record.get("transport")
                or not options["--features"]
                or any(path_within(options[field], artifact_root) is None for field in ("--ready-file", "--stop-file", "--store-dir"))
                or (
                    record.get("listener_result_file") is not None
                    and path_within(options.get("--result-file"), artifact_root)
                    != path_within(record.get("listener_result_file"), artifact_root)
                )
            ):
                errors.append("raw runner listener command does not match the recorded listener")
            else:
                listener_options = options
            expected_feature = CAPABILITY_LISTENER_FEATURES.get(capability_id)
            if expected_feature is not None and expected_feature not in options.get("--features", "").split(","):
                errors.append("raw runner listener command does not enable the required optional service")
    listener_result_file = record.get("listener_result_file")
    if listener_result_file is not None:
        if not isinstance(listener_result_file, str):
            errors.append("raw runner listener result file is malformed")
        else:
            listener_result_path = path_within(listener_result_file, artifact_root)
            if listener_result_path is None:
                errors.append("raw runner listener result file escapes the artifact directory")
            else:
                listener_payload, listener_errors = load_evidence_json(
                    listener_result_path, "raw runner listener result file"
                )
                errors.extend(listener_errors)
                if listener_payload is not None and listener_payload != record.get("listener_result"):
                    errors.append("raw runner listener result file does not match the recorded listener payload")
                claim_paths.add(listener_result_path)

    if expected_profile == "private_network":
        errors.extend(validate_private_network_proofs(
            capability_id,
            expected_requires,
            dial_options,
            listener_options,
            payload or {},
            listener_payload,
            artifact_root,
            indexed_evidence,
        ))
    errors.extend(validate_effective_configuration(
        record,
        expected_profile,
        expected_stack,
        dial_options,
        listener_options,
        payload or {},
        listener_payload,
    ))

    for path in claim_paths:
        if path not in indexed_evidence:
            errors.append("raw runner evidence is absent from the verified evidence index")
        elif path in used_evidence:
            errors.append("raw runner evidence is reused by multiple capability directions")
        else:
            used_evidence.add(path)
    return errors


def validate_execution_receipt(receipt: object, artifact_path: Path, artifact: dict) -> list[str]:
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema_version", "runner_argv", "started_at_unix", "finished_at_unix", "returncode",
        "invocation_directory", "artifact_path", "artifact_sha256",
    }:
        return ["promotion execution receipt has invalid schema"]
    started = receipt.get("started_at_unix")
    finished = receipt.get("finished_at_unix")
    artifact_started = artifact.get("started_at_unix")
    artifact_finished = artifact.get("finished_at_unix")
    if (
        receipt.get("schema_version") != 2
        or receipt.get("runner_argv") != artifact.get("runner_argv")
        or receipt.get("returncode") != 0
        or absolute_path(receipt.get("invocation_directory")) != artifact_path.parent.resolve()
        or absolute_path(receipt.get("artifact_path")) != artifact_path.resolve()
        or receipt.get("artifact_sha256") != sha256_file(artifact_path)
        or not is_timestamp(started)
        or not is_timestamp(finished)
        or not is_timestamp(artifact_started)
        or not is_timestamp(artifact_finished)
        or started > artifact_started
        or finished < artifact_finished
    ):
        return ["promotion execution receipt does not bind this successful runner invocation"]
    return []


def validate(
    root: Path, manifest_path: Path, artifact_path: Path, expected_head: str,
    execution_receipt: Optional[dict] = None,
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
    if execution_receipt is not None:
        errors.extend(validate_execution_receipt(execution_receipt, artifact_path, artifact))
    root_value = artifact.get("artifact_root")
    if not isinstance(root_value, str) or not root_value or not Path(root_value).is_absolute():
        return [*errors, "artifact_root must be an absolute runner artifact directory"], False
    artifact_root = Path(root_value).resolve()
    if not artifact_root.is_dir():
        return [*errors, "artifact_root is unavailable"], False
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
    binary_paths, provenance_errors = validate_execution_provenance(
        artifact.get("fixture_provenance"), expected_head, current_identity
    )
    errors.extend(provenance_errors)
    inputs, input_errors = validate_runner_inputs(
        root, artifact_path, artifact_root, manifest_path, artifact.get("fixture_provenance")
    )
    errors.extend(input_errors)
    errors.extend(validate_runner_argv(
        root, artifact.get("runner_argv"), manifest_path, inputs, binary_paths
    ))
    failures = artifact.get("failures")
    if not isinstance(failures, list):
        errors.append("canonical runner failures has invalid schema")
    elif failures:
        errors.append("canonical runner failures must be exactly empty")
    artifacts = artifact.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return [*errors, "canonical runner artifacts must be a non-empty array"], False
    indexed_evidence, evidence_errors = validate_evidence_index(
        artifact_path, artifact_root, artifacts, artifact.get("evidence_index")
    )
    errors.extend(evidence_errors)
    errors.extend(validate_all_result_evidence(artifacts, indexed_evidence, artifact_root))

    used_records: set[int] = set()
    used_evidence: set[Path] = set()
    for (capability_id, scenario_id), (
        expected_directions,
        _expected_status,
        expected_profile,
        expected_stack,
        expected_runner_scenario,
        expected_requires,
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
                    capability_id,
                    direction,
                    expected_profile,
                    expected_stack,
                    expected_runner_scenario,
                    scenario_id,
                    expected_requires,
                    indexed_evidence,
                    used_evidence,
                    binary_paths,
                    artifact_root,
                )
            )
    return errors, any(
        status == ARTIFACT_SCHEMA["limited_status"] for _, status, _, _, _, _ in required.values()
    )


def fixture_manifest(expected_status: str = "passed", capability_id: str = "test.protocol",
                     profile: str = "native", requires: tuple[str, ...] = ()) -> dict[str, object]:
    if profile == "native":
        runner_scenario_id = "tcp_noise/test_scenario"
        transport_stack = ["tcp", "yamux"]
    elif profile == "private_network":
        runner_scenario_id = "private_tcp_yamux_pnet/test_scenario"
        transport_stack = ["tcp", "yamux", "pnet"]
    else:
        raise ValueError(f"unsupported fixture profile: {profile}")
    entry: dict[str, object] = {
        "scenarios": [
            {
                "id": "test_scenario",
                "runner_scenario_id": runner_scenario_id,
                "profile": profile,
                "transport_stack": transport_stack,
                "activation": "enabled",
                "registration": "registered",
                "source_case_id": "test.case",
                "requires_capabilities": list(requires),
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
            "capabilities": {capability_id: entry},
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
    root = root.resolve()
    return [
        {
            "path": path.resolve().relative_to(root).as_posix(),
            "size": path.resolve().stat().st_size,
            "sha256": sha256_file(path.resolve()),
        }
        for path in sorted(raw_evidence_paths(artifacts), key=lambda value: str(value))
    ]


def write_artifact(root: Path, manifest_path: Path, artifact_path: Path, head: str,
                   capability_id: str = "test.protocol", profile: str = "native",
                   requires: tuple[str, ...] = ()) -> None:
    artifact_root = artifact_path.parent / "interop-run"
    artifact_root.mkdir(parents=True, exist_ok=True)
    donors_root = root / "donors"
    donors_root.mkdir(exist_ok=True)
    binaries = {}
    for implementation in ("forge", "go", "rust"):
        binary = artifact_root / f"{implementation}-fixture"
        binary.write_text(f"{implementation} fixture\n")
        binaries[implementation] = binary
    timestamp = max(time.time(), float(subprocess.check_output(
        ["git", "-C", str(root), "show", "-s", "--format=%ct", "HEAD"], text=True
    ).strip()))
    if profile == "native":
        runner_scenario_id = "tcp_noise/test_scenario"
        transport_stack = ["tcp", "yamux"]
        transport = "tcp"
    elif profile == "private_network":
        runner_scenario_id = "private_tcp_yamux_pnet/test_scenario"
        transport_stack = ["tcp", "yamux", "pnet"]
        transport = PRIVATE_NETWORK_TRANSPORT
    else:
        raise ValueError(f"unsupported fixture profile: {profile}")
    pnet_key_file = root / "private-inputs" / "fixture.pnet.key"
    if profile == "private_network":
        pnet_key_file.parent.mkdir(exist_ok=True)
        # The fixture key is intentionally not recorded, logged or indexed as evidence.
        pnet_key_file.write_bytes(b"fixture-private-network-key")
    private_pnet_fingerprint = pnet_fingerprint(pnet_key_file) if profile == "private_network" else None
    private_egress = (
        PRIVATE_EGRESS_POLICY_VALUE if PRIVATE_EGRESS_POLICY_DEPENDENCY in requires else None
    )
    listener_features = "ping,autonatv1" if capability_id.startswith("protocol.autonat_v1_") else "ping"
    artifacts: list[dict] = []
    for dialer, listener in (("forge", "go"), ("go", "forge")):
        stem = f"{dialer}-to-{listener}"
        result_file = artifact_root / f"{stem}.json"
        listener_result_file = artifact_root / f"{stem}-listener.json"
        command_log = artifact_root / f"{stem}-dial.log"
        listener_log = artifact_root / f"{stem}-listen.log"
        result_payload = {
            "implementation": dialer,
            "role": "dialer",
            "scenario": "test_scenario",
            "status": "ok",
        }
        listener_payload = {"implementation": listener, "role": "listener", "status": "ok"}
        if profile == "private_network":
            result_payload.update({
                "pnet_enabled": True,
                "negotiated_pnet": True,
                "pnet_fingerprint": private_pnet_fingerprint,
            })
            listener_payload.update({
                "pnet_enabled": True,
                "negotiated_pnet": True,
                "pnet_fingerprint": private_pnet_fingerprint,
            })
        if private_egress is not None:
            result_payload.update({
                "private_egress_policy": private_egress,
                "egress_policy_enforced": True,
            })
            listener_payload.update({
                "private_egress_policy": private_egress,
                "egress_policy_enforced": True,
            })
        result_file.write_text(json.dumps(result_payload) + "\n")
        listener_result_file.write_text(json.dumps(listener_payload) + "\n")
        command_log.write_text("dial finished\n")
        listener_log.write_text("listener stopped\n")
        dial_command = [
            str(binaries[dialer]), "dial", "--scenario", "test_scenario", "--peer-id", "peer",
            "--addr", "/ip4/127.0.0.1/tcp/1", "--result-file", str(result_file),
            "--store-dir", str(artifact_root / f"{stem}-dial-store"), "--transport", transport,
        ]
        listener_command = [
            str(binaries[listener]), "listen", "--ready-file", str(artifact_root / f"{stem}-ready.json"),
            "--stop-file", str(artifact_root / f"{stem}.stop"),
            "--store-dir", str(artifact_root / f"{stem}-listen-store"), "--features", listener_features,
            "--transport", transport, "--scenario", "test_scenario", "--result-file", str(listener_result_file),
        ]
        if profile == "private_network":
            dial_command.extend(["--pnet-key-file", str(pnet_key_file)])
            listener_command.extend(["--pnet-key-file", str(pnet_key_file)])
        if private_egress is not None:
            dial_command.extend(["--private-egress-policy", private_egress])
            listener_command.extend(["--private-egress-policy", private_egress])
        artifacts.append({
            "dialer": dialer,
            "listener": listener,
            "scenario": "test_scenario",
            "runner_scenario_id": runner_scenario_id,
            "acceptance_scenario_id": "test_scenario",
            "profile": profile,
            "transport_stack": transport_stack,
            "transport": transport,
            "effective_configuration": {
                "activation": "enabled",
                "profile": profile,
                "transport_stack": transport_stack,
                "dialer": launcher_execution_description(
                    dict(zip(dial_command[2::2], dial_command[3::2])), result_payload
                ),
                "listener": launcher_execution_description(
                    dict(zip(listener_command[2::2], listener_command[3::2])), listener_payload
                ),
            },
            "result": {
                **result_payload,
                "result_file": str(result_file),
                "attempts": [{
                    "kind": "dial",
                    "scenario_id": "test_scenario",
                    "command": dial_command,
                    "log_file": str(command_log),
                    "exit_code": 0,
                }],
            },
            "listener_process": {
                "command": listener_command,
                "log_file": str(listener_log),
                "terminal_status": {"exit_code": 0, "termination": "graceful"},
            },
            "listener_result_file": str(listener_result_file),
            "listener_result": listener_payload,
        })
    identity = fixture_identity(root, head)
    artifact = {
        "schema_version": 2,
        "runner_argv": [
            str(Path(sys.executable).resolve()), str((root / CANONICAL_RUNNER).resolve()),
            "--enabled", "ON",
            "--forge-fixture", str(binaries["forge"]),
            "--source-dir", str((root / CANONICAL_RUNNER).parent.resolve()),
            "--build-dir", str(artifact_path.parent.resolve()),
            "--forge-root", str(root.resolve()),
            "--donors-root", str(donors_root.resolve()),
            "--acceptance-manifest", str(manifest_path.resolve()),
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
            "tools": {
                "python": {
                    "path": str(Path(sys.executable).resolve()),
                    "version_output": subprocess.check_output(
                        [str(Path(sys.executable).resolve()), "--version"], text=True
                    ).strip(),
                },
            },
            "binaries": {
                implementation: {"path": str(binary), "sha256": sha256_file(binary)}
                for implementation, binary in binaries.items()
            },
            "runner_inputs": {
                "source_dir": str((root / CANONICAL_RUNNER).parent.resolve()),
                "build_dir": str(artifact_path.parent.resolve()),
                "forge_root": str(root.resolve()),
                "donors_root": str(donors_root.resolve()),
                "acceptance_manifest": str(manifest_path.resolve()),
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


def expect_rejected(root: Path, manifest_path: Path, artifact_path: Path, head: str, label: str,
                    expected_error: Optional[str] = None) -> bool:
    errors, _ = validate(root, manifest_path, artifact_path, head)
    if errors:
        if expected_error is None or any(expected_error in error for error in errors):
            return True
        print(
            f"self-test failed: {label} did not report {expected_error!r}: {errors}",
            file=sys.stderr,
        )
        return False
    print(f"self-test failed: {label} was accepted", file=sys.stderr)
    return False


def replace_option(command: list[str], option: str, value: str) -> None:
    index = command.index(option)
    command[index + 1] = value


def remove_option(command: list[str], option: str) -> None:
    index = command.index(option)
    del command[index:index + 2]


def rewrite_result_evidence(record: dict) -> None:
    result = record["result"]
    Path(result["result_file"]).write_text(
        json.dumps({key: value for key, value in result.items() if key not in {"result_file", "attempts"}}) + "\n"
    )
    listener_result_file = record.get("listener_result_file")
    if isinstance(listener_result_file, str):
        Path(listener_result_file).write_text(json.dumps(record["listener_result"]) + "\n")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        runner_path = root / CANONICAL_RUNNER
        manifest_path = root / "manifest.json"
        artifact_path = root / "artifacts" / "interop-artifacts.json"
        runner_path.parent.mkdir(parents=True)
        runner_path.write_text("# fixture runner\n")
        (root / ".gitignore").write_text("artifacts/\nprivate-inputs/\nprivate-*.json\n__pycache__/\n")
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
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        receipt = {
            "schema_version": 2,
            "runner_argv": artifact["runner_argv"],
            "started_at_unix": artifact["started_at_unix"] - 1,
            "finished_at_unix": artifact["finished_at_unix"] + 1,
            "returncode": 0,
            "invocation_directory": str(artifact_path.parent.resolve()),
            "artifact_path": str(artifact_path.resolve()),
            "artifact_sha256": sha256_file(artifact_path),
        }
        errors, _ = validate(root, manifest_path, artifact_path, head, receipt)
        if errors:
            print("self-test failed: in-process promotion receipt was not accepted", file=sys.stderr)
            return 1
        receipt["runner_argv"] = ["/bin/false"]
        errors, _ = validate(root, manifest_path, artifact_path, head, receipt)
        if not errors:
            print("self-test failed: forged promotion receipt argv was accepted", file=sys.stderr)
            return 1
        receipt["runner_argv"] = artifact["runner_argv"]
        receipt["invocation_directory"] = str(root.resolve())
        errors, _ = validate(root, manifest_path, artifact_path, head, receipt)
        if not errors:
            print("self-test failed: forged promotion receipt directory was accepted", file=sys.stderr)
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["runner_argv"] = artifact["runner_argv"][:-2]
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "incomplete runner argv"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["runner_argv"][0] = "/bin/false"
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "forged runner executable"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["runner_argv"].extend(["--provenance-only", "1"])
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "provenance-only runner argv"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["artifacts"][0]["result"]["attempts"][0]["command"][0] = "/bin/false"
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "false dial executable"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        artifact["fixture_provenance"]["binaries"]["forge"]["sha256"] = "0" * 64
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "bad binary provenance hash"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        result_path = Path(artifact["artifacts"][0]["result"]["result_file"])
        result_path.write_text("not JSON\n")
        artifact["evidence_index"] = build_evidence_index(Path(artifact["artifact_root"]).resolve(), artifact["artifacts"])
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "non-JSON result evidence"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        result_path = Path(artifact["artifacts"][0]["result"]["result_file"])
        result_path.write_text(json.dumps({"status": "ok", "scenario": "different"}) + "\n")
        artifact["evidence_index"] = build_evidence_index(Path(artifact["artifact_root"]).resolve(), artifact["artifacts"])
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "mismatched result evidence"):
            return 1

        write_artifact(root, manifest_path, artifact_path, head)
        artifact = load_json(artifact_path)
        assert isinstance(artifact, dict)
        result = artifact["artifacts"][0]["result"]
        result["error"] = "fixture reported failure"
        result_path = Path(result["result_file"])
        result_path.write_text(json.dumps({key: value for key, value in result.items() if key not in {"result_file", "attempts"}}) + "\n")
        artifact["evidence_index"] = build_evidence_index(Path(artifact["artifact_root"]).resolve(), artifact["artifacts"])
        artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(root, manifest_path, artifact_path, head, "contradictory failure text"):
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

        private_manifest_path = root / "private-manifest.json"
        private_artifact_path = root / "artifacts" / "private" / "interop-artifacts.json"
        private_requires = (PRIVATE_NETWORK_PSK_DEPENDENCY,)
        private_manifest_path.write_text(json.dumps(fixture_manifest(
            capability_id="test.private_protocol",
            profile="private_network",
            requires=private_requires,
        )))
        write_artifact(
            root,
            private_manifest_path,
            private_artifact_path,
            head,
            capability_id="test.private_protocol",
            profile="private_network",
            requires=private_requires,
        )
        private_errors, private_limitations = validate(root, private_manifest_path, private_artifact_path, head)
        if private_errors or private_limitations:
            print("self-test failed: private-network launcher/result artifact was not accepted", file=sys.stderr)
            return 1

        artifact = load_json(private_artifact_path)
        assert isinstance(artifact, dict)
        mismatch_record = artifact["artifacts"][0]
        assert isinstance(mismatch_record, dict)
        mismatch_record["result"]["pnet_fingerprint"] = "b" * 64
        mismatch_record["effective_configuration"]["dialer"]["pnet_fingerprint"] = "b" * 64
        rewrite_result_evidence(mismatch_record)
        artifact["evidence_index"] = build_evidence_index(
            Path(artifact["artifact_root"]).resolve(), artifact["artifacts"]
        )
        private_artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(
            root,
            private_manifest_path,
            private_artifact_path,
            head,
            "PNET fingerprint that does not match the PSK bytes",
            "private network dialer fingerprint does not match the configured PSK bytes",
        ):
            return 1

        write_artifact(
            root,
            private_manifest_path,
            private_artifact_path,
            head,
            capability_id="test.private_protocol",
            profile="private_network",
            requires=private_requires,
        )
        artifact = load_json(private_artifact_path)
        assert isinstance(artifact, dict)
        for record in artifact["artifacts"]:
            assert isinstance(record, dict)
            record["transport"] = "tcp"
            replace_option(record["result"]["attempts"][0]["command"], "--transport", "tcp")
            replace_option(record["listener_process"]["command"], "--transport", "tcp")
            record["effective_configuration"]["dialer"]["transport"] = "tcp"
            record["effective_configuration"]["listener"]["transport"] = "tcp"
        private_artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(
            root,
            private_manifest_path,
            private_artifact_path,
            head,
            "private profile over ordinary tcp",
            "private network commands must use --transport tcp-pnet",
        ):
            return 1

        write_artifact(
            root,
            private_manifest_path,
            private_artifact_path,
            head,
            capability_id="test.private_protocol",
            profile="private_network",
            requires=private_requires,
        )
        artifact = load_json(private_artifact_path)
        assert isinstance(artifact, dict)
        for record in artifact["artifacts"]:
            assert isinstance(record, dict)
            remove_option(record["result"]["attempts"][0]["command"], "--pnet-key-file")
            remove_option(record["listener_process"]["command"], "--pnet-key-file")
            for endpoint in ("dialer", "listener"):
                record["effective_configuration"][endpoint].pop("pnet_key_file")
                for field in PRIVATE_PNET_RESULT_FIELDS:
                    record["effective_configuration"][endpoint].pop(field)
            for field in PRIVATE_PNET_RESULT_FIELDS:
                record["result"].pop(field)
                record["listener_result"].pop(field)
            rewrite_result_evidence(record)
        artifact["evidence_index"] = build_evidence_index(
            Path(artifact["artifact_root"]).resolve(), artifact["artifacts"]
        )
        private_artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(
            root,
            private_manifest_path,
            private_artifact_path,
            head,
            "PNET profile label without PNET command/result proof",
            "private network commands must reference the same existing --pnet-key-file",
        ):
            return 1

        autonat_manifest_path = root / "private-autonat-manifest.json"
        autonat_artifact_path = root / "artifacts" / "private-autonat" / "interop-artifacts.json"
        autonat_requires = (PRIVATE_NETWORK_PSK_DEPENDENCY, PRIVATE_EGRESS_POLICY_DEPENDENCY)
        autonat_manifest_path.write_text(json.dumps(fixture_manifest(
            capability_id="protocol.autonat_v1_client",
            profile="private_network",
            requires=autonat_requires,
        )))
        write_artifact(
            root,
            autonat_manifest_path,
            autonat_artifact_path,
            head,
            capability_id="protocol.autonat_v1_client",
            profile="private_network",
            requires=autonat_requires,
        )
        autonat_errors, autonat_limitations = validate(
            root, autonat_manifest_path, autonat_artifact_path, head
        )
        if autonat_errors or autonat_limitations:
            print("self-test failed: private AutoNAT launcher/result artifact was not accepted", file=sys.stderr)
            return 1
        artifact = load_json(autonat_artifact_path)
        assert isinstance(artifact, dict)
        for record in artifact["artifacts"]:
            assert isinstance(record, dict)
            remove_option(record["result"]["attempts"][0]["command"], "--private-egress-policy")
            remove_option(record["listener_process"]["command"], "--private-egress-policy")
            for endpoint in ("dialer", "listener"):
                record["effective_configuration"][endpoint].pop("private_egress_policy")
                record["effective_configuration"][endpoint].pop("egress_policy_enforced")
            record["result"].pop("private_egress_policy")
            record["result"].pop("egress_policy_enforced")
            record["listener_result"].pop("private_egress_policy")
            record["listener_result"].pop("egress_policy_enforced")
            rewrite_result_evidence(record)
        artifact["evidence_index"] = build_evidence_index(
            Path(artifact["artifact_root"]).resolve(), artifact["artifacts"]
        )
        autonat_artifact_path.write_text(json.dumps(artifact))
        if not expect_rejected(
            root,
            autonat_manifest_path,
            autonat_artifact_path,
            head,
            "private AutoNAT without executable egress policy",
            "private Internet policy requires dialer --private-egress-policy",
        ):
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
        "stage6 acceptance checker self-test ok: canonical argv, forged executables, missing, stale, "
        "nonzero, failures, result parsing, evidence hashes/reuse, private PNET fingerprint/egress proofs, dirty tree, "
        "empty scenarios and limitations covered"
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
            status = "FAILED" if error == "canonical runner failures must be exactly empty" else "NOT_RUN"
            print(f"{status}: {error}", file=sys.stderr)
        return 1
    if has_documented_limitations:
        print("CONSISTENT_WITH_DOCUMENTED_LIMITATIONS: standalone artifact consistency only; not promotion")
    else:
        print("CONSISTENT: standalone artifact consistency only; CMake promotion wrapper owns PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
