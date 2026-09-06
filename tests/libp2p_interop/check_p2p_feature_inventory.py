#!/usr/bin/env python3
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path


REQUIRED_FIELDS = {
    "id",
    "state",
    "owner",
    "normal_activation",
    "configuration",
    "resource_ownership",
    "persistence",
    "maintenance",
    "diagnostics",
    "intended_disposition",
    "builtin_protocols",
    "capabilities",
    "evidence",
}

EVIDENCE_LAYERS = {
    "codec",
    "state_machine",
    "raw_node",
    "official_plugin",
    "restart_scale",
    "adversarial",
    "donor_interop",
}

REQUIRED_OWNERS = {
    "net.p2p.node": {
        "kind": "library",
        "path": "libraries/net/p2p",
        "target": "forge_net_p2p",
        "component": "net_p2p",
        "module_prefix": "forge.net.p2p",
        "module_root": "net/p2p",
    },
    "plugin.p2p.node": {
        "kind": "plugin",
        "path": "plugins/p2p/node",
        "target": "forge_plugins_p2p_node",
        "component": "plugins_p2p_node",
        "module_prefix": "forge.plugins.p2p.node",
        "module_root": "plugins/p2p/node",
    },
    "plugin.p2p.resolver": {
        "kind": "plugin",
        "path": "plugins/p2p/resolver",
        "target": "forge_plugins_p2p_resolver",
        "component": "plugins_p2p_resolver",
        "module_prefix": "forge.plugins.p2p.resolver",
        "module_root": "plugins/p2p/resolver",
    },
    "plugin.p2p.pubsub": {
        "kind": "plugin",
        "path": "plugins/p2p/pubsub",
        "target": "forge_plugins_p2p_pubsub",
        "component": "plugins_p2p_pubsub",
        "module_prefix": "forge.plugins.p2p.pubsub",
        "module_root": "plugins/p2p/pubsub",
    },
    "plugin.p2p.diagnostics": {
        "kind": "plugin",
        "path": "plugins/p2p/diagnostics",
        "target": "forge_plugins_p2p_diagnostics",
        "component": "plugins_p2p_diagnostics",
        "module_prefix": "forge.plugins.p2p.diagnostics",
        "module_root": "plugins/p2p/diagnostics",
    },
    "application": {"kind": "external"},
    "none": {"kind": "none"},
}


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def extract_namespace_names(source: str, namespace: str, declaration: str) -> set[str]:
    match = re.search(rf"namespace {namespace}\s*\{{(?P<body>.*?)\n\}}", source, re.DOTALL)
    if match is None:
        return set()
    return set(re.findall(declaration, match.group("body")))


def has_registered_live_interop(case: object) -> bool:
    if not isinstance(case, dict):
        return False
    scenarios = case.get("forge_live_scenario", [])
    tests = case.get("forge_tests", [])
    if case.get("mapping_state") != "mapped":
        return False
    if not isinstance(scenarios, list) or not scenarios or any(
        not isinstance(selector, dict)
        or set(selector) != {"profile", "scenario"}
        or not isinstance(selector.get("profile"), str)
        or not isinstance(selector.get("scenario"), str)
        for selector in scenarios
    ):
        return False
    if not isinstance(tests, list):
        return False
    return any(
        isinstance(reference, str)
        and reference.strip().split()[0] == "test_forge_libp2p_interop"
        for reference in tests
        if reference.strip()
    )


def public_surface_snapshot(
    root: Path, owner: dict[str, str]
) -> tuple[list[str], list[str], str, list[str]]:
    public_root = root / owner["path"] / "include/forge" / owner["module_root"]
    sources = sorted(public_root.glob("*.cppm"))
    headers = sorted([*public_root.glob("*.hpp"), *public_root.glob("*.h")])
    nested = sorted(
        source.relative_to(root).as_posix()
        for source in public_root.rglob("*")
        if source.is_file()
        and source.suffix in {".cppm", ".hpp", ".h"}
        and source.parent != public_root
    )
    digest = hashlib.sha256()
    modules: list[str] = []
    for source in [*sources, *headers]:
        modules.extend(
            re.findall(
                r"(?m)^(?:export\s+)?module\s+([A-Za-z0-9_.]+)\s*;",
                source.read_text(),
            )
        )
        digest.update(source.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(source.read_bytes())
        digest.update(b"\0")
    header_paths = [header.relative_to(root).as_posix() for header in headers]
    return modules, header_paths, digest.hexdigest(), nested


def main() -> int:
    if len(sys.argv) not in {5, 6}:
        print(
            "usage: check_p2p_feature_inventory.py "
            "SOURCE_ROOT INVENTORY DONOR_CAPABILITIES DONOR_CASES [DONORS_ROOT]",
            file=sys.stderr,
        )
        return 2

    root = Path(sys.argv[1]).resolve()
    inventory_path = Path(sys.argv[2]).resolve()
    capability_path = Path(sys.argv[3]).resolve()
    donor_path = Path(sys.argv[4]).resolve()
    donors_root = Path(sys.argv[5]).resolve() if len(sys.argv) == 6 and sys.argv[5] else None
    errors: list[str] = []
    try:
        inventory = json.loads(inventory_path.read_text(), object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: inventory: {error}", file=sys.stderr)
        return 1
    try:
        donor = json.loads(donor_path.read_text(), object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: donor matrix: {error}", file=sys.stderr)
        return 1
    try:
        capability_inventory = json.loads(
            capability_path.read_text(), object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: donor capability inventory: {error}", file=sys.stderr)
        return 1
    if not isinstance(inventory, dict):
        print("ERROR: inventory: top-level value must be an object", file=sys.stderr)
        return 1
    if not isinstance(donor, dict):
        print("ERROR: donor matrix: top-level value must be an object", file=sys.stderr)
        return 1
    if not isinstance(capability_inventory, dict):
        print(
            "ERROR: donor capability inventory: top-level value must be an object",
            file=sys.stderr,
        )
        return 1

    if inventory.get("schema_version") != 1:
        errors.append("inventory: unsupported schema_version")
    if inventory.get("claim_scope") != "source_structure_and_declared_evidence_only":
        errors.append("inventory: claim_scope must not imply executed runtime evidence")
    if inventory.get("donor_capabilities") != capability_path.name:
        errors.append("inventory: donor_capabilities must reference the donor-first manifest")

    expected_states = {"live", "manual-only", "partial", "stub", "orphan", "unverified"}
    allowed_states_value = inventory.get("allowed_states", [])
    if not isinstance(allowed_states_value, list) or any(
        not isinstance(value, str) for value in allowed_states_value
    ):
        errors.append("inventory: allowed_states must be an array of strings")
        allowed_states: set[str] = set()
    else:
        allowed_states = set(allowed_states_value)
    if allowed_states != expected_states:
        errors.append("inventory: allowed_states must match the accepted hardening vocabulary")

    owners = inventory.get("owners", {})
    if not isinstance(owners, dict):
        errors.append("inventory: owners must be an object")
        owners = {}
    elif owners != REQUIRED_OWNERS:
        errors.append("inventory: owners must match the canonical P2P target/component/module mapping")
    root_cmake = (root / "CMakeLists.txt").read_text()
    package_config = (root / "cmake/ForgeConfig.cmake.in").read_text()
    for owner_id, owner in REQUIRED_OWNERS.items():
        kind = owner.get("kind", "")
        if kind in {"library", "plugin"}:
            path = owner.get("path", "")
            relative_path = Path(path)
            if (
                not path
                or relative_path.is_absolute()
                or ".." in relative_path.parts
                or not (root / relative_path).is_dir()
            ):
                errors.append(f"owner {owner_id}: path must reference a repository directory")
            for field in ("target", "component", "module_prefix", "module_root"):
                if not owner.get(field, ""):
                    errors.append(f"owner {owner_id}: missing {field}")
            cmake_path = root / relative_path / "CMakeLists.txt"
            cmake_source = cmake_path.read_text() if cmake_path.is_file() else ""
            target = owner.get("target", "")
            target_declaration = rf"add_library\s*\(\s*{re.escape(target)}(?:\s|\))"
            if not cmake_path.is_file() or not re.search(target_declaration, cmake_source):
                errors.append(f"owner {owner_id}: target is not declared by its CMakeLists.txt")
            module_root = owner.get("module_root", "")
            module_registration = (
                rf"forge_target_modules_at\s*\(\s*{re.escape(target)}\s+"
                rf"{re.escape(module_root)}\s*\)"
            )
            if target and module_root and not re.search(module_registration, cmake_source):
                errors.append(
                    f"owner {owner_id}: public modules are not registered to the canonical target/root"
                )
            component = owner.get("component", "")
            if not re.search(rf"(?m)^\s*{re.escape(component)}\s*$", root_cmake):
                errors.append(f"owner {owner_id}: component is not listed in FORGE_BUILT_COMPONENTS")
            if f'"{component}"' not in package_config:
                errors.append(f"owner {owner_id}: component is not handled by ForgeConfig.cmake.in")
            module_prefix = owner.get("module_prefix", "")
            module_sources = list((root / relative_path).glob("include/**/*.cppm"))
            declared_modules = {
                module
                for source in module_sources
                for module in re.findall(
                    r"(?m)^(?:export\s+)?module\s+([A-Za-z0-9_.]+)\s*;",
                    source.read_text(),
                )
            }
            if not declared_modules:
                errors.append(f"owner {owner_id}: no public modules were discovered")
            elif module_prefix and any(
                module != module_prefix and not module.startswith(f"{module_prefix}.")
                for module in declared_modules
            ):
                errors.append(f"owner {owner_id}: public module outside canonical module_prefix")
        elif kind not in {"external", "none"}:
            errors.append(f"owner {owner_id}: unknown kind {kind!r}")

    surface_snapshots = inventory.get("public_surface_snapshots", {})
    repository_owners = {
        owner_id for owner_id, owner in REQUIRED_OWNERS.items() if owner["kind"] in {"library", "plugin"}
    }
    if not isinstance(surface_snapshots, dict):
        errors.append("inventory: public_surface_snapshots must be an object")
        surface_snapshots = {}
    elif set(surface_snapshots) != repository_owners:
        errors.append("inventory: public_surface_snapshots must cover every repository P2P owner exactly once")

    donor_cases = donor.get("cases", [])
    if not isinstance(donor_cases, list):
        errors.append("donor matrix: cases must be an array")
        donor_cases = []
    donor_by_id = {
        case.get("id", ""): case
        for case in donor_cases
        if isinstance(case, dict) and isinstance(case.get("id", ""), str)
    }
    donor_ids = set(donor_by_id)
    if donor.get("status_scope") != "donor_case_coverage_only":
        errors.append("donor matrix: status_scope must prevent production interpretation")
    if donor.get("execution_scope") != "registered_optional_tests_not_current_results":
        errors.append("donor matrix: execution_scope must not imply current interop results")
    if donor.get("production_inventory") != inventory_path.name:
        errors.append("donor matrix: production_inventory must reference the feature inventory")
    if donor.get("capability_inventory") != capability_path.name:
        errors.append("donor matrix: capability_inventory must reference the donor-first manifest")

    if capability_inventory.get("schema_version") != 1:
        errors.append("donor capabilities: unsupported schema_version")
    if capability_inventory.get("claim_scope") != "donor_first_capability_classification_only":
        errors.append("donor capabilities: claim_scope must not imply implementation support")
    if capability_inventory.get("donor_matrix") != donor_path.name:
        errors.append("donor capabilities: donor_matrix must reference the donor case matrix")

    expected_support_requirements = {"required", "optional", "deferred", "excluded"}
    support_requirement_values = capability_inventory.get("allowed_support_requirements", [])
    if not isinstance(support_requirement_values, list) or any(
        not isinstance(value, str) for value in support_requirement_values
    ):
        errors.append("donor capabilities: allowed_support_requirements must be an array of strings")
        allowed_support_requirements: set[str] = set()
    else:
        allowed_support_requirements = set(support_requirement_values)
    if allowed_support_requirements != expected_support_requirements:
        errors.append("donor capabilities: allowed_support_requirements must match the accepted vocabulary")

    expected_default_activations = {"enabled", "opt_in", "not_applicable"}
    default_activation_values = capability_inventory.get("allowed_default_activations", [])
    if not isinstance(default_activation_values, list) or any(
        not isinstance(value, str) for value in default_activation_values
    ):
        errors.append("donor capabilities: allowed_default_activations must be an array of strings")
        allowed_default_activations: set[str] = set()
    else:
        allowed_default_activations = set(default_activation_values)
    if allowed_default_activations != expected_default_activations:
        errors.append("donor capabilities: allowed_default_activations must match the accepted vocabulary")

    expected_interop_applicability = {
        "go_and_rust",
        "go_only",
        "go_only_rust_limited",
        "not_applicable",
    }
    interop_applicability_values = capability_inventory.get("allowed_interop_applicability", [])
    if not isinstance(interop_applicability_values, list) or any(
        not isinstance(value, str) for value in interop_applicability_values
    ):
        errors.append("donor capabilities: allowed_interop_applicability must be an array of strings")
        allowed_interop_applicability: set[str] = set()
    else:
        allowed_interop_applicability = set(interop_applicability_values)
    if allowed_interop_applicability != expected_interop_applicability:
        errors.append("donor capabilities: allowed_interop_applicability must match the accepted vocabulary")

    expected_decisions = {
        "current",
        "stage_6",
        "stage_7",
        "stage_9",
        "future_profile",
        "legacy_rejected",
        "test_only",
        "application_owned",
        "external_component",
    }
    decision_values = capability_inventory.get("allowed_decisions", [])
    if not isinstance(decision_values, list) or any(
        not isinstance(value, str) for value in decision_values
    ):
        errors.append("donor capabilities: allowed_decisions must be an array of strings")
        allowed_decisions: set[str] = set()
    else:
        allowed_decisions = set(decision_values)
    if allowed_decisions != expected_decisions:
        errors.append("donor capabilities: allowed_decisions must match the accepted roadmap vocabulary")

    profiles = capability_inventory.get("profiles", {})
    if not isinstance(profiles, dict) or not profiles:
        errors.append("donor capabilities: profiles must be a non-empty object")
        profiles = {}
    profile_capability_locks: dict[str, set[str]] = {}
    for profile_id, profile in profiles.items():
        if not isinstance(profile_id, str) or not profile_id:
            errors.append("donor capabilities: profile ids must be non-empty strings")
            continue
        if not isinstance(profile, dict) or set(profile) != {
            "description",
            "release_gate",
            "capability_ids",
        }:
            errors.append(f"donor capabilities: profile {profile_id!r} has invalid shape")
            continue
        if any(
            not isinstance(profile[field], str) or not profile[field].strip()
            for field in ("description", "release_gate")
        ):
            errors.append(f"donor capabilities: profile {profile_id!r} fields must be non-empty strings")
        locked_ids = profile.get("capability_ids", [])
        if not isinstance(locked_ids, list) or any(
            not isinstance(capability_id, str) or not capability_id.strip()
            for capability_id in locked_ids
        ):
            errors.append(
                f"donor capabilities: profile {profile_id!r} capability_ids must be strings"
            )
            locked_ids = []
        if len(set(locked_ids)) != len(locked_ids):
            errors.append(
                f"donor capabilities: profile {profile_id!r} capability_ids must be unique"
            )
        profile_capability_locks[profile_id] = set(locked_ids)

    donor_revisions = donor.get("donor_revisions", {})
    capability_revisions = capability_inventory.get("donor_revisions", {})
    if not isinstance(capability_revisions, dict) or capability_revisions != donor_revisions:
        errors.append("donor capabilities: donor_revisions must exactly match the donor case matrix")
        capability_revisions = {}

    required_capability_fields = {
        "id",
        "category",
        "profiles",
        "support_requirement",
        "default_activation",
        "interop_applicability",
        "decision",
        "forge_feature_ids",
        "donor_sources",
        "rationale",
    }
    capability_ids: set[str] = set()
    mapped_feature_coverage: Counter[str] = Counter()
    profile_coverage: Counter[str] = Counter()
    classified_profile_capabilities: dict[str, set[str]] = {
        profile_id: set() for profile_id in profiles
    }
    capabilities = capability_inventory.get("capabilities", [])
    if not isinstance(capabilities, list):
        errors.append("donor capabilities: capabilities must be an array")
        capabilities = []
    for capability in capabilities:
        if not isinstance(capability, dict):
            errors.append("donor capabilities: every capability must be an object")
            continue
        capability_id = capability.get("id", "")
        if not isinstance(capability_id, str) or not capability_id:
            errors.append("donor capabilities: capability without id")
            continue
        if capability_id in capability_ids:
            errors.append(f"donor capabilities: duplicate capability id {capability_id!r}")
        capability_ids.add(capability_id)
        missing = required_capability_fields - capability.keys()
        if missing:
            errors.append(f"donor capability {capability_id}: missing fields {sorted(missing)}")
            continue

        category = capability.get("category")
        rationale = capability.get("rationale")
        origin = capability.get("origin", "libp2p")
        support_requirement = capability.get("support_requirement")
        default_activation = capability.get("default_activation")
        interop_applicability = capability.get("interop_applicability")
        decision = capability.get("decision")
        capability_profiles = capability.get("profiles", [])
        feature_mappings = capability.get("forge_feature_ids", [])
        donor_sources = capability.get("donor_sources", [])
        if not isinstance(category, str) or not category.strip():
            errors.append(f"donor capability {capability_id}: category must be a non-empty string")
        if not isinstance(rationale, str) or not rationale.strip():
            errors.append(f"donor capability {capability_id}: rationale must be a non-empty string")
        if origin not in {"libp2p", "forge_extension"}:
            errors.append(f"donor capability {capability_id}: unknown origin {origin!r}")
        if support_requirement not in allowed_support_requirements:
            errors.append(f"donor capability {capability_id}: unknown support_requirement {support_requirement!r}")
        if default_activation not in allowed_default_activations:
            errors.append(f"donor capability {capability_id}: unknown default_activation {default_activation!r}")
        if interop_applicability not in allowed_interop_applicability:
            errors.append(
                f"donor capability {capability_id}: unknown interop_applicability "
                f"{interop_applicability!r}"
            )
        if decision not in allowed_decisions:
            errors.append(f"donor capability {capability_id}: unknown decision {decision!r}")
        if not isinstance(capability_profiles, list) or not capability_profiles or any(
            not isinstance(profile, str) or profile not in profiles for profile in capability_profiles
        ):
            errors.append(f"donor capability {capability_id}: profiles must reference known profiles")
            capability_profiles = []
        if len(set(capability_profiles)) != len(capability_profiles):
            errors.append(f"donor capability {capability_id}: profiles must be unique")
        profile_coverage.update(capability_profiles)
        for profile_id in capability_profiles:
            classified_profile_capabilities[profile_id].add(capability_id)
        if not isinstance(feature_mappings, list) or any(
            not isinstance(feature_id, str) or not feature_id.strip()
            for feature_id in feature_mappings
        ):
            errors.append(f"donor capability {capability_id}: forge_feature_ids must be strings")
            feature_mappings = []
        if len(set(feature_mappings)) != len(feature_mappings):
            errors.append(f"donor capability {capability_id}: forge_feature_ids must be unique")
        mapped_feature_coverage.update(feature_mappings)
        if not isinstance(donor_sources, list) or any(
            not isinstance(source, str) or not source.strip() for source in donor_sources
        ):
            errors.append(f"donor capability {capability_id}: donor_sources must be strings")
            donor_sources = []
        if origin == "libp2p" and not donor_sources:
            errors.append(f"donor capability {capability_id}: libp2p origin needs donor_sources")
        for source in donor_sources:
            relative = Path(source)
            if relative.is_absolute() or ".." in relative.parts:
                errors.append(f"donor capability {capability_id}: invalid donor source {source!r}")
            elif len(relative.parts) < 3 or relative.parts[0] != "donors":
                errors.append(
                    f"donor capability {capability_id}: donor source must start with donors/<repo>/"
                )
            elif relative.parts[1] not in capability_revisions:
                errors.append(
                    f"donor capability {capability_id}: donor repository is not pinned: {relative.parts[1]}"
                )
            elif donors_root is not None and not (
                donors_root / Path(*relative.parts[1:])
            ).is_file():
                errors.append(
                    f"donor capability {capability_id}: donor source does not exist: {source}"
                )
        forge_sources = capability.get("forge_sources", [])
        if not isinstance(forge_sources, list) or any(
            not isinstance(source, str) or not source.strip() for source in forge_sources
        ):
            errors.append(f"donor capability {capability_id}: forge_sources must be strings")
            forge_sources = []
        if origin == "forge_extension" and not forge_sources:
            errors.append(f"donor capability {capability_id}: Forge extension needs forge_sources")
        if origin == "libp2p" and forge_sources:
            errors.append(f"donor capability {capability_id}: libp2p origin cannot use forge_sources")
        for source in forge_sources:
            relative = Path(source)
            if relative.is_absolute() or ".." in relative.parts or not (root / relative).is_file():
                errors.append(
                    f"donor capability {capability_id}: Forge source does not exist: {source}"
                )

        if decision == "current" and not feature_mappings:
            errors.append(f"donor capability {capability_id}: current decision needs a Forge feature mapping")
        if decision in {"stage_6", "stage_7", "stage_9"}:
            branch = capability.get("planned_branch")
            if not isinstance(branch, str) or not branch.startswith("forge-p2p-"):
                errors.append(f"donor capability {capability_id}: planned decision needs a P2P branch")
        elif "planned_branch" in capability:
            errors.append(f"donor capability {capability_id}: planned_branch is only valid for a staged decision")
        if support_requirement == "deferred" and decision not in {"stage_9", "future_profile"}:
            errors.append(f"donor capability {capability_id}: deferred support_requirement needs deferred decision")
        if support_requirement == "excluded" and decision not in {
            "legacy_rejected",
            "test_only",
            "application_owned",
        }:
            errors.append(f"donor capability {capability_id}: excluded support_requirement has active decision")
        if support_requirement in {"required", "optional"} and decision in {
            "legacy_rejected",
            "test_only",
            "application_owned",
        }:
            errors.append(f"donor capability {capability_id}: active support_requirement has excluded decision")
        if support_requirement in {"deferred", "excluded"} and default_activation != "not_applicable":
            errors.append(
                f"donor capability {capability_id}: inactive support_requirement cannot have a default activation"
            )
        if default_activation == "not_applicable" and support_requirement in {"required", "optional"}:
            errors.append(
                f"donor capability {capability_id}: active support_requirement needs enabled or opt_in activation"
            )
        if interop_applicability != "not_applicable" and support_requirement == "excluded":
            errors.append(
                f"donor capability {capability_id}: excluded support cannot claim donor interop applicability"
            )
        if interop_applicability == "go_only_rust_limited" and "Rust" not in rationale:
            errors.append(
                f"donor capability {capability_id}: Rust limitation must be explicit in rationale"
            )

    private_capabilities = classified_profile_capabilities.get("private_network", set())
    forbidden_private_capabilities = {
        "transport.quic_v1",
        "relay.circuit_v2_client_transport",
        "relay.autorelay_lifecycle",
        "relay.circuit_v2_service",
        "relay.dcutr",
    }
    if forbidden_private_capabilities & private_capabilities:
        errors.append(
            "donor capabilities: private_network must exclude QUIC, Relay and DCUtR "
            f"{sorted(forbidden_private_capabilities & private_capabilities)}"
        )
    if "security.private_network_psk" not in private_capabilities:
        errors.append("donor capabilities: private_network must include the transport PSK layer")
    if "reachability.private_internet_policy" not in private_capabilities:
        errors.append("donor capabilities: private_network must gate AutoNAT and UPnP behind Internet policy")
    if "connections.coordinated_dial_port_reuse" not in private_capabilities:
        errors.append("donor capabilities: private_network must retain modern coordinated dialing")
    if "connections.simultaneous_connect_legacy" in private_capabilities:
        errors.append("donor capabilities: private_network must not negotiate legacy simultaneous-connect")

    required_stage_6_opt_ins = {
        "connections.inlined_muxer_negotiation",
        "pubsub.partial_messages",
    }
    for capability in capabilities:
        if not isinstance(capability, dict) or capability.get("id") not in required_stage_6_opt_ins:
            continue
        if (
            capability.get("support_requirement") != "required"
            or capability.get("default_activation") != "opt_in"
            or capability.get("decision") != "stage_6"
        ):
            errors.append(
                f"donor capability {capability.get('id')}: Stage 6 support must be required and opt_in"
            )

    required_semantics = {
        "reachability.autonat_v1_node_lifecycle": (
            {"native", "private_network"}, "required", "opt_in", "go_and_rust", "stage_6"
        ),
        "reachability.autonat_v2_address_lifecycle": (
            {"native", "private_network"}, "required", "opt_in", "go_and_rust", "stage_6"
        ),
        "reachability.private_internet_policy": (
            {"private_network"}, "required", "opt_in", "not_applicable", "stage_6"
        ),
        "discovery.mdns_public": (
            {"native"}, "optional", "opt_in", "go_and_rust", "stage_6"
        ),
        "discovery.mdns_private_fingerprinted": (
            {"private_network"}, "optional", "opt_in", "go_only_rust_limited", "stage_6"
        ),
        "security.private_network_psk": (
            {"private_network"}, "required", "enabled", "go_and_rust", "stage_6"
        ),
        "connections.coordinated_dial_port_reuse": (
            {"native", "private_network"}, "required", "enabled", "go_and_rust", "stage_6"
        ),
        "connections.simultaneous_connect_legacy": (
            {"legacy"}, "excluded", "not_applicable", "not_applicable", "legacy_rejected"
        ),
        "protocol.autonat_v1_client": (
            {"native", "private_network"}, "required", "opt_in", "go_and_rust", "stage_6"
        ),
        "protocol.autonat_v1_service": (
            {"native", "private_network"}, "optional", "opt_in", "go_and_rust", "stage_6"
        ),
    }
    capabilities_by_id = {
        capability.get("id"): capability
        for capability in capabilities
        if isinstance(capability, dict) and isinstance(capability.get("id"), str)
    }
    for capability_id, expected in required_semantics.items():
        capability = capabilities_by_id.get(capability_id)
        if capability is None:
            errors.append(f"donor capabilities: required Stage 6 classification is missing {capability_id}")
            continue
        expected_profiles, expected_support, expected_activation, expected_interop, expected_decision = expected
        actual = (
            set(capability.get("profiles", [])),
            capability.get("support_requirement"),
            capability.get("default_activation"),
            capability.get("interop_applicability"),
            capability.get("decision"),
        )
        if actual != expected:
            errors.append(
                f"donor capability {capability_id}: semantic classification differs from the Stage 6 baseline"
            )

    symmetric_interop_ids = {
        "protocol.ping",
        "reachability.autonat_v1_node_lifecycle",
        "protocol.autonat_v1_client",
        "protocol.autonat_v1_service",
        "reachability.autonat_v2_address_lifecycle",
        "protocol.autonat_v2_client",
        "protocol.autonat_v2_service",
        "discovery.mdns_public",
        "connections.coordinated_dial_port_reuse",
        "connections.inlined_muxer_negotiation",
        "pubsub.partial_messages",
        "security.private_network_psk",
    }
    for capability_id in symmetric_interop_ids:
        capability = capabilities_by_id.get(capability_id)
        if capability is None:
            errors.append(f"donor capabilities: symmetric interop classification is missing {capability_id}")
            continue
        sources = capability.get("donor_sources", [])
        if not isinstance(sources, list) or not any(
            isinstance(source, str) and source.startswith("donors/go-") for source in sources
        ) or not any(
            isinstance(source, str) and source.startswith("donors/rust-") for source in sources
        ):
            errors.append(
                f"donor capability {capability_id}: Go and Rust donor evidence must both be pinned"
            )

    host_local_policy_ids = {
        "reachability.private_internet_policy",
        "security.connection_gater",
        "resource.memory_fd_transient_service_scopes",
        "dialing.happy_eyeballs",
        "dialing.udp_ipv6_black_hole_detection",
        "events.host_state",
        "nat.upnp_mapping",
        "reachability.observed_address_manager",
    }
    for capability_id in host_local_policy_ids:
        capability = capabilities_by_id.get(capability_id)
        if capability is None:
            errors.append(f"donor capabilities: host-local policy classification is missing {capability_id}")
        elif capability.get("interop_applicability") != "not_applicable":
            errors.append(
                f"donor capability {capability_id}: host-local orchestration cannot claim bilateral interop"
            )

    gossipsub_branch_owners = {
        "pubsub.gossipsub_v1_0_v1_1": "forge-p2p-gossipsub-scoring-v1",
        "pubsub.gossipsub_v1_2": "forge-p2p-gossipsub-extensions-v1",
        "pubsub.gossipsub_v1_3": "forge-p2p-gossipsub-extensions-v1",
        "pubsub.partial_messages": "forge-p2p-gossipsub-extensions-v1",
    }
    for capability_id, expected_branch in gossipsub_branch_owners.items():
        capability = capabilities_by_id.get(capability_id)
        if capability is None:
            errors.append(f"donor capabilities: GossipSub branch owner is missing {capability_id}")
        elif capability.get("planned_branch") != expected_branch:
            errors.append(
                f"donor capability {capability_id}: expected GossipSub owner {expected_branch}"
            )

    missing_profiles = set(profiles) - set(profile_coverage)
    if missing_profiles:
        errors.append(f"donor capabilities: profiles without capabilities {sorted(missing_profiles)}")
    for profile_id, locked_ids in profile_capability_locks.items():
        classified_ids = classified_profile_capabilities.get(profile_id, set())
        if locked_ids != classified_ids:
            errors.append(
                f"donor capabilities: profile {profile_id!r} scope lock differs; "
                f"missing {sorted(locked_ids - classified_ids)}, "
                f"unlocked {sorted(classified_ids - locked_ids)}"
            )
    duplicate_feature_mappings = sorted(
        feature_id for feature_id, count in mapped_feature_coverage.items() if count != 1
    )
    if duplicate_feature_mappings:
        errors.append(
            "donor capabilities: Forge feature mappings must be owned exactly once "
            f"{duplicate_feature_mappings}"
        )
    required_feature_ids = set(mapped_feature_coverage)

    feature_ids: set[str] = set()
    builtin_coverage: Counter[str] = Counter()
    capability_coverage: Counter[str] = Counter()
    negotiated_protocol_coverage: Counter[str] = Counter()
    public_component_coverage: Counter[str] = Counter()
    test_manifest = (root / "tests/CMakeLists.txt").read_text()
    registered_tests = set(
        re.findall(
            r"add_(?:executable|custom_target)\s*\(\s*([A-Za-z0-9_]+)",
            test_manifest,
            re.DOTALL,
        )
    )
    registered_tests.update(
        re.findall(r"add_test\s*\(\s*NAME\s+([A-Za-z0-9_]+)", test_manifest, re.DOTALL)
    )

    features = inventory.get("features", [])
    if not isinstance(features, list):
        errors.append("inventory: features must be an array")
        features = []
    for feature in features:
        if not isinstance(feature, dict):
            errors.append("inventory: every feature must be an object")
            continue
        feature_id = feature.get("id", "")
        if not isinstance(feature_id, str) or not feature_id:
            errors.append("feature without id")
            continue
        if feature_id in feature_ids:
            errors.append(f"{feature_id}: duplicate feature id")
        feature_ids.add(feature_id)

        missing = REQUIRED_FIELDS - feature.keys()
        if missing:
            errors.append(f"{feature_id}: missing fields {sorted(missing)}")
            continue

        string_values: dict[str, str] = {}
        for field in (
            "owner",
            "normal_activation",
            "configuration",
            "resource_ownership",
            "persistence",
            "maintenance",
            "diagnostics",
            "intended_disposition",
        ):
            value = feature[field]
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{feature_id}: {field} must be a non-empty string")
                string_values[field] = ""
            else:
                string_values[field] = value.strip()

        state_value = feature["state"]
        state = state_value if isinstance(state_value, str) else ""
        if not state:
            errors.append(f"{feature_id}: state must be a non-empty string")
        owner = string_values["owner"]
        if state not in allowed_states:
            errors.append(f"{feature_id}: unknown state {state!r}")
        if owner not in REQUIRED_OWNERS:
            errors.append(f"{feature_id}: unknown owner {owner!r}")

        if state == "orphan" and owner != "none":
            errors.append(f"{feature_id}: orphan feature must have owner 'none'")
        if state != "orphan" and owner == "none":
            errors.append(f"{feature_id}: owner 'none' requires orphan state")
        if state == "manual-only" and "explicit" not in string_values["normal_activation"]:
            errors.append(f"{feature_id}: manual-only feature must identify explicit activation")
        if state == "stub" and not any(
            action in string_values["intended_disposition"] for action in ("replace", "reject", "remove")
        ):
            errors.append(f"{feature_id}: stub must be replaced, rejected or removed")

        list_values: dict[str, list[str]] = {}
        for field in ("builtin_protocols", "capabilities", "negotiated_protocol_ids", "public_components"):
            value = feature.get(field, [])
            if not isinstance(value, list) or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                errors.append(f"{feature_id}: {field} must be an array of non-empty strings")
                list_values[field] = []
            else:
                list_values[field] = value

        evidence = feature["evidence"]
        if not isinstance(evidence, dict):
            errors.append(f"{feature_id}: evidence must be an object")
            continue

        evidence_values: dict[str, list[str]] = {}
        for field in ("layers", "source_paths", "tests", "donor_sources", "donor_cases"):
            value = evidence.get(field, [])
            if not isinstance(value, list) or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                errors.append(f"{feature_id}: evidence.{field} must be an array of non-empty strings")
                evidence_values[field] = []
            else:
                evidence_values[field] = value

        layers = set(evidence_values["layers"])
        unknown_layers = layers - EVIDENCE_LAYERS
        if unknown_layers:
            errors.append(f"{feature_id}: unknown evidence layers {sorted(unknown_layers)}")
        if state == "live":
            required_live = EVIDENCE_LAYERS
            if not required_live <= layers:
                errors.append(
                    f"{feature_id}: live claim lacks evidence layers {sorted(required_live - layers)}"
                )
            if string_values["diagnostics"].lower() in {"none", "unavailable"}:
                errors.append(f"{feature_id}: live claim lacks diagnostics")

        source_paths = evidence_values["source_paths"]
        tests = evidence_values["tests"]
        donor_sources = evidence_values["donor_sources"]
        case_ids = evidence_values["donor_cases"]
        if not source_paths:
            errors.append(f"{feature_id}: evidence must list source_paths")
        if not tests:
            errors.append(f"{feature_id}: evidence must list tests")
        if not donor_sources:
            errors.append(f"{feature_id}: evidence must list donor_sources")
        if state == "live" and not case_ids:
            errors.append(f"{feature_id}: live claim must reference donor cases")
        if state == "live" and not any(path.startswith("plugins/") for path in source_paths):
            errors.append(f"{feature_id}: live claim must reference its official-plugin path")
        if state == "live" and not any(test.startswith("test_forge_plugins") for test in tests):
            errors.append(f"{feature_id}: live claim must reference an official-plugin test target")
        if state == "live" and not any(
            has_registered_live_interop(donor_by_id.get(case_id)) for case_id in case_ids
        ):
            errors.append(f"{feature_id}: live claim must reference a donor case with registered live interop")

        for relative in source_paths + donor_sources:
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                errors.append(f"{feature_id}: evidence path must be repository-relative: {relative}")
            elif not (root / relative).is_file():
                errors.append(f"{feature_id}: evidence path does not exist: {relative}")

        for case_id in case_ids:
            if case_id not in donor_ids:
                errors.append(f"{feature_id}: unknown donor case {case_id!r}")
        for test in tests:
            if test not in registered_tests:
                errors.append(f"{feature_id}: unknown test target {test!r}")

        builtin_coverage.update(list_values["builtin_protocols"])
        capability_coverage.update(list_values["capabilities"])
        negotiated_protocol_coverage.update(list_values["negotiated_protocol_ids"])
        public_component_coverage.update(list_values["public_components"])

    missing_features = required_feature_ids - feature_ids
    unknown_features = feature_ids - required_feature_ids
    if missing_features:
        errors.append(f"inventory: missing required features {sorted(missing_features)}")
    if unknown_features:
        errors.append(f"inventory: features lack donor-capability ownership {sorted(unknown_features)}")

    expected_surface_features: dict[str, list[str]] = {owner: [] for owner in repository_owners}
    for feature in features:
        if not isinstance(feature, dict) or not isinstance(feature.get("id"), str):
            continue
        owner = feature.get("owner")
        surface_owner = owner if owner in repository_owners else "net.p2p.node"
        expected_surface_features[surface_owner].append(feature["id"])
    for owner_id in sorted(repository_owners):
        snapshot = surface_snapshots.get(owner_id, {})
        if not isinstance(snapshot, dict):
            errors.append(f"public surface {owner_id}: snapshot must be an object")
            continue
        owner = REQUIRED_OWNERS[owner_id]
        modules, headers, digest, nested = public_surface_snapshot(root, owner)
        if nested:
            errors.append(f"public surface {owner_id}: nested public source files are forbidden {nested}")
        if snapshot.get("owner") != owner_id:
            errors.append(f"public surface {owner_id}: owner must be exact")
        if snapshot.get("module_count") != len(modules):
            errors.append(f"public surface {owner_id}: public module count changed")
        if snapshot.get("modules") != modules:
            errors.append(f"public surface {owner_id}: public module inventory changed")
        if snapshot.get("headers") != headers:
            errors.append(f"public surface {owner_id}: public macro-header inventory changed")
        if snapshot.get("sha256") != digest:
            errors.append(
                f"public surface {owner_id}: declarations changed; update feature classification deliberately"
            )
        snapshot_features = snapshot.get("feature_ids", [])
        if not isinstance(snapshot_features, list) or any(
            not isinstance(feature_id, str) or not feature_id.strip()
            for feature_id in snapshot_features
        ):
            errors.append(f"public surface {owner_id}: feature_ids must be non-empty strings")
        elif sorted(snapshot_features) != sorted(expected_surface_features[owner_id]):
            errors.append(f"public surface {owner_id}: feature_ids do not match owned public surface")
        module_features = snapshot.get("module_features", {})
        if not isinstance(module_features, dict) or set(module_features) != set(modules):
            errors.append(f"public surface {owner_id}: every module needs exact feature classification")
            module_features = {}
        classified_features: set[str] = set()
        for module, classified in module_features.items():
            if not isinstance(classified, list) or not classified or any(
                not isinstance(feature_id, str) or feature_id not in feature_ids
                for feature_id in classified
            ):
                errors.append(f"public surface {owner_id}: invalid feature classification for {module}")
                continue
            classified_features.update(classified)
        header_features = snapshot.get("header_features", {})
        if not isinstance(header_features, dict) or set(header_features) != set(headers):
            errors.append(f"public surface {owner_id}: every macro header needs exact feature classification")
            header_features = {}
        for header, classified in header_features.items():
            if not isinstance(classified, list) or not classified or any(
                not isinstance(feature_id, str) or feature_id not in feature_ids
                for feature_id in classified
            ):
                errors.append(f"public surface {owner_id}: invalid feature classification for {header}")
                continue
            classified_features.update(classified)
        if classified_features != set(expected_surface_features[owner_id]):
            errors.append(f"public surface {owner_id}: module/header classifications miss owned features")

    protocol_path = root / "libraries/net/p2p/include/forge/net/p2p/protocol.cppm"
    protocol_source = protocol_path.read_text()
    declared_builtins = extract_namespace_names(
        protocol_source,
        "builtins",
        r"inline const protocol_id\s+([a-zA-Z0-9_]+)",
    )
    declared_capabilities = extract_namespace_names(
        protocol_source,
        "capabilities",
        r"inline constexpr std::uint64_t\s+([a-zA-Z0-9_]+)",
    )
    builtins_match = re.search(r"namespace builtins\s*\{(?P<body>.*?)\n\}", protocol_source, re.DOTALL)
    builtin_values = (
        set(re.findall(r'\.value\s*=\s*"([^"]+)"', builtins_match.group("body"))) if builtins_match else set()
    )
    p2p_sources = list((root / "libraries/net/p2p").glob("*.cpp"))
    p2p_sources.extend((root / "libraries/net/p2p/include").glob("**/*.cppm"))
    p2p_sources.extend((root / "plugins/p2p").glob("**/*.cpp"))
    p2p_sources.extend((root / "plugins/p2p").glob("**/*.cppm"))
    protocol_literals = {
        value
        for source in p2p_sources
        for value in re.findall(
            r'protocol_id(?:\s+[A-Za-z0-9_]+)?\s*\{\s*\.value\s*=\s*"([^"]+)"',
            source.read_text(),
        )
        if value.startswith("/")
    }
    declared_negotiated_protocols = protocol_literals - builtin_values
    public_components = {
        component
        for source in (root / "libraries/net/p2p/include").glob("**/*.cppm")
        for component in re.findall(
            r"(?m)^class\s+([A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*)\s*[{:]",
            source.read_text(),
        )
    }

    plugin_sources = "\n".join(
        source.read_text() for source in (root / "plugins/p2p/node").glob("*.cpp")
    )
    if "start_maintenance" in plugin_sources or "async_refresh_discovery" in plugin_sources:
        errors.append("plugin.p2p.node: network maintenance must be owned by forge_net_p2p")
    node_lifecycle_source = (root / "libraries/net/p2p/node_impl_lifecycle.cpp").read_text()
    bootstrap_source = (root / "libraries/net/p2p/bootstrap_service.cpp").read_text()
    if "bootstrap_service" not in node_lifecycle_source or "start_maintenance" not in bootstrap_source:
        errors.append("net.p2p.node: bootstrap maintenance ownership is not structurally discoverable")

    for kind, declared, coverage in (
        ("built-in protocol", declared_builtins, builtin_coverage),
        ("capability", declared_capabilities, capability_coverage),
        ("negotiated protocol", declared_negotiated_protocols, negotiated_protocol_coverage),
        ("public nested component", public_components, public_component_coverage),
    ):
        unknown = set(coverage) - declared
        missing = declared - set(coverage)
        duplicates = sorted(name for name, count in coverage.items() if count != 1)
        if unknown:
            errors.append(f"inventory: unknown {kind}s {sorted(unknown)}")
        if missing:
            errors.append(f"inventory: missing {kind}s {sorted(missing)}")
        if duplicates:
            errors.append(f"inventory: {kind}s must be owned exactly once {duplicates}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        "P2P source inventory valid: "
        f"{len(capability_ids)} classified capabilities, "
        f"{len(feature_ids)} implementation features, "
        f"{len(declared_builtins)} built-in protocols, "
        f"{len(declared_capabilities)} capabilities, "
        f"{len(declared_negotiated_protocols)} negotiated protocols, "
        f"{len(public_components)} public nested components"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
