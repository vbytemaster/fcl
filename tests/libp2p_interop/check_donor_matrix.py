#!/usr/bin/env python3
import ast
import json
import re
import sys
from pathlib import Path

from provenance import donor_checkout_head_errors, donor_revision_schema_errors


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def scenario_profiles(runner_path: Path) -> set[tuple[str, str]]:
    source = runner_path.read_text()
    tree = ast.parse(runner_path.read_text(), filename=str(runner_path))
    for statement in tree.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if not isinstance(target, ast.Name) or target.id != "LIVE_SCENARIO_PROFILES":
            continue
        value = ast.literal_eval(statement.value)
        if not isinstance(value, dict) or any(
            not isinstance(profile, str)
            or not isinstance(scenarios, tuple)
            or not scenarios
            or any(not isinstance(scenario, str) or not scenario for scenario in scenarios)
            for profile, scenarios in value.items()
        ):
            raise ValueError("LIVE_SCENARIO_PROFILES must be a literal profile-to-scenarios map")
        for profile in value:
            if source.count(f'"{profile}"') < 2:
                raise ValueError(f"live scenario profile {profile!r} is not used by the runner")
        return {
            (profile, scenario)
            for profile, scenarios in value.items()
            for scenario in scenarios
        }
    raise ValueError("runner does not declare LIVE_SCENARIO_PROFILES")


def executable_source_corpora(root: Path, manifest: str) -> dict[str, str]:
    corpora: dict[str, str] = {}
    for match in re.finditer(r"add_executable\s*\((?P<body>.*?)\)", manifest, re.DOTALL):
        tokens = re.findall(r"[^\s()]+", match.group("body"))
        if not tokens:
            continue
        target = tokens[0]
        sources = []
        for token in tokens[1:]:
            if token.startswith("$") or Path(token).suffix not in {".cpp", ".py"}:
                continue
            source = root / "tests" / token
            if source.is_file():
                sources.append(source.read_text(errors="replace"))
        corpora[target] = "\n".join(sources)
    return corpora


def main() -> int:
    if len(sys.argv) not in {3, 4}:
        print(
            "usage: check_donor_matrix.py SOURCE_ROOT donor_cases.json [DONORS_ROOT]",
            file=sys.stderr,
        )
        return 2

    root = Path(sys.argv[1]).resolve()
    path = Path(sys.argv[2]).resolve()
    donors_root = Path(sys.argv[3]).resolve() if len(sys.argv) == 4 and sys.argv[3] else None
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(), object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: donor matrix: {error}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        print("ERROR: donor matrix: top-level value must be an object", file=sys.stderr)
        return 1

    allowed_value = data.get("allowed_mapping_states", [])
    if not isinstance(allowed_value, list) or any(not isinstance(value, str) for value in allowed_value):
        errors.append("allowed_mapping_states must be an array of strings")
        allowed: set[str] = set()
    else:
        allowed = set(allowed_value)

    expected_statuses = {"mapped", "not_applicable", "unsupported"}
    if allowed != expected_statuses:
        errors.append("allowed_mapping_states must match the donor mapping vocabulary")
    if data.get("status_scope") != "donor_case_coverage_only":
        errors.append("status_scope must be donor_case_coverage_only")
    if data.get("execution_scope") != "registered_optional_tests_not_current_results":
        errors.append("execution_scope must not imply current interop results")
    inventory = data.get("production_inventory", "")
    if not isinstance(inventory, str) or not inventory or not (path.parent / inventory).is_file():
        errors.append("production_inventory must reference the P2P feature inventory")
    capability_inventory = data.get("capability_inventory", "")
    if (
        not isinstance(capability_inventory, str)
        or not capability_inventory
        or not (path.parent / capability_inventory).is_file()
    ):
        errors.append("capability_inventory must reference the donor-first capability manifest")

    donor_revisions = data.get("donor_revisions", {})
    donor_revision_errors = donor_revision_schema_errors(donor_revisions)
    errors.extend(donor_revision_errors)
    if not isinstance(donor_revisions, dict):
        donor_revisions = {}
    if donors_root is not None and not donor_revision_errors:
        errors.extend(donor_checkout_head_errors(donors_root, donor_revisions))

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
    target_corpora = executable_source_corpora(root, test_manifest)
    profiles = scenario_profiles(root / "tests/libp2p_interop/runner.py")
    scenario_names = {scenario for _, scenario in profiles}

    seen: set[str] = set()
    cases = data.get("cases", [])
    if not isinstance(cases, list):
        errors.append("cases must be an array")
        cases = []
    for case in cases:
        if not isinstance(case, dict):
            errors.append("every donor case must be an object")
            continue
        case_id = case.get("id", "")
        status = case.get("mapping_state", "")
        tests = case.get("forge_tests", [])
        source = case.get("source", "")
        donor = case.get("donor", "")
        donor_files = case.get("donor_file", [])
        donor_cases = case.get("donor_case", [])
        live_scenarios = case.get("forge_live_scenario", [])

        if not isinstance(case_id, str) or not case_id:
            errors.append("case without id")
            continue
        if case_id in seen:
            errors.append(f"duplicate case id: {case_id}")
        seen.add(case_id)
        if not isinstance(status, str) or status not in allowed:
            errors.append(f"{case_id}: unknown status {status!r}")
        if "status" in case or "supported" in case:
            errors.append(f"{case_id}: legacy production-like status fields are forbidden")
        if not isinstance(source, str) or not source.strip():
            errors.append(f"{case_id}: source must be a non-empty string")
            source = ""
        if not isinstance(donor, str) or not donor.strip():
            errors.append(f"{case_id}: donor must be a non-empty string")
        for local_doc in re.findall(r"docs/[A-Za-z0-9_./-]+\.md", source):
            if Path(local_doc).is_absolute() or ".." in Path(local_doc).parts:
                errors.append(f"{case_id}: local donor document must be repository-relative")
            elif not (root / local_doc).is_file():
                errors.append(f"{case_id}: local donor document does not exist: {local_doc}")
        for field, values in (("donor_file", donor_files), ("donor_case", donor_cases)):
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value.strip() for value in values
            ):
                errors.append(f"{case_id}: {field} must be an array of non-empty strings")
        if status == "mapped" and (not donor_files or not donor_cases):
            errors.append(f"{case_id}: mapped donor case requires donor_file and donor_case")
        if isinstance(donor_files, list):
            for donor_file in donor_files:
                if not isinstance(donor_file, str) or not donor_file.strip():
                    continue
                relative = Path(donor_file)
                if relative.is_absolute() or ".." in relative.parts:
                    errors.append(f"{case_id}: donor_file must be repository-relative: {donor_file}")
                elif relative.parts and relative.parts[0] == "docs":
                    if not (root / relative).is_file():
                        errors.append(f"{case_id}: local donor_file does not exist: {donor_file}")
                elif relative.parts and relative.parts[0] == "donors" and len(relative.parts) > 2:
                    repository = relative.parts[1]
                    if repository not in donor_revisions:
                        errors.append(f"{case_id}: donor_file repository is not pinned: {repository}")
                    elif donors_root is not None and not (donors_root / Path(*relative.parts[1:])).is_file():
                        errors.append(f"{case_id}: donor_file does not exist: {donor_file}")
                else:
                    errors.append(f"{case_id}: donor_file must start with docs/ or donors/<repo>/")
        if not isinstance(tests, list) or any(
            not isinstance(test, str) or not test.strip() for test in tests
        ):
            errors.append(f"{case_id}: forge_tests must be an array of non-empty strings")
            tests = []
        if not isinstance(live_scenarios, list) or any(not isinstance(item, dict) for item in live_scenarios):
            errors.append(f"{case_id}: forge_live_scenario must be an array of selector objects")
            live_scenarios = []
        for selector in live_scenarios:
            if set(selector) != {"profile", "scenario"}:
                errors.append(f"{case_id}: live selector must contain only profile and scenario")
                continue
            profile = selector.get("profile")
            scenario = selector.get("scenario")
            if not isinstance(profile, str) or not isinstance(scenario, str):
                errors.append(f"{case_id}: live selector values must be strings")
            elif (profile, scenario) not in profiles:
                errors.append(f"{case_id}: unknown live selector {profile!r}/{scenario!r}")
        if live_scenarios and not any(
            isinstance(reference, str)
            and reference.strip().split()[0] == "test_forge_libp2p_interop"
            for reference in tests
            if reference.strip()
        ):
            errors.append(f"{case_id}: live scenarios require the registered interop target")
        for selector in live_scenarios:
            scenario = selector.get("scenario") if isinstance(selector, dict) else None
            if isinstance(scenario, str) and f"test_forge_libp2p_interop {scenario}" not in tests:
                errors.append(f"{case_id}: live selector {scenario!r} lacks exact interop test reference")
        if status == "mapped" and not tests:
            errors.append(f"{case_id}: mapped donor case must list at least one FORGE test")
        for reference in tests:
            reference = reference.strip()
            parts = reference.split(maxsplit=1)
            target = parts[0]
            if target in registered_tests:
                if len(parts) != 2 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", parts[1]):
                    errors.append(f"{case_id}: evidence requires a target and one exact test/scenario id")
                elif target == "test_forge_libp2p_interop":
                    if parts[1] not in scenario_names:
                        errors.append(f"{case_id}: unknown interop scenario {parts[1]!r}")
                elif not re.search(
                    rf"\b{re.escape(parts[1])}\b", target_corpora.get(target, "")
                ):
                    errors.append(f"{case_id}: test case {parts[1]!r} is not owned by {target}")
                continue
            errors.append(f"{case_id}: test evidence must start with a registered target: {reference!r}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"donor matrix ok: {len(seen)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
