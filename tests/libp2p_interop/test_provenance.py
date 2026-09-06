#!/usr/bin/env python3
import hashlib
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

from provenance import worktree_identity
from runner import (
    SUPPORTED_FORGE_BUILD_PROFILES,
    forge_fixture_requirements,
    require_dht_provider_evidence,
    require_local_topology_evidence,
    require_pnet_fingerprint,
    require_supported_forge_build_profile,
    pnet_fingerprint as runner_pnet_fingerprint,
    run_dial,
)
from check_stage6_acceptance import pnet_fingerprint as checker_pnet_fingerprint
from promote_stage6_acceptance import (
    PROMOTION_DIRECTORY_PREFIX,
    create_invocation_directory,
    forced_live_environment,
    promotion_status,
)


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def initialize_repository(root: Path) -> None:
    root.mkdir()
    git(root, "init")
    git(root, "config", "user.name", "Forge provenance test")
    git(root, "config", "user.email", "forge-provenance@example.invalid")


def commit(root: Path, message: str) -> str:
    git(root, "add", ".")
    git(root, "commit", "-m", message)
    return git(root, "rev-parse", "HEAD")


def add_submodule(root: Path, source: Path, destination: str) -> None:
    git(root, "-c", "protocol.file.allow=always", "submodule", "add", str(source), destination)


class WorktreeFingerprintTest(unittest.TestCase):
    def make_uninitialized_gitlink(self, temporary: Path) -> Path:
        source = temporary / "source"
        initialize_repository(source)
        (source / "source.txt").write_text("source\n")
        source_head = commit(source, "source")

        root = temporary / "root"
        initialize_repository(root)
        (root / "root.txt").write_text("root\n")
        commit(root, "root")
        git(root, "update-index", "--add", "--cacheinfo", f"160000,{source_head},vendor/empty")
        git(root, "commit", "-m", "indexed gitlink")
        (root / "vendor" / "empty").mkdir(parents=True)
        return root

    def make_nested_worktree(self, temporary: Path) -> tuple[Path, str, str, str]:
        leaf = temporary / "leaf"
        initialize_repository(leaf)
        (leaf / "leaf.txt").write_text("first\n")
        leaf_first = commit(leaf, "leaf first")
        (leaf / "leaf.txt").write_text("second\n")
        leaf_second = commit(leaf, "leaf second")
        git(leaf, "checkout", leaf_first)

        module = temporary / "module"
        initialize_repository(module)
        add_submodule(module, leaf, "nested")
        (module / "module.txt").write_text("first\n")
        module_first = commit(module, "module first")
        (module / "module.txt").write_text("second\n")
        module_second = commit(module, "module second")
        git(module, "checkout", module_first)

        root = temporary / "root"
        initialize_repository(root)
        add_submodule(root, module, "module")
        commit(root, "root")
        git(root, "-c", "protocol.file.allow=always", "submodule", "update", "--init", "--recursive")
        return root, module_first, module_second, leaf_second

    def restore_clean_submodules(self, root: Path) -> None:
        git(root, "-c", "protocol.file.allow=always", "submodule", "update", "--init", "--recursive", "--force")
        git(root / "module", "clean", "-fd")
        git(root / "module" / "nested", "clean", "-fd")

    def test_fingerprint_tracks_direct_and_nested_submodule_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, module_first, module_second, leaf_second = self.make_nested_worktree(Path(directory))
            clean = worktree_identity(root)
            self.assertFalse(clean.dirty)

            git(root / "module", "checkout", module_second)
            different_checkout = worktree_identity(root)
            self.assertNotEqual(different_checkout.fingerprint, clean.fingerprint)
            self.assertTrue(different_checkout.dirty)
            self.restore_clean_submodules(root)
            self.assertEqual(worktree_identity(root), clean)
            self.assertEqual(git(root / "module", "rev-parse", "HEAD"), module_first)

            (root / "module" / "module.txt").write_text("dirty\n")
            dirty_tracked = worktree_identity(root)
            self.assertNotEqual(dirty_tracked.fingerprint, clean.fingerprint)
            self.assertTrue(dirty_tracked.dirty)
            self.restore_clean_submodules(root)
            self.assertEqual(worktree_identity(root), clean)

            module_file = root / "module" / "module.txt"
            module_file.write_text("dirty before chmod\n")
            dirty_before_chmod = worktree_identity(root)
            module_file.chmod(module_file.stat().st_mode ^ stat.S_IXUSR)
            dirty_after_chmod = worktree_identity(root)
            self.assertTrue(dirty_before_chmod.dirty)
            self.assertTrue(dirty_after_chmod.dirty)
            self.assertNotEqual(dirty_after_chmod.fingerprint, dirty_before_chmod.fingerprint)
            self.restore_clean_submodules(root)
            self.assertEqual(worktree_identity(root), clean)

            (root / "module" / "untracked.txt").write_text("untracked\n")
            dirty_untracked = worktree_identity(root)
            self.assertNotEqual(dirty_untracked.fingerprint, clean.fingerprint)
            self.assertTrue(dirty_untracked.dirty)
            self.restore_clean_submodules(root)
            self.assertEqual(worktree_identity(root), clean)

            git(root / "module" / "nested", "checkout", leaf_second)
            dirty_nested = worktree_identity(root)
            self.assertNotEqual(dirty_nested.fingerprint, clean.fingerprint)
            self.assertTrue(dirty_nested.dirty)
            self.restore_clean_submodules(root)
            self.assertEqual(worktree_identity(root), clean)

    def test_empty_uninitialized_gitlink_is_clean_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_uninitialized_gitlink(Path(directory))
            first = worktree_identity(root)
            second = worktree_identity(root)
            self.assertFalse(first.dirty)
            self.assertEqual(first, second)

    def test_nonempty_uninitialized_gitlink_is_dirty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_uninitialized_gitlink(Path(directory))
            clean = worktree_identity(root)
            (root / "vendor" / "empty" / "unexpected.txt").write_text("not a repository\n")
            invalid = worktree_identity(root)
            self.assertTrue(invalid.dirty)
            self.assertNotEqual(invalid.fingerprint, clean.fingerprint)

    def test_initialized_nested_submodule_remains_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, _, _, _ = self.make_nested_worktree(Path(directory))
            self.assertTrue((root / "module" / ".git").is_file())
            self.assertTrue((root / "module" / "nested" / ".git").is_file())
            self.assertFalse(worktree_identity(root).dirty)


class InteropCMakeConfigurationTest(unittest.TestCase):
    def test_multi_config_artifacts_are_configuration_scoped(self) -> None:
        source = (Path(__file__).parents[1] / "CMakeLists.txt").read_text()
        self.assertIn(
            "set(FORGE_INTEROP_ARTIFACT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/libp2p_interop)", source
        )
        self.assertIn(
            "set(FORGE_INTEROP_ARTIFACT_DIRECTORY ${FORGE_INTEROP_ARTIFACT_DIRECTORY}/$<CONFIG>)", source
        )
        self.assertIn(
            "set(FORGE_INTEROP_BUILD_INFO_HEADER ${FORGE_INTEROP_BUILD_INFO_DIRECTORY}/forge_interop_build_info.hxx)",
            source,
        )
        self.assertIn(
            "set(FORGE_INTEROP_BUILD_INFO_STAMP ${FORGE_INTEROP_BUILD_INFO_DIRECTORY}/forge_interop_build_info.json)",
            source,
        )
        self.assertEqual(source.count("--build-dir ${FORGE_INTEROP_ARTIFACT_DIRECTORY}"), 3)
        self.assertIn(
            "set(\n      FORGE_P2P_STAGE6_PROMOTION_DIRECTORY\n      ${FORGE_P2P_STAGE6_PROMOTION_DIRECTORY}/$<CONFIG>\n   )",
            source,
        )
        self.assertIn("add_dependencies(forge_interop_fixture forge_interop_fixture_build_info)", source)
        self.assertNotIn("OBJECT_DEPENDS", source)


class InteropRunnerResultTest(unittest.TestCase):
    def test_pnet_fingerprint_is_domain_separated_and_checked_by_runner_and_checker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pnet_key_file = Path(directory) / "pnet.key"
            pnet_key_file.write_bytes(b"private-network-test-key")
            expected = hashlib.sha256(
                b"forge-p2p-stage6-pnet-fingerprint-v1\x00" + pnet_key_file.read_bytes()
            ).hexdigest()
            self.assertEqual(runner_pnet_fingerprint(pnet_key_file), expected)
            self.assertEqual(checker_pnet_fingerprint(pnet_key_file), expected)
            require_pnet_fingerprint({"pnet_fingerprint": expected}, pnet_key_file, "fixture")
            with self.assertRaisesRegex(RuntimeError, "did not emit the required PNET fingerprint"):
                require_pnet_fingerprint({"pnet_fingerprint": "0" * 64}, pnet_key_file, "fixture")

    def test_run_dial_rejects_non_ok_fixture_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "non_ok_fixture.py"
            fixture.write_text(
                f"#!{sys.executable}\n"
                "import json\n"
                "import sys\n"
                "from pathlib import Path\n"
                "result_file = Path(sys.argv[sys.argv.index('--result-file') + 1])\n"
                "result_file.write_text(json.dumps({'status': 'failed'}) + '\\n')\n"
            )
            fixture.chmod(fixture.stat().st_mode | stat.S_IXUSR)
            with self.assertRaisesRegex(RuntimeError, "did not report status=ok"):
                run_dial(
                    fixture,
                    "fixture",
                    "ping",
                    "peer",
                    "/ip4/127.0.0.1/tcp/1",
                    root,
                )


class Stage6PromotionHelperTest(unittest.TestCase):
    def test_invocation_directories_are_unique_children_of_the_configured_base(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "promotion-base"
            first = create_invocation_directory(base)
            second = create_invocation_directory(base)
            self.assertEqual(first.parent, base)
            self.assertEqual(second.parent, base)
            self.assertNotEqual(first, second)
            self.assertTrue(first.name.startswith(PROMOTION_DIRECTORY_PREFIX))
            self.assertTrue(second.name.startswith(PROMOTION_DIRECTORY_PREFIX))

    def test_promotion_forces_live_environment_and_checker_errors_fail(self) -> None:
        inherited = {"FORGE_ENABLE_LIBP2P_INTEROP": "0", "OTHER": "value"}
        environment = forced_live_environment(inherited)
        self.assertEqual(environment["FORGE_ENABLE_LIBP2P_INTEROP"], "1")
        self.assertEqual(environment["OTHER"], "value")
        self.assertEqual(promotion_status(0, ["artifact is missing"]), "FAILED")
        self.assertEqual(promotion_status(1, []), "FAILED")


class InteropFixtureContractTest(unittest.TestCase):
    def fixture_lock(self, build_profiles: object = None) -> dict:
        return {
            "schema_version": 2,
            "toolchains": {
                "forge_fixture": {
                    "compiler_id": "Clang",
                    "compiler_version": "22.1.8",
                    "build_profiles": list(SUPPORTED_FORGE_BUILD_PROFILES)
                    if build_profiles is None else build_profiles,
                },
            },
        }

    def test_forge_fixture_accepts_each_locked_build_profile(self) -> None:
        requirements = forge_fixture_requirements(self.fixture_lock())
        for profile in SUPPORTED_FORGE_BUILD_PROFILES:
            require_supported_forge_build_profile(profile, requirements)

    def test_forge_fixture_rejects_unsupported_or_malformed_build_profiles(self) -> None:
        requirements = forge_fixture_requirements(self.fixture_lock())
        with self.assertRaises(RuntimeError):
            require_supported_forge_build_profile("Experimental", requirements)
        with self.assertRaises(RuntimeError):
            require_supported_forge_build_profile(None, requirements)

        malformed_profiles = (
            "default",
            list(SUPPORTED_FORGE_BUILD_PROFILES[:-1]),
            [*SUPPORTED_FORGE_BUILD_PROFILES, "Experimental"],
        )
        for profiles in malformed_profiles:
            with self.subTest(profiles=profiles), self.assertRaises(RuntimeError):
                forge_fixture_requirements(self.fixture_lock(profiles))

    def test_dht_provider_evidence_requires_correlated_provider_query(self) -> None:
        require_dht_provider_evidence(
            {
                "provider_count": 1,
                "provider_peer": "provider",
                "querier_peer": "querier",
                "returned_provider_peer": "provider",
                "address_count": 1,
                "protocol_streams_opened_delta": 1,
                "query_requests_delta": 1,
                "negotiated_protocol": "/ipfs/kad/1.0.0",
            },
            "forge",
        )
        for result in ({}, {"provider_count": 0}, {"provider_count": -1}, {"provider_count": True}):
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                require_dht_provider_evidence(result, "forge")

        for result in (
            {"provider_count": 1},
            {"provider_count": 1, "provider_peer": "provider"},
            {"provider_count": 1, "querier_peer": "querier"},
            {"provider_count": 1, "provider_peer": "same", "querier_peer": "same"},
            {"provider_count": 1, "provider_peer": "provider", "querier_peer": "querier"},
            {
                "provider_count": 1,
                "provider_peer": "provider",
                "querier_peer": "querier",
                "returned_provider_peer": "different",
                "address_count": 1,
                "protocol_streams_opened_delta": 1,
                "negotiated_protocol": "/ipfs/kad/1.0.0",
            },
            {
                "provider_count": 1,
                "provider_peer": "provider",
                "querier_peer": "querier",
                "returned_provider_peer": "provider",
                "address_count": 0,
                "protocol_streams_opened_delta": 1,
                "negotiated_protocol": "/ipfs/kad/1.0.0",
            },
            {
                "provider_count": 1,
                "provider_peer": "provider",
                "querier_peer": "querier",
                "returned_provider_peer": "provider",
                "address_count": 1,
                "protocol_streams_opened_delta": 0,
                "negotiated_protocol": "/ipfs/kad/1.0.0",
            },
            {
                "provider_count": 1,
                "provider_peer": "provider",
                "querier_peer": "querier",
                "returned_provider_peer": "provider",
                "address_count": 1,
                "protocol_streams_opened_delta": 1,
                "negotiated_protocol": "/ipfs/kad/1.1.0",
            },
            {
                "provider_count": 1,
                "provider_peer": "provider",
                "querier_peer": "querier",
                "returned_provider_peer": "provider",
                "address_count": 1,
                "protocol_streams_opened_delta": 1,
                "query_requests_delta": 0,
                "negotiated_protocol": "/ipfs/kad/1.0.0",
            },
        ):
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                require_dht_provider_evidence(result, "forge")

    def test_local_topology_evidence_is_fail_closed(self) -> None:
        require_local_topology_evidence(
            {"status": "ok", "relay_echo": True, "relay_bytes": 1}, "relay_echo_topology"
        )
        valid_dcutr = {
            "status": "ok",
            "hole_punch_status": 3,
            "relay_echo": True,
            "source_hole_punch_successes": 1,
            "relay_bytes": 1,
        }
        require_local_topology_evidence(valid_dcutr, "dcutr_relay_topology")

        invalid = (
            {**valid_dcutr, "status": "failed"},
            {**valid_dcutr, "hole_punch_status": 4},
            {**valid_dcutr, "hole_punch_status": 3.0},
            {**valid_dcutr, "hole_punch_status": True},
            {**valid_dcutr, "relay_echo": False},
            {**valid_dcutr, "source_hole_punch_successes": 0},
            {**valid_dcutr, "source_hole_punch_successes": True},
            {**valid_dcutr, "source_hole_punch_successes": 1.0},
            {**valid_dcutr, "relay_bytes": 0},
            {**valid_dcutr, "relay_bytes": True},
            {**valid_dcutr, "relay_bytes": 1.0},
        )
        for result in invalid:
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                require_local_topology_evidence(result, "dcutr_relay_topology")

        for result in (
            {"status": "ok", "relay_echo": True, "relay_bytes": True},
            {"status": "ok", "relay_echo": True, "relay_bytes": 1.0},
        ):
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                require_local_topology_evidence(result, "relay_echo_topology")

        with self.assertRaises(RuntimeError):
            require_local_topology_evidence({"status": "ok"}, "unknown_topology")


if __name__ == "__main__":
    unittest.main()
