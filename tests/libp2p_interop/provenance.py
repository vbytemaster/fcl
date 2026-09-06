#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional


WORKTREE_FINGERPRINT_FORMAT = b"forge-libp2p-interop-worktree-v2\0"
DONOR_CHECKOUT_KEY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
DONOR_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")

# Fixture provenance has a deliberately smaller, named subset of the complete
# donor pin map. Names are semantic fixture identities, not interchangeable
# labels for a checkout that happens to have a canonical pin.
FIXTURE_DONOR_DIRECTORIES = {
    "go-libp2p": "go-libp2p",
    "rust-libp2p": "rust-libp2p",
    "go-kad": "go-libp2p-kad-dht",
    "go-pubsub": "go-libp2p-pubsub",
    "libp2p-specs": "libp2p-specs",
}


@dataclass(frozen=True)
class WorktreeIdentity:
    head: str
    fingerprint: str
    dirty: bool

    def as_json(self) -> dict:
        return {
            "head": self.head,
            "worktree_sha256": self.fingerprint,
            "dirty": self.dirty,
            "exact_identity": f"git:{self.head};worktree-sha256:{self.fingerprint}",
        }


@dataclass(frozen=True)
class IndexEntry:
    mode: bytes
    object_id: bytes
    stage: bytes
    relative: bytes


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as value:
        while chunk := value.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def graph_hash(root: Path, paths: list[str]) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        path = root / relative
        digest.update(relative.encode())
        digest.update(b"\0")
        with path.open("rb") as value:
            while chunk := value.read(1024 * 1024):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def git_output(root: Path, *args: str) -> bytes:
    try:
        return subprocess.check_output(["git", "-C", str(root), *args])
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"Git command failed for {root}: {error}") from error


def donor_revision_schema_errors(donor_revisions: object) -> list[str]:
    """Return fail-closed errors for the canonical donor revision map."""
    if not isinstance(donor_revisions, Mapping) or not donor_revisions:
        return ["donor_revisions must be a non-empty object"]

    errors: list[str] = []
    for repository, revision in donor_revisions.items():
        if not isinstance(repository, str) or not DONOR_CHECKOUT_KEY_PATTERN.fullmatch(repository):
            errors.append(f"invalid donor repository name {repository!r}")
            continue
        if not isinstance(revision, str) or not DONOR_REVISION_PATTERN.fullmatch(revision):
            errors.append(f"donor {repository}: revision must be a full lowercase commit SHA")
    return errors


def reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_canonical_donor_revisions(case_matrix_path: Path) -> dict[str, str]:
    """Load the sole canonical donor pin map from the donor case matrix."""
    try:
        case_matrix = json.loads(
            case_matrix_path.read_text(), object_pairs_hook=reject_duplicate_json_keys
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(f"cannot load canonical donor revisions: {error}") from error
    if not isinstance(case_matrix, Mapping):
        raise RuntimeError("canonical donor case matrix must be an object")
    donor_revisions = case_matrix.get("donor_revisions")
    errors = donor_revision_schema_errors(donor_revisions)
    if errors:
        raise RuntimeError(f"canonical donor revisions are invalid: {'; '.join(errors)}")
    assert isinstance(donor_revisions, Mapping)
    return dict(donor_revisions)


def fixture_donor_revision_bindings(
    fixture_donors: object, canonical_donor_revisions: object
) -> tuple[dict[str, str], list[str]]:
    """Bind fixture-lock donor directories and commits to the canonical case-matrix pins."""
    errors = donor_revision_schema_errors(canonical_donor_revisions)
    if errors:
        return {}, [f"canonical donor revisions are invalid: {error}" for error in errors]
    if not isinstance(fixture_donors, list):
        return {}, ["fixture lock donors must be an array"]

    assert isinstance(canonical_donor_revisions, Mapping)
    bindings: dict[str, str] = {}
    seen_names: set[str] = set()
    seen_directories: set[str] = set()
    for donor in fixture_donors:
        if not isinstance(donor, Mapping):
            errors.append("fixture lock donor entry must be an object")
            continue
        name = donor.get("name")
        directory = donor.get("directory")
        commit = donor.get("commit")
        tree = donor.get("tree")
        if not isinstance(name, str) or name not in FIXTURE_DONOR_DIRECTORIES:
            errors.append(f"fixture lock donor name is invalid: {name!r}")
            continue
        if name in seen_names:
            errors.append(f"fixture lock donor name is duplicated: {name}")
            continue
        seen_names.add(name)
        if not isinstance(directory, str) or not DONOR_CHECKOUT_KEY_PATTERN.fullmatch(directory):
            errors.append(f"fixture lock donor directory is invalid: {directory!r}")
            continue
        if directory in seen_directories:
            errors.append(f"fixture lock donor directory is duplicated: {directory}")
            continue
        seen_directories.add(directory)
        expected_directory = FIXTURE_DONOR_DIRECTORIES[name]
        if directory != expected_directory:
            errors.append(
                f"fixture lock donor {name}: directory must be {expected_directory}"
            )
            continue
        if not isinstance(commit, str) or not DONOR_REVISION_PATTERN.fullmatch(commit):
            errors.append(f"fixture lock donor {directory}: commit must be a full lowercase commit SHA")
            continue
        if not isinstance(tree, str) or not DONOR_REVISION_PATTERN.fullmatch(tree):
            errors.append(f"fixture lock donor {directory}: tree must be a full lowercase tree SHA")
            continue
        canonical_commit = canonical_donor_revisions.get(directory)
        if canonical_commit is None:
            errors.append(f"fixture lock donor directory is not canonically pinned: {directory}")
            continue
        if commit != canonical_commit:
            errors.append(
                f"fixture lock donor {directory}: commit does not match canonical donor_cases revision"
            )
            continue
        bindings[directory] = canonical_commit
    if seen_names != set(FIXTURE_DONOR_DIRECTORIES):
        errors.append("fixture lock donor names do not match the canonical fixture donor registry")
    if seen_directories != set(FIXTURE_DONOR_DIRECTORIES.values()):
        errors.append("fixture lock donor directories do not match the canonical fixture donor registry")
    return bindings, errors


def donor_checkout_head_errors(donors_root: Path, donor_revisions: object) -> list[str]:
    """Return the existing donor-pin errors for unavailable or stale checkouts."""
    schema_errors = donor_revision_schema_errors(donor_revisions)
    if schema_errors:
        return schema_errors

    assert isinstance(donor_revisions, Mapping)
    errors: list[str] = []
    for repository, revision in donor_revisions.items():
        assert isinstance(repository, str)
        assert isinstance(revision, str)
        repository_path = donors_root / repository
        if not repository_path.is_dir():
            errors.append(f"donor {repository}: repository is unavailable")
            continue
        try:
            head = git_output(repository_path, "rev-parse", "HEAD").decode("ascii").strip()
        except RuntimeError:
            errors.append(f"donor {repository}: checkout does not match pinned revision")
            continue
        if head != revision:
            errors.append(f"donor {repository}: checkout does not match pinned revision")
    return errors


def fixture_donor_checkout_errors(
    donors_root: Path, fixture_donors: object, canonical_donor_revisions: object
) -> list[str]:
    """Verify fixture donor checkout HEADs and trees against canonical revisions."""
    bindings, errors = fixture_donor_revision_bindings(fixture_donors, canonical_donor_revisions)
    if errors:
        return errors
    errors.extend(donor_checkout_head_errors(donors_root, bindings))
    assert isinstance(fixture_donors, list)
    for donor in fixture_donors:
        assert isinstance(donor, Mapping)
        directory = donor["directory"]
        tree = donor["tree"]
        assert isinstance(directory, str)
        assert isinstance(tree, str)
        if directory not in bindings:
            continue
        checkout = donors_root / directory
        try:
            actual_tree = git_output(checkout, "rev-parse", f"{bindings[directory]}^{{tree}}")
        except RuntimeError:
            errors.append(f"fixture donor revision lookup failed for {directory}")
            continue
        if actual_tree.decode("ascii").strip() != tree:
            errors.append(f"fixture donor tree mismatch: {directory}")
    return errors


def donor_source_object_errors(
    donors_root: Path, donor_revisions: object, source: object
) -> list[str]:
    """Verify a donor evidence path as a blob in the exact pinned Git object tree."""
    schema_errors = donor_revision_schema_errors(donor_revisions)
    if schema_errors:
        return schema_errors
    if not isinstance(source, str) or not source or "\x00" in source:
        return [f"donor source must be a non-empty path: {source!r}"]
    relative = PurePosixPath(source)
    if (
        source.startswith("/")
        or relative.is_absolute()
        or len(relative.parts) < 3
        or relative.parts[0] != "donors"
        or ".." in relative.parts
    ):
        return [f"donor source must start with donors/<repo>/: {source}"]

    assert isinstance(donor_revisions, Mapping)
    repository = relative.parts[1]
    revision = donor_revisions.get(repository)
    if revision is None:
        return [f"donor source repository is not pinned: {repository}"]
    checkout = donors_root / repository
    if not checkout.is_dir():
        return [f"donor {repository}: repository is unavailable"]
    object_name = f"{revision}:{'/'.join(relative.parts[2:])}"
    exists = subprocess.run(
        ["git", "-C", str(checkout), "cat-file", "-e", object_name],
        capture_output=True,
        check=False,
    )
    if exists.returncode != 0:
        return [f"donor source is absent from pinned revision: {source}"]
    object_type = subprocess.run(
        ["git", "-C", str(checkout), "cat-file", "-t", object_name],
        capture_output=True,
        text=True,
        check=False,
    )
    if object_type.returncode != 0 or object_type.stdout.strip() != "blob":
        return [f"donor source is not a pinned blob: {source}"]
    return []


def safe_worktree_path(root: Path, relative: bytes) -> Path:
    decoded = os.fsdecode(relative)
    candidate = Path(decoded)
    if not relative or relative.startswith(b"/") or candidate.is_absolute() or ".." in candidate.parts:
        raise RuntimeError(f"Git returned an unsafe worktree path: {relative!r}")
    path = root / candidate
    try:
        path.parent.resolve().relative_to(root)
    except (RuntimeError, ValueError) as error:
        raise RuntimeError(f"Git path escapes the worktree through a symlink: {relative!r}") from error
    return path


def git_index_entries(root: Path) -> list[IndexEntry]:
    output = git_output(root, "ls-files", "--stage", "-z")
    entries = []
    for value in output.split(b"\0"):
        if not value:
            continue
        try:
            metadata, relative = value.split(b"\t", 1)
            mode, object_id, stage = metadata.split(b" ", 2)
        except ValueError as error:
            raise RuntimeError(f"Git returned an invalid index entry: {value!r}") from error
        safe_worktree_path(root, relative)
        entries.append(IndexEntry(mode=mode, object_id=object_id, stage=stage, relative=relative))
    return sorted(entries, key=lambda value: (value.relative, value.stage, value.mode, value.object_id))


def git_untracked_paths(root: Path) -> list[bytes]:
    output = git_output(root, "ls-files", "--others", "--exclude-standard", "-z")
    paths = {value for value in output.split(b"\0") if value}
    for relative in paths:
        safe_worktree_path(root, relative)
    return sorted(paths)


def append_bytes(digest: "hashlib._Hash", value: bytes) -> None:
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


def path_is_within_submodule(relative: bytes, submodules: set[bytes]) -> bool:
    return any(relative == submodule or relative.startswith(submodule + b"/") for submodule in submodules)


def append_worktree_path(digest: "hashlib._Hash", root: Path, relative: bytes) -> None:
    path = safe_worktree_path(root, relative)
    digest.update(b"path\0")
    append_bytes(digest, relative)
    try:
        metadata = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        digest.update(b"missing\0")
        return
    if stat.S_ISLNK(metadata.st_mode):
        target = os.fsencode(os.readlink(path))
        digest.update(b"symlink\0")
        append_bytes(digest, target)
        return
    if stat.S_ISREG(metadata.st_mode):
        digest.update(b"executable-bits\0")
        digest.update(struct.pack(">I", metadata.st_mode & 0o111))
        digest.update(b"content\0")
        digest.update(struct.pack(">Q", metadata.st_size))
        read = 0
        with path.open("rb") as value:
            while chunk := value.read(1024 * 1024):
                digest.update(chunk)
                read += len(chunk)
        if read != metadata.st_size:
            raise RuntimeError(f"worktree file changed while fingerprinting: {path}")
        return
    digest.update(b"other\0")
    digest.update(struct.pack(">I", stat.S_IFMT(metadata.st_mode)))


def append_invalid_gitlink_path(digest: "hashlib._Hash", path: Path, relative: bytes) -> None:
    """Fingerprint unexpected gitlink contents without following a nested repository."""
    metadata = path.lstat()
    digest.update(b"gitlink-path\0")
    append_bytes(digest, relative)
    if stat.S_ISLNK(metadata.st_mode):
        digest.update(b"symlink\0")
        append_bytes(digest, os.fsencode(os.readlink(path)))
        return
    if stat.S_ISREG(metadata.st_mode):
        digest.update(b"file\0")
        digest.update(struct.pack(">Q", metadata.st_size))
        with path.open("rb") as value:
            while chunk := value.read(1024 * 1024):
                digest.update(chunk)
        return
    if stat.S_ISDIR(metadata.st_mode):
        digest.update(b"directory\0")
        for child in sorted(path.iterdir(), key=lambda value: os.fsencode(value.name)):
            append_invalid_gitlink_path(digest, child, relative + b"/" + os.fsencode(child.name))
        return
    digest.update(b"other\0")
    digest.update(struct.pack(">I", stat.S_IFMT(metadata.st_mode)))


def initialized_submodule_root(path: Path) -> Optional[Path]:
    """Return a valid nested repository root, never Git's enclosing superproject."""
    marker = path / ".git"
    try:
        marker_metadata = marker.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    if stat.S_ISLNK(marker_metadata.st_mode) or not (
        stat.S_ISREG(marker_metadata.st_mode) or stat.S_ISDIR(marker_metadata.st_mode)
    ):
        return None
    try:
        inside = git_output(path, "rev-parse", "--is-inside-work-tree").strip()
        checked_out_root = Path(
            git_output(path, "rev-parse", "--show-toplevel").decode("utf-8").strip()
        ).resolve()
    except RuntimeError:
        return None
    resolved = path.resolve()
    return resolved if inside == b"true" and checked_out_root == resolved else None


def append_submodule(digest: "hashlib._Hash", root: Path, relative: bytes, object_id: bytes,
                     ancestors: frozenset[Path]) -> bool:
    path = safe_worktree_path(root, relative)
    digest.update(b"gitlink\0")
    append_bytes(digest, relative)
    digest.update(b"index-oid\0")
    append_bytes(digest, object_id)
    try:
        metadata = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        digest.update(b"uninitialized-missing\0")
        return False
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        digest.update(b"invalid\0")
        digest.update(struct.pack(">I", stat.S_IFMT(metadata.st_mode)))
        return True
    resolved = initialized_submodule_root(path)
    if resolved is None:
        children = tuple(path.iterdir())
        if not children:
            digest.update(b"uninitialized-empty\0")
            return False
        digest.update(b"invalid-non-repository\0")
        append_invalid_gitlink_path(digest, path, relative)
        return True
    if resolved in ancestors:
        raise RuntimeError(f"Git submodule recursion cycle: {resolved}")
    identity = worktree_identity(resolved, ancestors)
    digest.update(b"initialized\0")
    digest.update(b"head\0")
    append_bytes(digest, identity.head.encode("ascii"))
    digest.update(b"fingerprint\0")
    append_bytes(digest, identity.fingerprint.encode("ascii"))
    digest.update(b"dirty\0")
    digest.update(b"1" if identity.dirty else b"0")
    return identity.dirty or identity.head.encode("ascii") != object_id


def worktree_identity(root: Path, ancestors: frozenset[Path] = frozenset()) -> WorktreeIdentity:
    root = root.resolve()
    if root in ancestors:
        raise RuntimeError(f"Git worktree recursion cycle: {root}")
    ancestors = ancestors | {root}
    head = git_output(root, "rev-parse", "HEAD").decode("ascii").strip()
    entries = git_index_entries(root)
    gitlinks = {value.relative for value in entries if value.mode == b"160000"}
    tracked_paths = {value.relative for value in entries if value.relative not in gitlinks}
    paths = tracked_paths | {value for value in git_untracked_paths(root) if not path_is_within_submodule(value, gitlinks)}

    digest = hashlib.sha256()
    digest.update(WORKTREE_FINGERPRINT_FORMAT)
    digest.update(b"head\0")
    digest.update(head.encode("ascii"))
    digest.update(b"\0")
    for entry in entries:
        digest.update(b"index-entry\0")
        append_bytes(digest, entry.relative)
        append_bytes(digest, entry.mode)
        append_bytes(digest, entry.object_id)
        append_bytes(digest, entry.stage)
    for relative in sorted(paths):
        append_worktree_path(digest, root, relative)

    submodule_dirty = False
    for relative in sorted(gitlinks):
        stage_zero = next((entry for entry in entries if entry.relative == relative and entry.stage == b"0"), None)
        if stage_zero is None:
            digest.update(b"gitlink-unmerged\0")
            append_bytes(digest, relative)
            submodule_dirty = True
            continue
        submodule_dirty = append_submodule(digest, root, relative, stage_zero.object_id, ancestors) or submodule_dirty

    dirty = bool(git_output(root, "status", "--porcelain=v1", "-z")) or submodule_dirty
    return WorktreeIdentity(head=head, fingerprint=digest.hexdigest(), dirty=dirty)


def write_if_changed(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == value:
        return
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value)
    temporary.replace(path)


def cxx_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def emit_build_info(root: Path, output_header: Path, output_stamp: Path, compiler_path: str,
                    compiler_id: str, compiler_version: str, build_profile: str) -> None:
    identity = worktree_identity(root)
    if not build_profile:
        raise RuntimeError("Forge interop build profile is empty")
    compiler = {
        "path": str(Path(compiler_path).resolve()),
        "id": compiler_id,
        "version": compiler_version,
    }
    header = (
        "// Generated by tests/libp2p_interop/provenance.py.\n"
        "#pragma once\n"
        f"#define FORGE_INTEROP_BUILD_FORGE_HEAD {cxx_string(identity.head)}\n"
        f"#define FORGE_INTEROP_BUILD_WORKTREE_SHA256 {cxx_string(identity.fingerprint)}\n"
        f"#define FORGE_INTEROP_BUILD_WORKTREE_DIRTY {1 if identity.dirty else 0}\n"
        f"#define FORGE_INTEROP_BUILD_COMPILER_PATH {cxx_string(compiler['path'])}\n"
        f"#define FORGE_INTEROP_BUILD_COMPILER_ID {cxx_string(compiler['id'])}\n"
        f"#define FORGE_INTEROP_BUILD_COMPILER_VERSION {cxx_string(compiler['version'])}\n"
        f"#define FORGE_INTEROP_BUILD_PROFILE {cxx_string(build_profile)}\n"
    )
    stamp = json.dumps(
        {
            "schema_version": 2,
            "forge": identity.as_json(),
            "compiler": compiler,
            "build_profile": build_profile,
        },
        indent=2,
        sort_keys=True,
    ) + "\n"
    write_if_changed(output_header, header)
    write_if_changed(output_stamp, stamp)


def main() -> int:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    fingerprint = subcommands.add_parser("fingerprint")
    fingerprint.add_argument("--forge-root", required=True)
    build_info = subcommands.add_parser("emit-build-info")
    build_info.add_argument("--forge-root", required=True)
    build_info.add_argument("--output-header", required=True)
    build_info.add_argument("--output-stamp", required=True)
    build_info.add_argument("--compiler-path", required=True)
    build_info.add_argument("--compiler-id", required=True)
    build_info.add_argument("--compiler-version", required=True)
    build_info.add_argument("--build-profile", required=True)
    args = parser.parse_args()

    if args.command == "fingerprint":
        print(json.dumps(worktree_identity(Path(args.forge_root)).as_json(), sort_keys=True))
        return 0
    emit_build_info(
        Path(args.forge_root),
        Path(args.output_header),
        Path(args.output_stamp),
        args.compiler_path,
        args.compiler_id,
        args.compiler_version,
        args.build_profile,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
