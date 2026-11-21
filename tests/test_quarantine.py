import hashlib
import json
import os
from pathlib import Path

import pytest

from pdcm.engines.cleaner_engine import CleanerScanEngine
from pdcm.engines.duplicate_engine import DuplicateEngine, _file_signature
from pdcm.services.quarantine import (
    BatchQuarantineError,
    DuplicateKeeperError,
    ManifestValidationError,
    QuarantineCandidate,
    QuarantineError,
    QuarantineService,
)
from pdcm.services.quarantine_store import (
    STORE_NAME,
    QuarantineStoreError,
    validate_quarantine_store,
)
import pdcm.services.quarantine as quarantine_module


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Quarantine moves use Windows handle-based rename")


@pytest.fixture(autouse=True)
def enable_file_moves_for_synthetic_tests(monkeypatch):
    monkeypatch.setattr(quarantine_module, "_FILE_MOVES_ENABLED", True)


def _candidate(root: Path, path: Path, category: str = "synthetic") -> QuarantineCandidate:
    info = path.stat()
    return QuarantineCandidate(
        str(root),
        str(path),
        info.st_size,
        info.st_mtime_ns,
        _file_signature(info),
        hashlib.sha256(path.read_bytes()).hexdigest(),
        category,
        "Synthetic test file",
        "Synthetic data only.",
    )


def test_quarantine_and_restore_are_disabled_by_default(monkeypatch, tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "disabled.txt"
    source.write_text("synthetic", encoding="utf-8")
    candidate = _candidate(root, source)
    service = QuarantineService(root)
    monkeypatch.setattr(quarantine_module, "_FILE_MOVES_ENABLED", False)

    with pytest.raises(QuarantineError, match="disabled until the security gate"):
        service.quarantine_selected([candidate])

    assert source.read_text(encoding="utf-8") == "synthetic"
    assert not (root / STORE_NAME).exists()
    monkeypatch.setattr(quarantine_module, "_FILE_MOVES_ENABLED", True)
    operation = service.quarantine_selected([candidate])[0]
    monkeypatch.setattr(quarantine_module, "_FILE_MOVES_ENABLED", False)

    with pytest.raises(QuarantineError, match="disabled until the security gate"):
        service.restore(operation.operation_id)

    assert not source.exists()
    assert (root / STORE_NAME / operation.operation_id / "payload").read_text(
        encoding="utf-8"
    ) == "synthetic"


def test_quarantine_and_restore_round_trip_excludes_store_from_scans(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "example.bin"
    source.write_bytes(b"synthetic quarantine data")
    candidate = _candidate(root, source)
    service = QuarantineService(root)

    quarantined = service.quarantine_selected([candidate])

    assert not source.exists()
    assert quarantined[0].status == "QUARANTINED"
    assert validate_quarantine_store(root / STORE_NAME)
    operations = service.list_operations()
    assert [operation.operation_id for operation in operations] == [quarantined[0].operation_id]
    assert operations[0].status == "QUARANTINED"
    scan = CleanerScanEngine().scan(root)
    assert scan.files_scanned == 0
    assert scan.duplicates == []
    with pytest.raises(ValueError, match="quarantine store"):
        CleanerScanEngine().scan(root / STORE_NAME / quarantined[0].operation_id)
    with pytest.raises(ValueError, match="quarantine store"):
        DuplicateEngine().scan(root / STORE_NAME / quarantined[0].operation_id)

    restored = service.restore(quarantined[0].operation_id)

    assert restored.status == "RESTORED"
    assert source.read_bytes() == b"synthetic quarantine data"
    assert service.list_operations()[0].status == "RESTORED"


def test_quarantine_rejects_file_changed_after_scan(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "changed.txt"
    source.write_text("before", encoding="utf-8")
    candidate = _candidate(root, source)
    source.write_text("after", encoding="utf-8")

    with pytest.raises(BatchQuarantineError, match="changed after the scan"):
        QuarantineService(root).quarantine_selected([candidate])

    assert source.read_text(encoding="utf-8") == "after"
    assert not list((root / STORE_NAME).glob("*/payload"))


def test_quarantine_rejects_path_replacement_after_scan_before_open(monkeypatch, tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "replace-after-scan.txt"
    source.write_text("original", encoding="utf-8")
    candidate = _candidate(root, source)
    service = QuarantineService(root)
    original_open = service._open_candidate
    replaced = False

    def replace_before_open(path, root_final_path, scan_candidate):
        nonlocal replaced
        if not replaced:
            replacement = root / "replacement.txt"
            replacement.write_text("concurrent replacement", encoding="utf-8")
            replacement.replace(path)
            replaced = True
        return original_open(path, root_final_path, scan_candidate)

    monkeypatch.setattr(service, "_open_candidate", replace_before_open)
    with pytest.raises(BatchQuarantineError, match="replaced while being validated"):
        service.quarantine_selected([candidate])

    assert replaced
    assert source.read_text(encoding="utf-8") == "concurrent replacement"
    assert not list((root / STORE_NAME).glob("*/payload"))


def test_open_quarantine_source_denies_write_and_rename_races(monkeypatch, tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "open-handle-race.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    candidate = _candidate(root, source)
    original_verify = service._verify_open_handle
    write_blocked = False
    rename_blocked = False

    def attempt_mutation_then_verify(handle, manifest, cancellation_event):
        nonlocal write_blocked, rename_blocked
        if source.exists():
            try:
                source.write_text("concurrent write", encoding="utf-8")
            except OSError:
                write_blocked = True
            try:
                source.rename(root / "renamed-during-quarantine.txt")
            except OSError:
                rename_blocked = True
        return original_verify(handle, manifest, cancellation_event)

    monkeypatch.setattr(service, "_verify_open_handle", attempt_mutation_then_verify)
    result = service.quarantine_selected([candidate])

    assert write_blocked
    assert rename_blocked
    assert result[0].status == "QUARANTINED"
    assert not source.exists()
    assert (root / STORE_NAME / result[0].operation_id / "payload").read_text(
        encoding="utf-8"
    ) == "synthetic"


def test_quarantine_rejects_different_handle_volume(monkeypatch, tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "volume.txt"
    source.write_text("synthetic", encoding="utf-8")
    candidate = _candidate(root, source)
    original_identity = quarantine_module._handle_file_identity

    def report_other_volume(handle):
        identity = original_identity(handle)
        if identity[1] == candidate.file_signature[1]:
            return (identity[0] + 1, *identity[1:])
        return identity

    monkeypatch.setattr(quarantine_module, "_handle_file_identity", report_other_volume)

    with pytest.raises(BatchQuarantineError, match="different volume"):
        QuarantineService(root).quarantine_selected([candidate])

    assert source.read_text(encoding="utf-8") == "synthetic"
    assert not list((root / STORE_NAME).glob("*/manifest.json"))


def test_duplicate_group_requires_an_explicit_survivor(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    first = root / "first.bin"
    second = root / "second.bin"
    first.write_bytes(b"same synthetic content")
    second.write_bytes(b"same synthetic content")
    candidates = [_candidate(root, first), _candidate(root, second)]
    service = QuarantineService(root)

    with pytest.raises(DuplicateKeeperError, match="At least one verified copy"):
        service.quarantine_selected(candidates, [candidates])

    operation = service.quarantine_selected([candidates[0]], [candidates])
    assert not first.exists()
    assert second.read_bytes() == b"same synthetic content"
    assert operation[0].status == "QUARANTINED"


def test_restore_never_overwrites_an_existing_destination(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "conflict.txt"
    source.write_text("original", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    source.write_text("new destination data", encoding="utf-8")

    with pytest.raises(QuarantineError, match="already exists"):
        service.restore(operation.operation_id)

    assert source.read_text(encoding="utf-8") == "new destination data"
    assert service.list_operations()[0].status == "QUARANTINED"


def test_restore_no_overwrite_holds_when_destination_appears_during_restore(monkeypatch, tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "race.txt"
    source.write_text("original", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    original_rename = quarantine_module._rename_handle

    def create_destination_then_rename(handle, destination):
        if destination == source:
            source.write_text("concurrent destination", encoding="utf-8")
        return original_rename(handle, destination)

    monkeypatch.setattr(quarantine_module, "_rename_handle", create_destination_then_rename)

    with pytest.raises(OSError, match="already exists"):
        service.restore(operation.operation_id)

    assert source.read_text(encoding="utf-8") == "concurrent destination"
    assert service.list_operations()[0].status == "QUARANTINED"
    assert (root / STORE_NAME / operation.operation_id / "payload").read_text(
        encoding="utf-8"
    ) == "original"


def test_quarantine_holds_destination_directory_against_replacement(monkeypatch, tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "directory-handle.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    original_rename = quarantine_module._rename_handle
    rename_blocked = False

    def try_replace_operation_directory(handle, destination):
        nonlocal rename_blocked
        if destination.name == "payload":
            moved_directory = destination.parent.with_name("operation-moved")
            try:
                destination.parent.rename(moved_directory)
            except OSError:
                rename_blocked = True
        return original_rename(handle, destination)

    monkeypatch.setattr(quarantine_module, "_rename_handle", try_replace_operation_directory)
    operation = service.quarantine_selected([_candidate(root, source)])[0]

    assert rename_blocked
    assert operation.status == "QUARANTINED"
    assert (root / STORE_NAME / operation.operation_id / "payload").read_text(
        encoding="utf-8"
    ) == "synthetic"


def test_restore_holds_destination_parent_against_replacement(monkeypatch, tmp_path):
    root = tmp_path / "selected"
    parent = root / "nested"
    parent.mkdir(parents=True)
    source = parent / "directory-handle-restore.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    original_rename = quarantine_module._rename_handle
    rename_blocked = False

    def try_replace_restore_parent(handle, destination):
        nonlocal rename_blocked
        if destination == source:
            moved_parent = parent.with_name("nested-moved")
            try:
                parent.rename(moved_parent)
            except OSError:
                rename_blocked = True
        return original_rename(handle, destination)

    monkeypatch.setattr(quarantine_module, "_rename_handle", try_replace_restore_parent)
    restored = service.restore(operation.operation_id)

    assert rename_blocked
    assert restored.status == "RESTORED"
    assert source.read_text(encoding="utf-8") == "synthetic"


def test_malicious_manifest_outside_original_scope_is_rejected(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "manifest.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    manifest_path = root / STORE_NAME / operation.operation_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert set(manifest) == {
        "schema_version",
        "application_version",
        "store_id",
        "operation_id",
        "original_root",
        "original_path",
        "object_id",
        "size",
        "sha256",
        "modified_ns",
        "file_identity",
        "created_at",
        "status",
    }
    manifest["original_path"] = str(tmp_path / "outside.txt")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ManifestValidationError, match="outside the permitted original scope"):
        service.list_operations()


def test_manifest_path_traversal_is_rejected(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "traversal.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    manifest_path = root / STORE_NAME / operation.operation_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["original_path"] = str(root / ".." / "outside.txt")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ManifestValidationError, match="paths or timestamp are invalid"):
        service.list_operations()


def test_interrupted_move_is_recorded_as_failed_without_losing_source(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "interrupted.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    manifest_path = root / STORE_NAME / operation.operation_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload = manifest_path.parent / "payload"
    payload.rename(source)
    manifest["status"] = "MOVING"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    records = service.list_operations()

    assert source.read_text(encoding="utf-8") == "synthetic"
    assert records[0].status == "FAILED"


def test_interrupted_move_after_rename_is_reconciled_as_quarantined(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "moved-before-state-update.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    manifest_path = root / STORE_NAME / operation.operation_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["status"] = "MOVING"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    records = service.list_operations()

    assert not source.exists()
    assert records[0].status == "QUARANTINED"


def test_ambiguous_interrupted_move_requires_recovery_before_more_quarantine(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "ambiguous.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    operation_dir = root / STORE_NAME / operation.operation_id
    manifest_path = operation_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["status"] = "MOVING"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    source.write_text("synthetic", encoding="utf-8")

    assert service.list_operations()[0].status == "RECOVERY_REQUIRED"
    with pytest.raises(QuarantineError, match="Resolve the existing recovery-required"):
        service.quarantine_selected([_candidate(root, source)])


def test_restore_rejects_modified_quarantine_payload(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "modified-payload.txt"
    source.write_text("original", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    payload = root / STORE_NAME / operation.operation_id / "payload"
    payload.write_text("tampered", encoding="utf-8")
    payload_info = payload.stat()
    manifest_path = payload.parent / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    os.utime(payload, ns=(payload_info.st_atime_ns, manifest["modified_ns"]))

    with pytest.raises(QuarantineError, match="SHA-256"):
        service.restore(operation.operation_id)

    assert not source.exists()
    assert payload.read_text(encoding="utf-8") == "tampered"


def test_invalid_reserved_quarantine_directory_aborts_scan(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    store = root / STORE_NAME
    store.mkdir()
    (store / ".store.json").write_text("{}", encoding="utf-8")

    with pytest.raises(QuarantineStoreError):
        CleanerScanEngine().scan(root, include_duplicates=False)


def test_quarantine_rejects_a_file_reached_through_an_external_junction(tmp_path, make_junction):
    root = tmp_path / "selected"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    external_file = outside / "external.txt"
    external_file.write_text("outside approved scan root", encoding="utf-8")
    junction = root / "linked"
    make_junction(junction, outside)
    candidate = _candidate(root, junction / external_file.name)

    with pytest.raises(BatchQuarantineError, match="outside the approved scan root"):
        QuarantineService(root).quarantine_selected([candidate])

    assert external_file.read_text(encoding="utf-8") == "outside approved scan root"
    assert not list((root / STORE_NAME).glob("*/payload"))


def test_quarantine_rejects_a_file_symlink_to_an_external_target(tmp_path, make_symlink):
    root = tmp_path / "selected"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("external data", encoding="utf-8")
    link = root / "linked.txt"
    make_symlink(link, outside)
    candidate = _candidate(root, link)

    with pytest.raises(BatchQuarantineError, match="Only unchanged regular files"):
        QuarantineService(root).quarantine_selected([candidate])

    assert outside.read_text(encoding="utf-8") == "external data"
    assert link.is_symlink()
    assert not list((root / STORE_NAME).glob("*/payload"))


def test_restore_rejects_symlinked_destination_parent(tmp_path, make_symlink):
    root = tmp_path / "selected"
    original_parent = root / "original-parent"
    outside = tmp_path / "outside"
    original_parent.mkdir(parents=True)
    outside.mkdir()
    source = original_parent / "item.txt"
    source.write_text("original", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    moved_parent = root / "original-parent-moved"
    original_parent.rename(moved_parent)
    make_symlink(original_parent, outside, target_is_directory=True)

    with pytest.raises(QuarantineError, match="parent directory is not a safe"):
        service.restore(operation.operation_id)

    payload = root / STORE_NAME / operation.operation_id / "payload"
    assert payload.read_text(encoding="utf-8") == "original"
    assert list(outside.iterdir()) == []


def test_operation_lock_rejects_concurrent_quarantine(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "locked.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    competing_service = QuarantineService(root)
    candidate = _candidate(root, source)
    service._ensure_store()

    with service._operation_lock():
        with pytest.raises(QuarantineError, match="already in progress"):
            competing_service.quarantine_selected([candidate])

    assert source.read_text(encoding="utf-8") == "synthetic"
    assert not list((root / STORE_NAME).glob("*/payload"))


def test_repeated_quarantine_does_not_duplicate_or_lose_the_payload(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "repeat.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    candidate = _candidate(root, source)
    operation = service.quarantine_selected([candidate])[0]

    with pytest.raises(BatchQuarantineError):
        service.quarantine_selected([candidate])

    payload = root / STORE_NAME / operation.operation_id / "payload"
    assert payload.read_text(encoding="utf-8") == "synthetic"
    assert len(service.list_operations()) == 1


def test_restore_rejects_concurrent_restore_of_same_operation(monkeypatch, tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "concurrent-restore.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    original_rename = quarantine_module._rename_handle
    nested_restore_rejected = False

    def nested_restore_then_rename(handle, destination):
        nonlocal nested_restore_rejected
        try:
            service.restore(operation.operation_id)
        except QuarantineError as error:
            nested_restore_rejected = "already in progress" in str(error)
        return original_rename(handle, destination)

    monkeypatch.setattr(quarantine_module, "_rename_handle", nested_restore_then_rename)
    restored = service.restore(operation.operation_id)

    assert nested_restore_rejected
    assert restored.status == "RESTORED"
    assert source.read_text(encoding="utf-8") == "synthetic"


def test_disk_full_before_move_leaves_the_original_file_untouched(monkeypatch, tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "disk-full-before-move.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    candidate = _candidate(root, source)
    original_write = service._write_manifest

    def fail_moving_state(operation_dir, manifest, operation_final):
        if manifest["status"] == "MOVING":
            raise OSError("synthetic disk full")
        return original_write(operation_dir, manifest, operation_final)

    monkeypatch.setattr(service, "_write_manifest", fail_moving_state)
    with pytest.raises(BatchQuarantineError, match="synthetic disk full"):
        service.quarantine_selected([candidate])

    assert source.read_text(encoding="utf-8") == "synthetic"
    assert not list((root / STORE_NAME).glob("*/payload"))
    assert service.list_operations()[0].status == "FAILED"


def test_disk_full_persisting_restored_state_rolls_file_back_to_quarantine(monkeypatch, tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "disk-full-after-restore.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    original_write = service._write_manifest

    def fail_restored_state(operation_dir, manifest, operation_final):
        if manifest["status"] == "RESTORED":
            raise OSError("synthetic disk full")
        return original_write(operation_dir, manifest, operation_final)

    monkeypatch.setattr(service, "_write_manifest", fail_restored_state)
    with pytest.raises(OSError, match="synthetic disk full"):
        service.restore(operation.operation_id)

    payload = root / STORE_NAME / operation.operation_id / "payload"
    assert not source.exists()
    assert payload.read_text(encoding="utf-8") == "synthetic"
    assert service.list_operations()[0].status == "QUARANTINED"


def test_atomic_manifest_replace_failure_keeps_previous_manifest_readable(monkeypatch, tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "manifest-write-failure.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    manifest_path = root / STORE_NAME / operation.operation_id / "manifest.json"
    original_bytes = manifest_path.read_bytes()
    manifest = json.loads(original_bytes)
    manifest["status"] = "FAILED"

    def fail_replace(_source, _destination):
        raise OSError("synthetic disk full")

    monkeypatch.setattr(quarantine_module.os, "replace", fail_replace)
    with pytest.raises(QuarantineError, match="could not be saved atomically"):
        service._write_manifest(manifest_path.parent, manifest, None)

    assert manifest_path.read_bytes() == original_bytes
    monkeypatch.undo()
    assert service.list_operations()[0].status == "QUARANTINED"


def test_manifest_duplicate_json_keys_are_rejected(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    source = root / "duplicate-keys.txt"
    source.write_text("synthetic", encoding="utf-8")
    service = QuarantineService(root)
    operation = service.quarantine_selected([_candidate(root, source)])[0]
    manifest_path = root / STORE_NAME / operation.operation_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    serialized = json.dumps(manifest, separators=(",", ":"))
    manifest_path.write_text(serialized[:-1] + ',"status":"QUARANTINED"}', encoding="utf-8")

    with pytest.raises(ManifestValidationError, match="not valid UTF-8 JSON"):
        service.list_operations()
