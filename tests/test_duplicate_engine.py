import os
from pathlib import Path

import pytest

import pdcm.engines.duplicate_engine as duplicate_engine
from pdcm.engines.duplicate_engine import DuplicateEngine


def _remove_junction(path):
    if path.exists() and duplicate_engine.is_link_or_junction(path):
        os.rmdir(path)


def test_exact_duplicate_scan_is_read_only(tmp_path):
    folder = tmp_path / "Pictures"
    folder.mkdir()
    (folder / "one.jpg").write_bytes(b"same-content")
    (folder / "renamed-copy.jpg").write_bytes(b"same-content")
    (folder / "other.jpg").write_bytes(b"different")
    groups = DuplicateEngine().scan(folder)
    assert len(groups) == 1
    assert len(groups[0]) == 2
    assert (folder / "one.jpg").exists()
    assert (folder / "renamed-copy.jpg").exists()


def test_same_size_and_same_edges_but_different_middle_are_not_duplicates(tmp_path):
    folder = tmp_path / "Videos"
    folder.mkdir()
    edge = b"A" * (64 * 1024)
    tail = b"Z" * (64 * 1024)
    (folder / "first.bin").write_bytes(edge + b"X" * 8192 + tail)
    (folder / "second.bin").write_bytes(edge + b"Y" * 8192 + tail)
    assert DuplicateEngine().scan(folder) == []


def test_nested_exact_duplicates_are_grouped(tmp_path):
    folder = tmp_path / "Files"
    (folder / "a").mkdir(parents=True)
    (folder / "b").mkdir()
    payload = b"repeat" * 10000
    (folder / "a" / "one.dat").write_bytes(payload)
    (folder / "b" / "two.dat").write_bytes(payload)
    groups = DuplicateEngine().scan(folder)
    assert len(groups) == 1
    assert {item.path.rsplit("/", 1)[-1].rsplit(chr(92), 1)[-1] for item in groups[0]} == {"one.dat", "two.dat"}


def test_scan_does_not_follow_directory_symlinks(tmp_path, make_symlink):
    folder = tmp_path / "Files"
    folder.mkdir()
    outside = tmp_path / "Outside"
    outside.mkdir()
    (outside / "one.bin").write_bytes(b"outside")
    (outside / "two.bin").write_bytes(b"outside")
    link = folder / "linked"
    make_symlink(link, outside, target_is_directory=True)
    assert DuplicateEngine().scan(folder) == []


def test_scan_skips_file_symlinks(tmp_path, make_symlink):
    folder = tmp_path / "Files"
    folder.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"same")
    (folder / "inside.bin").write_bytes(b"same")
    make_symlink(folder / "linked.bin", outside)
    assert DuplicateEngine().scan(folder) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows junction test")
def test_directory_junction_path_traversal_stays_within_selected_root(tmp_path, make_junction):
    folder = tmp_path / "Files"
    folder.mkdir()
    (folder / "inside-one.bin").write_bytes(b"inside")
    (folder / "inside-two.bin").write_bytes(b"inside")
    outside = tmp_path / "Outside"
    outside.mkdir()
    (outside / "outside-one.bin").write_bytes(b"outside")
    (outside / "outside-two.bin").write_bytes(b"outside")
    junction = folder / "junction"
    make_junction(junction, outside)
    try:
        groups = DuplicateEngine().scan(folder)
    finally:
        _remove_junction(junction)

    assert len(groups) == 1
    assert {item.path for item in groups[0]} == {
        str(folder / "inside-one.bin"),
        str(folder / "inside-two.bin"),
    }


@pytest.mark.skipif(os.name != "nt", reason="Windows concurrent junction test")
def test_concurrent_directory_replacement_with_junction_stays_confined(
    monkeypatch, tmp_path, make_junction
):
    folder = tmp_path / "Files"
    race_directory = folder / "changing"
    race_directory.mkdir(parents=True)
    (race_directory / "one.bin").write_bytes(b"outside")
    (race_directory / "two.bin").write_bytes(b"outside")
    outside = tmp_path / "Outside"
    outside.mkdir()
    (outside / "one.bin").write_bytes(b"outside")
    (outside / "two.bin").write_bytes(b"outside")
    (folder / "inside-one.bin").write_bytes(b"inside")
    (folder / "inside-two.bin").write_bytes(b"inside")

    original_open = duplicate_engine._windows_open_directory
    original_directory = tmp_path / "changing-before-race"
    replaced = False

    def replace_before_open(path, root_final_path):
        nonlocal replaced
        if path == race_directory and not replaced:
            race_directory.rename(original_directory)
            make_junction(race_directory, outside)
            replaced = True
        return original_open(path, root_final_path)

    monkeypatch.setattr(duplicate_engine, "_windows_open_directory", replace_before_open)
    try:
        groups = DuplicateEngine().scan(folder)
    finally:
        _remove_junction(race_directory)

    assert replaced
    assert len(groups) == 1
    assert {item.path for item in groups[0]} == {
        str(folder / "inside-one.bin"),
        str(folder / "inside-two.bin"),
    }


@pytest.mark.skipif(os.name != "nt", reason="Windows root-validation race test")
def test_scan_does_not_resolve_selected_root_before_handle_validation(
    monkeypatch, tmp_path, make_junction
):
    folder = tmp_path / "Selected"
    folder.mkdir()
    (folder / "inside-one.bin").write_bytes(b"inside")
    (folder / "inside-two.bin").write_bytes(b"inside")
    outside = tmp_path / "Outside"
    outside.mkdir()
    (outside / "outside-one.bin").write_bytes(b"outside")
    (outside / "outside-two.bin").write_bytes(b"outside")

    original_directory = tmp_path / "selected-before-race"
    original_resolve = Path.resolve
    replaced = False

    def replace_before_resolve(path, *args, **kwargs):
        nonlocal replaced
        if path == folder and not replaced:
            folder.rename(original_directory)
            make_junction(folder, outside)
            replaced = True
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", replace_before_resolve)
    try:
        groups = DuplicateEngine().scan(folder)
    finally:
        if replaced:
            _remove_junction(folder)

    assert not replaced
    assert len(groups) == 1
    assert {item.path for item in groups[0]} == {
        str(folder / "inside-one.bin"),
        str(folder / "inside-two.bin"),
    }


@pytest.mark.skipif(os.name != "nt", reason="Windows active-directory handle test")
def test_active_directory_handle_prevents_rename_before_enumeration(monkeypatch, tmp_path):
    folder = tmp_path / "Files"
    race_directory = folder / "changing"
    race_directory.mkdir(parents=True)
    (race_directory / "one.bin").write_bytes(b"identical")
    (race_directory / "two.bin").write_bytes(b"identical")

    original_scandir = duplicate_engine.os.scandir
    moved_directory = tmp_path / "changing-while-open"
    attempted = False
    rename_blocked = False

    def try_rename_before_enumeration(path, *args, **kwargs):
        nonlocal attempted, rename_blocked
        if path == race_directory and not attempted:
            attempted = True
            try:
                race_directory.rename(moved_directory)
            except OSError:
                rename_blocked = True
        return original_scandir(path, *args, **kwargs)

    monkeypatch.setattr(duplicate_engine.os, "scandir", try_rename_before_enumeration)
    groups = DuplicateEngine().scan(folder)

    assert attempted
    assert rename_blocked
    assert len(groups) == 1
    assert {item.path for item in groups[0]} == {
        str(race_directory / "one.bin"),
        str(race_directory / "two.bin"),
    }


def test_file_replaced_after_discovery_is_not_reported(monkeypatch, tmp_path):
    folder = tmp_path / "Files"
    folder.mkdir()
    replaced = folder / "one.bin"
    unchanged = folder / "two.bin"
    replaced.write_bytes(b"identical")
    unchanged.write_bytes(b"identical")
    original_fingerprint = duplicate_engine._quick_fingerprint
    did_replace = False

    def replace_before_fingerprint(path, size, *args):
        nonlocal did_replace
        if path == replaced and not did_replace:
            replacement = folder / "replacement.bin"
            replacement.write_bytes(b"replaced!")
            replacement.replace(replaced)
            did_replace = True
        return original_fingerprint(path, size, *args)

    monkeypatch.setattr(duplicate_engine, "_quick_fingerprint", replace_before_fingerprint)
    assert DuplicateEngine().scan(folder) == []
    assert did_replace


def test_file_changed_during_hash_is_not_reported(monkeypatch, tmp_path):
    folder = tmp_path / "Files"
    folder.mkdir()
    changed = folder / "one.bin"
    other = folder / "two.bin"
    changed.write_bytes(b"identical")
    other.write_bytes(b"identical")
    original_hash = duplicate_engine._sha256_file

    def hash_then_modify(path, *args):
        digest = original_hash(path)
        if path == changed:
            path.write_bytes(b"modified")
        return digest

    monkeypatch.setattr(duplicate_engine, "_sha256_file", hash_then_modify)
    assert DuplicateEngine().scan(folder) == []
