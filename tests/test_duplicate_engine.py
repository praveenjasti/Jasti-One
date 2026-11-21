import pytest

import pdcm.engines.duplicate_engine as duplicate_engine
from pdcm.engines.duplicate_engine import DuplicateEngine


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


def test_scan_does_not_follow_directory_symlinks(tmp_path):
    folder = tmp_path / "Files"
    folder.mkdir()
    outside = tmp_path / "Outside"
    outside.mkdir()
    (outside / "one.bin").write_bytes(b"outside")
    (outside / "two.bin").write_bytes(b"outside")
    link = folder / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        import pytest
        pytest.skip("Directory symbolic-link creation is unavailable")
    assert DuplicateEngine().scan(folder) == []


def test_scan_skips_file_symlinks(tmp_path):
    folder = tmp_path / "Files"
    folder.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"same")
    (folder / "inside.bin").write_bytes(b"same")
    try:
        (folder / "linked.bin").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("File symbolic-link creation is unavailable")
    assert DuplicateEngine().scan(folder) == []


def test_file_changed_during_hash_is_not_reported(monkeypatch, tmp_path):
    folder = tmp_path / "Files"
    folder.mkdir()
    changed = folder / "one.bin"
    other = folder / "two.bin"
    changed.write_bytes(b"identical")
    other.write_bytes(b"identical")
    original_hash = duplicate_engine._sha256_file

    def hash_then_modify(path):
        digest = original_hash(path)
        if path == changed:
            path.write_bytes(b"modified")
        return digest

    monkeypatch.setattr(duplicate_engine, "_sha256_file", hash_then_modify)
    assert DuplicateEngine().scan(folder) == []
