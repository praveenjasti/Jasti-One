import os
import pytest
from pdcm.services.path_policy import is_protected_path, validate_user_scan_root

@pytest.mark.skipif(os.name != "nt", reason="Windows path policy test")
def test_windows_system_directory_is_protected():
    assert is_protected_path(r"C:\Windows\System32")

@pytest.mark.skipif(os.name != "nt", reason="Windows path policy test")
def test_program_files_is_protected():
    assert is_protected_path(r"C:\Program Files")


@pytest.mark.skipif(os.name != "nt", reason="Windows path policy test")
def test_recycle_bin_is_protected_on_current_volume():
    system_drive = os.environ.get("SystemDrive", "C:")
    assert is_protected_path(system_drive + r"\$Recycle.Bin")


def test_validate_user_scan_root_rejects_missing_directory(tmp_path):
    with pytest.raises((FileNotFoundError, ValueError)):
        validate_user_scan_root(tmp_path / "missing")


def test_validate_user_scan_root_rejects_symlink(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic-link creation is unavailable")
    with pytest.raises(ValueError, match="Symbolic links and junctions"):
        validate_user_scan_root(link)


def test_personal_folder_named_windows_is_not_protected(tmp_path):
    folder = tmp_path / "Windows"
    folder.mkdir()
    assert validate_user_scan_root(folder) == folder.resolve()
