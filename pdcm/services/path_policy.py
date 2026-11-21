from pathlib import Path
import os
import stat

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_PROTECTED_ROOT_NAMES = {
    "$Recycle.Bin",
    "Recovery",
    "System Volume Information",
}


def is_link_or_junction(path: str | os.PathLike[str]) -> bool:
    info = Path(path).lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _protected_roots() -> list[Path]:
    roots: list[Path] = []
    for variable in ("SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value).resolve())

    return roots


def is_protected_path(path: str | os.PathLike[str]) -> bool:
    resolved = Path(path).resolve()
    if resolved == Path(resolved.anchor):
        return True
    if os.name == "nt":
        volume_root = Path(resolved.anchor)
        roots = _protected_roots()
        roots.extend(volume_root / name for name in _PROTECTED_ROOT_NAMES)
        return any(_is_within(resolved, root) for root in roots)
    return False


def validate_user_scan_root(path: str | os.PathLike[str]) -> Path:
    candidate = Path(path).expanduser().absolute()
    if not candidate.exists():
        raise FileNotFoundError(candidate)
    if not candidate.is_dir():
        raise ValueError("Choose an existing folder.")

    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current /= part
        if is_link_or_junction(current):
            raise ValueError("Symbolic links and junctions are not allowed in scan paths.")

    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("Choose an existing folder.")
    if is_protected_path(resolved):
        raise ValueError("Protected system location. Choose a personal data folder.")
    return resolved
