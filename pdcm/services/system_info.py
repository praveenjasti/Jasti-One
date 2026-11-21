from dataclasses import dataclass
import os
from pathlib import Path

import psutil

from .path_policy import is_link_or_junction


@dataclass(frozen=True)
class DriveSummary:
    mountpoint: str
    total_bytes: int
    used_bytes: int
    free_bytes: int


@dataclass(frozen=True)
class ProcessSummary:
    pid: int
    name: str
    memory_bytes: int
    cpu_percent: float


@dataclass(frozen=True)
class StartupEntry:
    name: str
    command: str
    source: str


def memory_summary():
    vm = psutil.virtual_memory()
    return f"{vm.percent}% used · {vm.available / (1024**3):.1f} GB available of {vm.total / (1024**3):.1f} GB"


def drive_summaries() -> tuple[list[DriveSummary], int]:
    drives = []
    seen = set()
    inaccessible = 0
    try:
        partitions = psutil.disk_partitions(all=False)
    except (psutil.Error, OSError):
        return drives, 1
    for partition in partitions:
        mountpoint = partition.mountpoint
        if mountpoint in seen:
            continue
        seen.add(mountpoint)
        try:
            usage = psutil.disk_usage(mountpoint)
        except (OSError, PermissionError):
            inaccessible += 1
            continue
        drives.append(
            DriveSummary(
                mountpoint,
                usage.total,
                usage.used,
                usage.free,
            )
        )
    return drives, inaccessible


def process_summaries(limit: int = 20) -> tuple[float, list[ProcessSummary], int]:
    cpu_percent = psutil.cpu_percent(interval=None)
    processes = []
    inaccessible = 0
    for process in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            info = process.info
            memory = info["memory_info"]
            processes.append(
                ProcessSummary(
                    info["pid"],
                    info["name"] or "Unknown",
                    memory.rss if memory else 0,
                    process.cpu_percent(interval=None),
                )
            )
        except (psutil.Error, OSError):
            inaccessible += 1
            continue
    processes.sort(key=lambda item: (-item.memory_bytes, item.name.casefold()))
    return cpu_percent, processes[:limit], inaccessible


def startup_entries() -> tuple[list[StartupEntry], int]:
    entries = []
    inaccessible = 0
    if os.name != "nt":
        return entries, inaccessible

    import winreg

    locations = (
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "Current user"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "All users"),
    )
    for hive, key_path, source in locations:
        try:
            with winreg.OpenKey(hive, key_path) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError as error:
                        if getattr(error, "winerror", None) != 259:
                            inaccessible += 1
                        break
                    entries.append(StartupEntry(name, str(value), source))
                    index += 1
        except OSError:
            inaccessible += 1
            continue

    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    startup_folders = [
        ("Current user startup folder", appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    ]
    program_data_value = os.environ.get("PROGRAMDATA")
    if program_data_value:
        program_data = Path(program_data_value)
        startup_folders.append(
            ("All users startup folder", program_data / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
        )
    for source, folder in startup_folders:
        try:
            folder.lstat()
            if is_link_or_junction(folder):
                inaccessible += 1
                continue
            with os.scandir(folder) as files:
                for entry in files:
                    entries.append(StartupEntry(entry.name, str(folder / entry.name), source))
        except FileNotFoundError:
            continue
        except OSError:
            inaccessible += 1
            continue
    return entries, inaccessible
