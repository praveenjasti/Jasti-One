import base64
import os
import subprocess

import pytest


@pytest.fixture
def make_junction():
    def quote_path(path):
        return "'" + str(path).replace("'", "''") + "'"

    def create_junction(link, target):
        script = (
            "$ErrorActionPreference = 'Stop'; "
            f"New-Item -ItemType Junction -Path {quote_path(link)} "
            f"-Target {quote_path(target)} | Out-Null"
        )
        encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as error:
            message = f"Windows junction creation is unavailable: {error}"
            if os.environ.get("JASTI_REQUIRE_SYMLINK_TESTS") == "1":
                pytest.fail(message)
            pytest.skip(message)
        if result.returncode:
            message = (
                "Windows junction creation is unavailable: "
                f"{result.stderr.strip() or result.stdout.strip() or result.returncode}"
            )
            if os.environ.get("JASTI_REQUIRE_SYMLINK_TESTS") == "1":
                pytest.fail(message)
            pytest.skip(message)

    return create_junction


@pytest.fixture
def make_symlink():
    def create_symlink(link, target, *, target_is_directory=False):
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (OSError, NotImplementedError) as error:
            message = f"Symbolic-link creation is unavailable: {error}"
            if os.environ.get("JASTI_REQUIRE_SYMLINK_TESTS") == "1":
                pytest.fail(message)
            pytest.skip(message)

    return create_symlink
