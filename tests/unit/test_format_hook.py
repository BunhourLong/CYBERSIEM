from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

# The gate must pass with only Task, uv, Node and Docker; CI's runner has jq, so this still runs there.
pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="the hook needs jq")

root = Path(__file__).parents[2]
hook = root / ".claude" / "hooks" / "format.sh"
misformatted = "x   =  1\n"


def run_hook(path: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        ["bash", str(hook)],  # noqa: S607
        input=json.dumps({"tool_input": {"file_path": path}}),
        text=True,
        env={**os.environ, "CLAUDE_PROJECT_DIR": str(root)},
    )


def test_dotdot_path_is_not_formatted(tmp_path):
    file = tmp_path / "x.py"
    file.write_text(misformatted)
    path = f"{root}/{os.path.relpath(file, root)}"

    result = run_hook(path)

    assert result.returncode == 0
    assert file.read_text() == misformatted


def test_project_path_is_formatted():
    with tempfile.TemporaryDirectory(dir=root / "tests") as tmp:
        file = Path(tmp) / "x.py"
        file.write_text(misformatted)

        result = run_hook(str(file))

        assert result.returncode == 0
        assert file.read_text() == "x = 1\n"
