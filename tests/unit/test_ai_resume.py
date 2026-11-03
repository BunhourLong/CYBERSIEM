from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

BASH = shutil.which("bash") or "bash"
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ai.sh"
STEP = json.dumps(
    {
        "type": "step_finish",
        "sessionID": "S1",
        "part": {"cost": 0.01, "tokens": {"input": 1, "output": 1, "cache": {"read": 0}}},
    }
)
TEXT = json.dumps({"type": "text", "sessionID": "S1", "part": {"text": "done"}})


def _error(message: str) -> str:
    return json.dumps({"type": "error", "sessionID": "S1", "error": {"data": {"message": message}}})


def _ai(tmp_path: Path, stub_dir: Path, stub_body: str, **env_extra: str) -> tuple[subprocess.CompletedProcess, Path]:
    """Run ai.sh in a throwaway repo with a stub opencode in place of the real one."""
    stub = stub_dir / "opencode"
    stub.write_text("#!/usr/bin/env bash\n" + stub_body)
    stub.chmod(0o755)

    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.test"]
    (repo / ".gitignore").write_text(".scan\n")
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "x"]):
        subprocess.run([*git, *args], cwd=repo, check=True)  # noqa: S603  # constant commands in a temp repo
    prompt = tmp_path / "prompt.md"
    prompt.write_text("do it")

    env = {**os.environ, "PATH": f"{stub_dir}:{os.environ['PATH']}"}
    env.pop("AI_WATCH", None)
    env.update(env_extra)
    done = subprocess.run(  # noqa: S603  # our own script with a stub opencode
        [BASH, str(SCRIPT), "explore", str(prompt)], cwd=repo, env=env, capture_output=True, text=True, timeout=25
    )
    return done, repo


def _run(tmp_path: Path, replies: list[str]) -> tuple[subprocess.CompletedProcess, list[str], Path]:
    """Play back one reply per opencode call."""
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    for index, reply in enumerate(replies):
        (stub_dir / f"reply{index}").write_text(reply + "\n")
    done, repo = _ai(
        tmp_path,
        stub_dir,
        f'd="{stub_dir}"\n'
        'n="$(cat "$d/count" 2>/dev/null || echo 0)"\n'
        'echo "$*" >> "$d/calls"\n'
        'echo $((n + 1)) > "$d/count"\n'
        'cat "$d/reply$n"\n',
    )
    return done, (stub_dir / "calls").read_text().splitlines(), repo


def test_tls_failure_resumes_the_same_session_with_continue(tmp_path):
    good = f"{TEXT}\n{STEP}"
    done, calls, repo = _run(tmp_path, [f"{STEP}\n{_error('EPROTO: The TLS handshake failed.')}", good])
    assert done.returncode == 0, done.stderr
    assert len(calls) == 2
    assert "-s S1" in calls[1] and calls[1].endswith("continue")
    assert (repo / ".scan/ai-explore.txt").read_text().strip() == "done"
    # Spend from the failed attempt counts too, or the budget is understated.
    assert len((repo / ".scan/ai-usage.tsv").read_text().splitlines()) == 2


def test_gives_up_after_three_resumes(tmp_path):
    bad = _error("EPROTO: The TLS handshake failed.")
    done, calls, _ = _run(tmp_path, [bad] * 6)
    assert done.returncode == 1
    assert len(calls) == 4


def test_a_hung_job_is_stopped_with_a_clear_error(tmp_path):
    # At Go's usage limit, opencode logs the error and then never exits.
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    done, _ = _ai(tmp_path, stub_dir, "exec sleep 30\n", AI_TIMEOUT="1")
    assert done.returncode == 1
    assert "usage limit" in done.stderr


def test_other_errors_are_not_retried(tmp_path):
    done, calls, repo = _run(tmp_path, [f"{STEP}\n{_error('Rate limit exceeded')}", TEXT])
    assert done.returncode == 1
    assert len(calls) == 1
    assert "Rate limit exceeded" in done.stderr
    assert len((repo / ".scan/ai-usage.tsv").read_text().splitlines()) == 1


def test_text_about_tls_errors_is_not_a_dropped_connection(tmp_path):
    # A job can read code or logs that mention these errors and still finish fine.
    read = json.dumps({"type": "tool_use", "sessionID": "S1", "part": {"state": {"output": "EPROTO TLS handshake"}}})
    done, calls, _ = _run(tmp_path, [f"{read}\n{TEXT}\n{STEP}", TEXT])
    assert done.returncode == 0, done.stderr
    assert len(calls) == 1


def test_watched_job_resumes_when_only_the_saved_session_shows_the_drop(tmp_path):
    # `run --attach` exits cleanly on a drop, so the error is only in the exported session.
    failed = {"messages": [{"info": {"role": "assistant", "error": {"data": {"message": "EPROTO: TLS handshake"}}}}]}
    finished = {
        "messages": [
            {"info": {"role": "assistant", "finish": "stop"}, "parts": [{"type": "text", "text": "done"}]},
        ]
    }
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    (stub_dir / "cmux").write_text("#!/usr/bin/env bash\nexit 1\n")
    (stub_dir / "cmux").chmod(0o755)
    (stub_dir / "export0").write_text(json.dumps(failed))
    (stub_dir / "export1").write_text(json.dumps(finished))
    body = (
        f'd="{stub_dir}"\n'
        'case "$1" in\n'
        "  serve) echo http://127.0.0.1:1; exec sleep 30 ;;\n"
        '  export) cat "$d/export$(($(cat "$d/count") - 1))" ;;\n'
        '  run) echo "$*" >> "$d/calls"; n="$(cat "$d/count" 2>/dev/null || echo 0)"; echo $((n + 1)) > "$d/count"\n'
        f"      echo '{json.dumps({'type': 'step_start', 'sessionID': 'S1'})}' ;;\n"
        "esac\n"
    )
    done, repo = _ai(tmp_path, stub_dir, body, AI_WATCH="1")
    calls = (stub_dir / "calls").read_text().splitlines()
    assert done.returncode == 0, done.stderr
    assert len(calls) == 2
    assert "-s S1" in calls[1] and calls[1].endswith("continue")
    assert (repo / ".scan/ai-explore.txt").read_text().strip() == "done"


def test_a_warning_on_stderr_does_not_resume_a_finished_job(tmp_path):
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    done, _ = _ai(tmp_path, stub_dir, f"echo x >> {stub_dir}/calls\necho 'EPROTO: retrying' >&2\necho '{TEXT}'\n")
    assert done.returncode == 0, done.stderr
    assert len((stub_dir / "calls").read_text().splitlines()) == 1
