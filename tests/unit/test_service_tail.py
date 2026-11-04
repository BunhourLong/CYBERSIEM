from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.security_engine.service import LogMonitorService


def test_tail_loop_survives_process_line_error(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("")
    svc = LogMonitorService(engine=MagicMock())
    handled: list[str] = []

    def fake_process(line):
        if "boom" in line:
            raise RuntimeError("x")
        handled.append(line)
        return MagicMock(), []

    svc.process_line = fake_process
    calls = {"n": 0}

    def fake_sleep(_):
        calls["n"] += 1
        if calls["n"] == 1:
            with log.open("a") as f:
                f.write("boom\nok\n")
        else:
            raise KeyboardInterrupt

    with patch("src.security_engine.service.time.sleep", fake_sleep), pytest.raises(KeyboardInterrupt):
        svc.run_forever(str(log))

    assert handled == ["ok\n"]
    assert svc.rejected_line_count == 1


def _run(tmp_path, results, content=b""):
    """Feed one line per result to process_line; stop when the file is drained."""
    log = tmp_path / "access.log"
    log.write_bytes(b"")
    svc = LogMonitorService(engine=MagicMock())
    it = iter(results)

    def fake_process(line):
        r = next(it)
        if isinstance(r, Exception):
            raise r
        return MagicMock(), []

    svc.process_line = fake_process

    def fake_sleep(_):
        if fake_sleep.fed:
            raise KeyboardInterrupt
        fake_sleep.fed = True
        with log.open("ab") as f:
            f.write(content or b"x\n" * len(results))

    fake_sleep.fed = False
    with patch("src.security_engine.service.time.sleep", fake_sleep):
        svc.run_forever(str(log))


def test_permanent_failure_eventually_raises(tmp_path):
    with pytest.raises(RuntimeError):
        _run(tmp_path, [RuntimeError("x")] * 25)


def test_success_resets_failure_streak(tmp_path):
    err = RuntimeError("x")
    with pytest.raises(KeyboardInterrupt):
        _run(tmp_path, [err] * 19 + [None] + [err] * 19)


def test_invalid_utf8_does_not_stop_loop(tmp_path):
    with pytest.raises(KeyboardInterrupt):
        _run(tmp_path, [None, None], content=b"\xff\xfe bad\nok\n")
