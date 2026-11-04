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
