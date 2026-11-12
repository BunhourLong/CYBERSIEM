from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from tests.eval_detection import run

BENIGN_SCRIPT_LINE = (
    "203.0.113.9 - - [01/Jan/2026:12:00:00 +0000] "
    '"GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 15 "-" "Mozilla/5.0"'
)
BENIGN_ORDINARY_LINE = '203.0.113.9 - - [01/Jan/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 15 "-" "Mozilla/5.0"'


def _corpus(tmp_path: Path, benign_line: str) -> tuple[Path, Path]:
    benign = tmp_path / "benign.txt"
    benign.write_text(benign_line + "\n")
    attack = tmp_path / "attack.txt"
    attack.write_text("")
    return benign, attack


def test_run_fails_when_a_benign_line_blocks(tmp_path):
    benign, attack = _corpus(tmp_path, BENIGN_SCRIPT_LINE)

    assert run(benign, attack) == 1


def test_run_passes_an_ordinary_corpus(tmp_path):
    benign, attack = _corpus(tmp_path, BENIGN_ORDINARY_LINE)

    assert run(benign, attack) == 0


def test_run_catches_a_block_raised_mid_replay(tmp_path):
    start = datetime(2026, 1, 1, 12, 0, 0)
    lines = []
    for burst_offset in (0, 65, 130, 1240):
        for i in range(30):
            at = start + timedelta(seconds=burst_offset + i)
            lines.append(
                f"203.0.113.200 - - [{at.strftime('%d/%b/%Y:%H:%M:%S +0000')}] "
                '"GET /burst HTTP/1.1" 200 15 "-" "Mozilla/5.0"'
            )
    benign = tmp_path / "benign.txt"
    benign.write_text("\n".join(lines) + "\n")
    attack = tmp_path / "attack.txt"
    attack.write_text("")

    assert run(benign, attack) == 1
