"""Verify the CLI and server mode never present an unanalysed config as a result."""

import json
import os
import subprocess
import sys

import pytest

import gixy
from gixy.cli.main import main
from gixy.core.manager import Manager

CLEAN = "http { server { listen 80; server_tokens off; return 200; } }\n"
FINDING = (
    "http { server { listen 80; server_tokens off; location /x { alias /srv/; } } }\n"
)
UNTERMINATED = "http {\n  server {\n"


def run_cli(monkeypatch, capsys, arguments):
    monkeypatch.setattr(sys, "argv", ["gixy"] + arguments)
    with pytest.raises(SystemExit) as error:
        main()
    return error.value.code, capsys.readouterr()


def write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content)
    return str(path)


@pytest.mark.parametrize("output_format", ["json", "json_report", "text", "checkstyle"])
def test_rejected_config_exits_2_in_every_format(
    tmp_path, monkeypatch, capsys, output_format
):
    path = write(tmp_path, "broken.conf", UNTERMINATED)
    code, output = run_cli(monkeypatch, capsys, ["-f", output_format, path])
    assert code == 2
    assert "Configuration error: unexpected end of file" in output.err


def test_exit_codes_separate_clean_findings_and_rejected(tmp_path, monkeypatch, capsys):
    codes = [
        run_cli(monkeypatch, capsys, ["-f", "json", write(tmp_path, name, content)])[0]
        for name, content in (
            ("clean.conf", CLEAN),
            ("finding.conf", FINDING),
            ("broken.conf", UNTERMINATED),
        )
    ]
    assert codes == [0, 1, 2]


def test_json_report_for_a_clean_config(tmp_path, monkeypatch, capsys):
    path = write(tmp_path, "clean.conf", CLEAN)
    code, output = run_cli(monkeypatch, capsys, ["-f", "json_report", path])
    assert code == 0
    assert json.loads(output.out) == {
        "report_version": 1,
        "gixy_version": gixy.version,
        "status": "analysed",
        "error": None,
        "issues": [],
    }


def test_json_report_issues_match_the_json_format(tmp_path, monkeypatch, capsys):
    path = write(tmp_path, "finding.conf", FINDING)
    code, output = run_cli(monkeypatch, capsys, ["-f", "json_report", path])
    report = json.loads(output.out)
    assert code == 1
    assert report["status"] == "analysed"
    assert report["error"] is None
    _, plain = run_cli(monkeypatch, capsys, ["-f", "json", path])
    assert report["issues"] == json.loads(plain.out)
    assert [issue["plugin"] for issue in report["issues"]] == ["alias_traversal"]


def test_json_report_for_a_rejected_config(tmp_path, monkeypatch, capsys):
    path = write(tmp_path, "broken.conf", UNTERMINATED)
    code, output = run_cli(monkeypatch, capsys, ["-f", "json_report", path])
    report = json.loads(output.out)
    assert code == 2
    assert report["status"] == "rejected"
    assert report["issues"] == []
    assert report["error"]["kind"] == "invalid_configuration"
    assert report["error"]["path"] == path
    assert "unexpected end of file" in report["error"]["message"]


def test_one_rejected_input_marks_the_whole_run(tmp_path, monkeypatch, capsys):
    finding = write(tmp_path, "finding.conf", FINDING)
    broken = write(tmp_path, "broken.conf", UNTERMINATED)
    code, output = run_cli(monkeypatch, capsys, ["-f", "json_report", finding, broken])
    report = json.loads(output.out)
    assert code == 2
    assert report["status"] == "rejected"
    assert report["error"]["path"] == broken
    assert [issue["path"] for issue in report["issues"]] == [finding]


def test_crash_during_audit_is_reported_not_raised(tmp_path, monkeypatch, capsys):
    def explode(self, *args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(Manager, "audit", explode)
    path = write(tmp_path, "clean.conf", CLEAN)
    code, output = run_cli(monkeypatch, capsys, ["-f", "json_report", path])
    report = json.loads(output.out)
    assert code == 2
    assert report["status"] == "error"
    assert report["error"] == {
        "kind": "internal_error",
        "message": "RuntimeError: boom",
        "path": path,
    }
    assert report["issues"] == []


def test_server_mode_reports_status():
    requests = [
        {"id": 1, "method": "analyze", "content": CLEAN},
        {"id": 2, "method": "analyze", "content": FINDING},
        {"id": 3, "method": "analyze", "content": UNTERMINATED},
        {"id": 4, "method": "analyze", "content": 7},
        {"id": 5, "method": "ping"},
    ]
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIXY_")
    }
    result = subprocess.run(  # noqa: UP022 - retain Python 3.6 support.
        [sys.executable, "-m", "gixy.cli", "--server", "--disable-includes"],
        input="".join(json.dumps(request) + "\n" for request in requests),
        stdout=subprocess.PIPE,  # Python 3.6 has no capture_output.
        stderr=subprocess.PIPE,
        universal_newlines=True,
        env=environment,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    ready, clean, finding, rejected, invalid, pong = (
        json.loads(line) for line in result.stdout.splitlines()
    )
    assert ready["ready"] is True
    assert clean == {"id": 1, "status": "analysed", "issues": [], "error": None}
    assert finding["status"] == "analysed"
    assert finding["error"] is None
    assert [issue["plugin"] for issue in finding["issues"]] == ["alias_traversal"]
    assert rejected["status"] == "rejected"
    assert rejected["issues"] == []
    assert "unexpected end of file" in rejected["error"]
    assert invalid["status"] == "error"
    assert invalid["error"] == "content must be text or bytes"
    assert pong["pong"] is True
