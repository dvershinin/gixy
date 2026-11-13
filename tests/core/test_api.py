"""Pin the public analysis contract: findings, or the reason there are none."""

import json

import gixy
from gixy.api import analyze, analyze_with_config
from gixy.core.config import Config
from gixy.core.manager import Manager

CLEAN = "http { server { listen 80; server_tokens off; return 200; } }"
FINDING = (
    "http { server { listen 80; server_tokens off; location /x { alias /srv/; } } }"
)
UNTERMINATED = "http { server { listen 80;"


def test_clean_config_is_analysed_without_issues():
    result = analyze(CLEAN)
    assert result.analysed
    assert result.as_dict() == {
        "report_version": 1,
        "gixy_version": gixy.version,
        "status": "analysed",
        "error": None,
        "issues": [],
    }


def test_findings_use_the_json_format_issue_shape():
    result = analyze(FINDING, filename="site.conf")
    assert result.status == "analysed"
    assert result.error is None
    (issue,) = result.issues
    assert issue["plugin"] == "alias_traversal"
    assert issue["path"] == "site.conf"
    assert {"summary", "severity", "description", "reference", "reason", "config"} <= (
        issue.keys()
    )
    json.dumps(result.as_dict())


def test_bytes_are_accepted():
    assert analyze(FINDING.encode("utf-8")).issues == analyze(FINDING).issues


def test_rejected_config_is_not_a_clean_result():
    result = analyze(UNTERMINATED)
    assert not result.analysed
    assert result.status == "rejected"
    assert result.issues == []
    assert result.error["kind"] == "invalid_configuration"
    assert "unexpected end of file" in result.error["message"]


def test_rejection_names_the_given_filename_not_a_temporary_file():
    message = analyze(UNTERMINATED, filename="upload.conf").error["message"]
    assert "upload.conf:1" in message
    assert "tmp" not in message


def test_crash_during_audit_is_an_error_result(monkeypatch, caplog):
    def explode(self, *args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(Manager, "audit", explode)
    result = analyze(CLEAN)
    assert result.status == "error"
    assert result.issues == []
    assert result.error == {"kind": "internal_error", "message": "RuntimeError: boom"}
    assert "Analysis failed" in caplog.text


def test_analysis_after_a_rejection_starts_clean():
    assert analyze(UNTERMINATED).status == "rejected"
    assert len(analyze(FINDING).issues) == 1
    assert analyze(CLEAN).as_dict()["status"] == "analysed"


def test_invalid_requests_are_error_results():
    for result in (
        analyze(None),
        analyze(CLEAN, nginx_version="auto"),
        analyze(CLEAN, nginx_version="latest"),
        analyze(CLEAN, nginx_flavor="no-such-flavor"),
    ):
        assert result.status == "error"
        assert result.error["kind"] == "invalid_request"
        assert result.issues == []


def test_nginx_version_enables_version_checks():
    plugins = {
        issue["plugin"] for issue in analyze(CLEAN, nginx_version="1.20.0").issues
    }
    assert "nginx_cves" in plugins
    assert "nginx_cves" not in {issue["plugin"] for issue in analyze(CLEAN).issues}


def test_checks_and_skips_select_plugins():
    assert analyze(FINDING, skips=["alias_traversal"]).issues == []
    assert analyze(FINDING, checks=["version_disclosure"]).issues == []
    assert len(analyze(FINDING, checks=["alias_traversal"]).issues) == 1


def test_includes_are_followed_only_on_request(tmp_path):
    included = tmp_path / "locations.conf"
    included.write_text("location /x { alias /srv/; }\n")
    config = (
        "http { server { listen 80; server_tokens off; include "
        + str(included)
        + "; } }"
    )
    assert analyze(config).issues == []
    (issue,) = analyze(config, allow_includes=True).issues
    assert issue["plugin"] == "alias_traversal"


def test_prepared_config_is_honoured():
    config = Config(skips=["alias_traversal"], allow_includes=False)
    assert analyze_with_config(FINDING, config).issues == []
    assert analyze_with_config(UNTERMINATED, config).status == "rejected"
