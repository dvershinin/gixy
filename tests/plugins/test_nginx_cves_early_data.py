"""Check CVE-2026-132779 (TLS 1.3 early data) through the real parser/auditor."""

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager

CVE = "CVE-2026-132779"


@pytest.fixture
def audit(tmp_path):
    def run(body, version="1.31.8"):
        path = tmp_path / "nginx.conf"
        path.write_text("events {}\n" + body, encoding="utf-8")
        config = Config(allow_includes=False, plugins=["nginx_cves"])
        config.set_for("nginx_cves", {"version": version})
        with Manager(config=config) as manager:
            with path.open(encoding="utf-8") as source:
                manager.audit(str(path), source)
            return [
                issue
                for issue in manager.auditor.plugins[0].issues
                if issue.reason.startswith(CVE + ":")
            ]

    return run


HTTP_LEVEL = "http { ssl_early_data on; server { listen 443 ssl; } }"
SERVER_LEVEL = "http { server { listen 443 ssl; ssl_early_data on; } }"


@pytest.mark.parametrize("body", [HTTP_LEVEL, SERVER_LEVEL])
def test_flagged_and_anchored_on_ssl_early_data(audit, body):
    issues = audit(body)
    assert len(issues) == 1
    assert [d.name for d in issues[0].directives][0] == "ssl_early_data"


def test_explicit_tls13_protocols_flagged(audit):
    body = (
        "http { server { listen 443 ssl; ssl_protocols TLSv1.3; ssl_early_data on; } }"
    )
    assert audit(body)


@pytest.mark.parametrize(
    "body",
    [
        "http { server { listen 443 ssl; } }",
        "http { ssl_early_data on; server { listen 443 ssl; ssl_early_data off; } }",
        "http { server { listen 443 ssl; ssl_early_data off; } }",
        "http { ssl_early_data on; server { listen 443 ssl; "
        "ssl_protocols TLSv1.2; } }",
        "http { ssl_early_data on; server { listen 80; } }",
        "stream { server { listen 443 ssl; ssl_early_data on; } }",
    ],
)
def test_not_flagged(audit, body):
    assert not audit(body)


@pytest.mark.parametrize("version", ["1.21.4", "1.30.7", "1.31.9"])
def test_vulnerable_versions_flagged(audit, version):
    # Explicit TLSv1.3: before 1.23.4 the default protocols exclude it.
    body = (
        "http { ssl_early_data on; ssl_protocols TLSv1.3; server { listen 443 ssl; } }"
    )
    assert audit(body, version)


@pytest.mark.parametrize("version", ["1.21.3", "1.30.8", "1.31.10"])
def test_fixed_versions_not_flagged(audit, version):
    assert not audit(HTTP_LEVEL, version)


def test_one_finding_per_server_with_several_listeners(audit):
    body = "http { ssl_early_data on; server { listen 443 ssl; listen 8443 ssl; } }"
    assert len(audit(body)) == 1
