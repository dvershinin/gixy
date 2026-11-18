"""Check November advisories through parsed ordinary NGINX configurations."""

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


@pytest.fixture
def audit(tmp_path):
    def run(cve, body, version="1.31.8"):
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
                if issue.reason.startswith(cve + ":")
            ]

    return run


RESOLVER = "CVE-2026-123634"
FLOW = "CVE-2026-123007"
HTTP3 = "CVE-2026-121810"
HTTP2_PROXY = "CVE-2026-123633"
TLS = "CVE-2026-118899"
MAIL = "CVE-2026-113425"
PROXY_V2 = "CVE-2026-120993"
ALIAS = "CVE-2026-125283"
SNI = "CVE-2026-120967"
PREREAD = "CVE-2026-123640"

MIRROR = """http { resolver 192.0.2.53; server {
    set $backend backend.example;
    location / { proxy_pass http://$backend; mirror /mirror; }
    location /mirror { internal; proxy_pass http://$backend; }
} }"""
MAP = "map $uri $mapped { ~^/(.*)$ /$1; default /index; }"
ALIAS_BODY = (
    """http { %s server { location /files/ {
    alias /srv/files/; try_files $mapped $uri =404;
} } }"""
    % MAP
)
STREAM_TLS = """listen 443 ssl; ssl_certificate /certs/$ssl_server_name.crt;
    ssl_certificate_key /certs/$ssl_server_name.key; proxy_pass backend:443;"""
SNI_BODY = """stream {
    server { listen 443 ssl; server_name default.example; }
    server { listen 443 ssl; server_name protected.example; ssl_verify_client on; }
}"""

CASES = [
    (RESOLVER, MIRROR, "0.6.18", "0.6.17", "proxy_pass"),
    (FLOW, "http { server { listen 443 ssl http2; } }", "1.9.5", "1.9.4", "listen"),
    (HTTP3, "http { server { listen 443 quic; } }", "1.25.0", "1.24.0", "listen"),
    (
        HTTP2_PROXY,
        "http { server { listen 443 ssl http2; location / { "
        "proxy_pass http://backend; } } }",
        "1.19.7",
        "1.19.6",
        "proxy_pass",
    ),
    (
        TLS,
        "http { server { listen 443 ssl; ssl_protocols TLSv1.3; } }",
        "1.13.0",
        "1.12.2",
        "listen",
    ),
    (MAIL, "mail { server { listen 25; } }", "0.5.33", "0.5.32", "listen"),
    (
        PROXY_V2,
        "stream { server { " + STREAM_TLS + " proxy_protocol v2; } }",
        "1.31.4",
        "1.31.3",
        "proxy_protocol",
    ),
    (ALIAS, ALIAS_BODY, "0.9.6", "0.9.5", "alias"),
    (SNI, SNI_BODY, "1.25.5", "1.25.4", "ssl_verify_client"),
    (
        PREREAD,
        "stream { server { listen 443; ssl_preread on; proxy_pass backend:443; } }",
        "1.15.2",
        "1.15.1",
        "ssl_preread",
    ),
]


@pytest.mark.parametrize("cve,body,low,before,anchor", CASES)
def test_affected_boundaries_and_directive_anchors(
    audit, cve, body, low, before, anchor
):
    for version in (low, "1.31.8"):
        issues = audit(cve, body, version)
        assert issues, (cve, version)
        assert all(anchor in [d.name for d in issue.directives] for issue in issues)
    assert not audit(cve, body, before)
    assert not audit(cve, body, "1.31.9")
    assert not audit(cve, body, "1.32.0")
    assert not audit(cve, body, "1.30.7")
    assert bool(audit(cve, body, "1.30.6")) == (cve != PROXY_V2)


@pytest.mark.parametrize("cve,body,low,before,anchor", CASES)
@pytest.mark.parametrize("version", ["", "unknown", "1.31"])
def test_unknown_version_stays_silent(audit, cve, body, low, before, anchor, version):
    assert not audit(cve, body, version)


@pytest.mark.parametrize(
    "cve,body",
    [
        (
            RESOLVER,
            "http { resolver 192.0.2.53; server { location / { "
            "proxy_pass http://$backend; } } }",
        ),
        (RESOLVER, MIRROR.replace("http://$backend", "http://backend.example")),
        (RESOLVER, MIRROR.replace("mirror /mirror;", "mirror off;")),
        (
            RESOLVER,
            MIRROR.replace(
                "internal; proxy_pass http://$backend;",
                "internal; proxy_pass http://$other;",
            ),
        ),
        (FLOW, "http { http2 on; server { listen 80; http2 off; } }"),
        (FLOW, "stream { server { listen 443 http2; } }"),
        (HTTP3, "http { http3 off; server { listen 443 quic; } }"),
        (HTTP3, "http { server { listen 443 ssl; http3 on; } }"),
        (HTTP3, "stream { server { listen 443 quic; } }"),
        (
            HTTP2_PROXY,
            "http { server { listen 443 ssl http2; } "
            "server { listen 80; location / { proxy_pass http://backend; } } }",
        ),
        (
            HTTP2_PROXY,
            "http { server { listen 443 ssl; location / { "
            "proxy_pass http://backend; } } }",
        ),
        (HTTP2_PROXY, "http { server { listen 443 ssl http2; return 200 ok; } }"),
        (
            TLS,
            "http { ssl_protocols TLSv1.3; server { listen 443 ssl; "
            "ssl_protocols TLSv1.2; } }",
        ),
        (TLS, "http { server { listen 80; ssl_protocols TLSv1.3; } }"),
        (TLS, "stream { server { listen 443 ssl; ssl_protocols TLSv1.3; } }"),
        (MAIL, "http { server { listen 25; } }"),
        (MAIL, "mail { auth_http localhost:9000/auth; }"),
        (PROXY_V2, "stream { server { " + STREAM_TLS + " proxy_protocol on; } }"),
        (
            PROXY_V2,
            "stream { server { "
            + STREAM_TLS.replace(
                "/certs/$ssl_server_name.crt", "/certs/static.crt"
            ).replace("/certs/$ssl_server_name.key", "/certs/static.key")
            + " proxy_protocol v2; } }",
        ),
        (
            PROXY_V2,
            "stream { server { " + STREAM_TLS + " } "
            "server { listen 8443; proxy_pass backend:443; proxy_protocol v2; } }",
        ),
        (ALIAS, ALIAS_BODY.replace("alias /srv/files/;", "root /srv/files;")),
        (
            ALIAS,
            ALIAS_BODY.replace("try_files $mapped $uri =404;", "try_files $uri =404;"),
        ),
        (ALIAS, ALIAS_BODY.replace(MAP, "map $uri $mapped { default /index; }")),
        (
            ALIAS,
            "http { " + MAP + " server { location /a/ { alias /srv/files/; } "
            "location /b/ { try_files $mapped $uri =404; } } }",
        ),
        (SNI, SNI_BODY.replace("ssl_verify_client on;", "ssl_verify_client optional;")),
        (
            SNI,
            "stream { server { listen 443 ssl; server_name protected.example; "
            "ssl_verify_client on; } }",
        ),
        (
            SNI,
            SNI_BODY.replace(
                "listen 443 ssl; server_name protected.example;",
                "listen 8443 ssl; server_name protected.example;",
            ),
        ),
        (
            PREREAD,
            "stream { ssl_preread on; server { listen 443; ssl_preread off; "
            "proxy_pass backend:443; } }",
        ),
        (PREREAD, "http { server { listen 443; ssl_preread on; } }"),
    ],
)
def test_missing_prerequisites_and_unrelated_scopes_stay_silent(audit, cve, body):
    assert not audit(cve, body)


@pytest.mark.parametrize(
    "version,expected",
    [
        ("1.13.0", False),
        ("1.22.1", False),
        ("1.23.3", False),
        ("1.23.4", True),
        ("1.30.6", True),
        ("1.31.8", True),
    ],
)
def test_tls13_default_depends_on_installed_version(audit, version, expected):
    assert bool(audit(TLS, "http { server { listen 443 ssl; } }", version)) == expected


@pytest.mark.parametrize(
    "cve,body",
    [
        (FLOW, "http { http2 on; server { listen 443 ssl; } }"),
        (HTTP3, "http { http3 off; server { listen 443 quic; http3 on; } }"),
        (
            HTTP2_PROXY,
            "http { http2 on; server { listen 443 ssl; "
            "location / { proxy_pass http://backend; } } }",
        ),
        (TLS, "http { ssl_protocols TLSv1.3; server { listen 443 ssl; } }"),
        (
            TLS,
            "http { ssl_protocols TLSv1.2; server { listen 443 ssl; "
            "ssl_protocols TLSv1.3; } }",
        ),
        (PROXY_V2, "stream { proxy_protocol v2; server { " + STREAM_TLS + " } }"),
        (
            PREREAD,
            "stream { ssl_preread on; server { listen 443; proxy_pass backend:443; } }",
        ),
    ],
)
def test_effective_inherited_settings_and_nearer_overrides(audit, cve, body):
    assert audit(cve, body)


def test_resolver_ssi_subrequest_surface(audit):
    assert audit(RESOLVER, MIRROR.replace("mirror /mirror;", "ssi on;"))


def test_resolver_known_mirror_target_cannot_borrow_unrelated_proxy(audit):
    body = MIRROR.replace(
        "internal; proxy_pass http://$backend;", "internal; proxy_pass http://$other;"
    )
    body = body.replace(
        "} }", "location /unrelated { proxy_pass http://$backend; } } }"
    )
    assert not audit(RESOLVER, body)


@pytest.mark.parametrize(
    "default_protocols,expected",
    [("TLSv1.2", False), ("TLSv1.3", True)],
)
def test_shared_tls_socket_uses_default_servers_protocols(
    audit, default_protocols, expected
):
    other_protocols = "TLSv1.3" if default_protocols == "TLSv1.2" else "TLSv1.2"
    body = "http { server { listen 443 ssl; ssl_protocols " + other_protocols
    body += "; } server { listen 0.0.0.0:443 ssl default_server; ssl_protocols "
    body += default_protocols + "; } }"
    assert bool(audit(TLS, body)) == expected


def test_alias_try_files_inherits_alias_but_nearer_root_masks_it(audit):
    template = "http { " + MAP + " server { location /files/ { alias /srv/files/; "
    template += "location /files/nested/ { %s try_files $mapped $uri =404; } } } }"
    assert audit(ALIAS, template % "")
    assert not audit(ALIAS, template % "root /srv/root;")


def test_explicit_stream_default_server_changes_which_server_is_nondefault(audit):
    body = "stream { server { listen 443 ssl; server_name protected.example; "
    body += "ssl_verify_client on; } server { listen 443 ssl default_server; "
    body += "server_name default.example; } }"
    assert audit(SNI, body)
    assert not audit(
        SNI,
        body.replace("ssl_verify_client on;", "").replace(
            "server_name default.example;",
            "server_name default.example; ssl_verify_client on;",
        ),
    )
