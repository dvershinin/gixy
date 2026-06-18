"""Dedicated tests for the ``nginx_cves`` plugin.

The simply-fixture framework asserts exactly one issue per non-FP
fixture, which doesn't hold once the CVE database includes dozens of
overlapping entries. These tests exercise the plugin directly with
per-fixture issue-count expectations, and also lock in the
range-subtraction logic for patched stable branches.
"""

import os
import tempfile

from gixy.core.config import Config
from gixy.core.manager import Manager as Gixy
from gixy.plugins._nginx_cves_db import (
    CVES,
    in_any_range,
    parse_oss,
    ranges_excluding_fixes,
)


# --------------------------------------------------------------------------
# Pure-data unit tests
# --------------------------------------------------------------------------


def test_parse_oss_accepts_valid_versions():
    assert parse_oss("1.29.8") == (1, 29, 8)
    assert parse_oss("v1.29.8") == (1, 29, 8)
    assert parse_oss(" 0.7.50 ") == (0, 7, 50)


def test_parse_oss_rejects_invalid():
    assert parse_oss("") is None
    assert parse_oss(None) is None
    assert parse_oss("1.29") is None
    assert parse_oss("1.29.x") is None


def test_ranges_excluding_fixes_unfixed_span_returned_as_is():
    spans = (((1, 0, 0), (1, 2, 0)),)
    assert ranges_excluding_fixes(spans, ()) == spans


def test_ranges_excluding_fixes_drops_post_fix_tail():
    # CVE-2025-23419 shape: span 1.11.4-1.27.3, fixes 1.26.3 and 1.27.4.
    spans = (((1, 11, 4), (1, 27, 3)),)
    result = ranges_excluding_fixes(spans, ("1.26.3", "1.27.4"))
    assert result == (((1, 11, 4), (1, 26, 2)), ((1, 27, 0), (1, 27, 3)))
    assert not in_any_range((1, 26, 3), result)
    assert in_any_range((1, 26, 2), result)
    assert in_any_range((1, 27, 3), result)
    assert not in_any_range((1, 27, 4), result)


def test_ranges_excluding_fixes_handles_disjoint_input():
    # CVE-2022-41741 shape: mainline 1.1.3-1.23.1 plus legacy stable
    # 1.0.7-1.0.15; fixes at 1.22.1 and 1.23.2.
    spans = (((1, 1, 3), (1, 23, 1)), ((1, 0, 7), (1, 0, 15)))
    result = ranges_excluding_fixes(spans, ("1.22.1", "1.23.2"))
    assert in_any_range((1, 22, 0), result)
    assert not in_any_range((1, 22, 1), result)
    assert in_any_range((1, 23, 1), result)
    assert not in_any_range((1, 23, 2), result)
    assert in_any_range((1, 0, 15), result)
    assert not in_any_range((1, 0, 16), result)


def test_ranges_excluding_fixes_handles_multi_branch_fixes():
    # CVE-2009-2629 shape: ancient span 0.1.0-0.8.14 with fixes on four
    # branches simultaneously.
    spans = (((0, 1, 0), (0, 8, 14)),)
    fixes = ("0.5.38", "0.6.39", "0.7.62", "0.8.15")
    result = ranges_excluding_fixes(spans, fixes)
    assert in_any_range((0, 7, 50), result)
    for v in ((0, 5, 38), (0, 6, 39), (0, 7, 62), (0, 8, 15)):
        assert not in_any_range(v, result), v


def test_every_cve_record_has_well_formed_fields():
    """Catch malformed records before they ship."""
    seen_ids = set()
    for record in CVES:
        cve_id = record["id"]
        assert cve_id.startswith("CVE-"), cve_id
        assert cve_id not in seen_ids, f"duplicate {cve_id}"
        seen_ids.add(cve_id)
        assert record["summary"].endswith(".")
        assert record["advisory"].startswith("https://"), cve_id
        assert isinstance(record["affected_oss"], tuple)
        for low, high in record["affected_oss"]:
            assert low <= high, f"{cve_id}: {low} > {high}"
        for fixed in record["fixed_oss"]:
            assert parse_oss(fixed) is not None, f"{cve_id}: bad fixed {fixed!r}"


def test_database_size_lower_bound():
    """Guardrail: ensure the database isn't accidentally truncated."""
    assert len(CVES) >= 50


# --------------------------------------------------------------------------
# End-to-end plugin tests
# --------------------------------------------------------------------------


def _run_plugin(version, conf_text):
    """Audit ``conf_text`` with ``--nginx-version=version`` and return issues.

    Args:
        version: Version string for ``--nginx-version`` (empty disables).
        conf_text: Full nginx configuration string.

    Returns:
        List of ``(severity, cve_id)`` tuples extracted from the issues.
    """
    config = Config(allow_includes=False, plugins=["nginx_cves"])
    if version:
        config.set_for("nginx_cves", {"version": version})
    with tempfile.NamedTemporaryFile(
        "w", suffix=".conf", delete=False, encoding="utf-8"
    ) as handle:
        handle.write(conf_text)
        path = handle.name
    try:
        with Gixy(config=config) as yoda:
            with open(path, encoding="utf-8") as fp:
                yoda.audit(path, fp)
            issues = yoda.auditor.plugins[0].issues
            return [
                (issue.severity, issue.reason.split(":", 1)[0].split(" ", 1)[0])
                for issue in issues
            ]
    finally:
        os.unlink(path)


def _cves_fired(version, conf_text):
    """Return the set of CVE IDs that the plugin emits for the given input.

    Args:
        version: nginx version string.
        conf_text: nginx configuration as a single string.

    Returns:
        Set of CVE ID strings.
    """
    return {cve for _, cve in _run_plugin(version, conf_text)}


_PLAIN = """events {}
http {
    server {
        listen 80;
        server_name example.com;
        location / { return 200 "ok"; }
    }
}
"""


def test_no_version_silences_plugin():
    assert _cves_fired("", _PLAIN) == set()


def test_patched_modern_version_silent():
    assert _cves_fired("1.31.1", _PLAIN) == set()


def test_cve_2026_9256_fires_on_vulnerable_modern_binary():
    assert "CVE-2026-9256" in _cves_fired("1.31.0", _PLAIN)


def test_cve_2026_9256_silent_on_mainline_fix():
    assert "CVE-2026-9256" not in _cves_fired("1.31.1", _PLAIN)


def test_cve_2026_9256_silent_on_stable_branch_fix():
    assert "CVE-2026-9256" not in _cves_fired("1.30.2", _PLAIN)


def test_cve_2026_9256_silent_on_pre_vulnerable_versions():
    assert "CVE-2026-9256" not in _cves_fired("0.1.16", _PLAIN)


def test_pure_version_only_fires_on_ancient_binary():
    fired = _cves_fired("0.7.50", _PLAIN)
    assert "CVE-2009-2629" in fired
    assert "CVE-2009-3896" in fired
    # 0.7.50 falls between 0.7.50 < 0.7.62 (first fix for 2629/3896).


def test_mp4_helper_gated_without_mp4_directive():
    fired = _cves_fired("1.22.0", _PLAIN)
    # Plain config: every mp4 CVE must be suppressed by gating.
    assert "CVE-2022-41741" not in fired
    assert "CVE-2022-41742" not in fired


def test_mp4_helper_fires_when_mp4_directive_present():
    config_with_mp4 = """events {}
http {
    server {
        listen 80;
        location /videos {
            mp4;
        }
    }
}
"""
    fired = _cves_fired("1.22.0", config_with_mp4)
    assert "CVE-2022-41741" in fired
    assert "CVE-2022-41742" in fired


def test_patched_stable_branch_suppresses_mp4_cve():
    """User on 1.22.1 (stable fix for CVE-2022-41741) must not be flagged."""
    config_with_mp4 = """events {}
http { server { listen 80; location / { mp4; } } }
"""
    fired = _cves_fired("1.22.1", config_with_mp4)
    assert "CVE-2022-41741" not in fired
    assert "CVE-2022-41742" not in fired


def test_resolver_helper_fires_only_with_resolver_directive():
    plain = _cves_fired("1.20.0", _PLAIN)
    assert "CVE-2021-23017" not in plain

    with_resolver = """events {}
http {
    resolver 8.8.8.8;
    server { listen 80; location / { return 200 "ok"; } }
}
"""
    fired = _cves_fired("1.20.0", with_resolver)
    assert "CVE-2021-23017" in fired


def test_http2_helper_detects_listen_arg_and_directive():
    conf_listen = """events {}
http {
    server { listen 443 ssl http2; }
}
"""
    assert "CVE-2019-9511" in _cves_fired("1.16.0", conf_listen)

    conf_directive = """events {}
http {
    http2 on;
    server { listen 443 ssl; }
}
"""
    assert "CVE-2019-9511" in _cves_fired("1.16.0", conf_directive)


def test_http2_patched_stable_excluded():
    """1.16.1 backported the CVE-2019-9511 fix to stable 1.16.x."""
    conf = """events {}
http { server { listen 443 ssl http2; } }
"""
    fired = _cves_fired("1.16.1", conf)
    assert "CVE-2019-9511" not in fired
    assert "CVE-2019-9513" not in fired
    assert "CVE-2019-9516" not in fired


def test_http3_helper_detects_quic_and_http3_directive():
    quic_conf = """events {}
http {
    server { listen 443 quic reuseport; }
}
"""
    assert "CVE-2024-24990" in _cves_fired("1.25.2", quic_conf)


def test_ssl_session_reuse_helper():
    conf = """events {}
http {
    ssl_session_tickets on;
    server { listen 443 ssl; }
}
"""
    fired = _cves_fired("1.20.0", conf)
    assert "CVE-2025-23419" in fired


def test_ssl_session_reuse_patched_branch_excluded():
    conf = """events {}
http {
    ssl_session_tickets on;
    server { listen 443 ssl; }
}
"""
    fired = _cves_fired("1.26.3", conf)
    assert "CVE-2025-23419" not in fired


def test_dav_helper():
    conf = """events {}
http {
    server {
        listen 80;
        location /webdav {
            dav_methods PUT DELETE MKCOL COPY MOVE;
        }
    }
}
"""
    fired = _cves_fired("1.28.0", conf)
    assert "CVE-2026-27654" in fired


def test_scgi_uwsgi_helper():
    conf = """events {}
http {
    server {
        listen 80;
        location /app { uwsgi_pass unix:/tmp/uwsgi.sock; }
    }
}
"""
    fired = _cves_fired("1.30.0", conf)
    assert "CVE-2026-42946" in fired


def test_charset_helper_skips_explicit_off():
    conf_off = """events {}
http {
    server { listen 80; charset off; }
}
"""
    assert "CVE-2026-42934" not in _cves_fired("1.30.0", conf_off)
    conf_on = """events {}
http {
    server { listen 80; charset utf-8; }
}
"""
    assert "CVE-2026-42934" in _cves_fired("1.30.0", conf_on)


def test_spdy_helper():
    conf = """events {}
http {
    server { listen 443 ssl spdy; }
}
"""
    fired = _cves_fired("1.5.10", conf)
    assert "CVE-2014-0088" in fired
    assert "CVE-2014-0133" in fired


def test_proxy_with_http2_requires_both():
    only_proxy = """events {}
http {
    server {
        listen 443 ssl;
        location / { proxy_pass http://upstream; }
    }
}
"""
    assert "CVE-2026-42926" not in _cves_fired("1.29.8", only_proxy)

    both = """events {}
http {
    server {
        listen 443 ssl http2;
        location / { proxy_pass http://upstream; }
    }
}
"""
    assert "CVE-2026-42926" in _cves_fired("1.29.8", both)


def test_mail_block_gates_mail_cves():
    no_mail = _cves_fired("1.29.0", _PLAIN)
    assert "CVE-2025-53859" not in no_mail
    assert "CVE-2026-28753" not in no_mail


def test_mail_smtp_helper():
    conf = """events {}
mail {
    server {
        listen 25;
        protocol smtp;
    }
}
http { server { listen 80; } }
"""
    fired = _cves_fired("1.29.0", conf)
    assert "CVE-2025-53859" in fired


def test_rewrite_rift_fires_with_rewrite_followup():
    conf = """events {}
http {
    server {
        listen 80;
        location / {
            rewrite ^/(.*)$ /x?$1 last;
            rewrite ^/y /z last;
        }
    }
}
"""
    assert "CVE-2026-42945" in _cves_fired("1.29.8", conf)


def test_rewrite_rift_fires_with_set_followup():
    conf = """events {}
http {
    server {
        listen 80;
        location / {
            rewrite ^/(.*)$ /x?$1 last;
            set $foo bar;
        }
    }
}
"""
    assert "CVE-2026-42945" in _cves_fired("1.29.8", conf)


def test_rewrite_rift_fires_with_if_followup():
    conf = """events {}
http {
    server {
        listen 80;
        location / {
            rewrite ^/(.*)$ /x?$1 last;
            if ($args ~ "q=") {
                return 200 "match";
            }
        }
    }
}
"""
    assert "CVE-2026-42945" in _cves_fired("1.29.8", conf)


def test_rewrite_rift_fires_with_braced_backref():
    conf = """events {}
http {
    server {
        listen 80;
        location / {
            rewrite ^/(.*)$ /x?${1} last;
            set $foo bar;
        }
    }
}
"""
    assert "CVE-2026-42945" in _cves_fired("1.29.8", conf)


def test_rewrite_rift_silent_without_followup():
    conf = """events {}
http {
    server {
        listen 80;
        location / {
            rewrite ^/(.*)$ /x?$1 last;
        }
    }
}
"""
    assert "CVE-2026-42945" not in _cves_fired("1.29.8", conf)


def test_rewrite_rift_silent_without_query_marker():
    conf = """events {}
http {
    server {
        listen 80;
        location / {
            rewrite ^/(.*)$ /x/$1 last;
            set $foo bar;
        }
    }
}
"""
    assert "CVE-2026-42945" not in _cves_fired("1.29.8", conf)


def test_anchor_picks_first_server_for_version_only():
    """Pure version-only CVEs must produce a visible issue location."""
    issues = _run_plugin("0.7.50", _PLAIN)
    assert issues, "ancient version should fire at least one version-only CVE"


# --------------------------------------------------------------------------
# CVEs landed via the 2026-06-17 nginx 1.30.3 / 1.31.2 releases.
# --------------------------------------------------------------------------

_HTTP3_ON = """events {}
http {
    http3 on;
    server { listen 443 quic reuseport; }
}
"""

_GRPC = """events {}
http {
    server {
        listen 80;
        location /grpc { grpc_pass grpc://upstream:50051; }
    }
}
"""

_PROXY_HTTP2_UPSTREAM = """events {}
http {
    server {
        listen 80;
        location / {
            proxy_http_version 2.0;
            proxy_pass http://upstream;
        }
    }
}
"""

_CHARSET_ON = """events {}
http {
    server { listen 80; charset utf-8; }
}
"""

_CHARSET_OFF = """events {}
http {
    server { listen 80; charset off; }
}
"""


def test_cve_2026_42530_fires_with_http3_on_mainline():
    assert "CVE-2026-42530" in _cves_fired("1.31.1", _HTTP3_ON)


def test_cve_2026_42530_silent_without_http3():
    assert "CVE-2026-42530" not in _cves_fired("1.31.1", _PLAIN)


def test_cve_2026_42530_silent_on_mainline_fix():
    assert "CVE-2026-42530" not in _cves_fired("1.31.2", _HTTP3_ON)


def test_cve_2026_42530_silent_on_stable_branches():
    """Stable 1.30.x was never exposed to CVE-2026-42530."""
    for version in ("1.30.0", "1.30.3"):
        assert "CVE-2026-42530" not in _cves_fired(version, _HTTP3_ON), version


def test_cve_2026_42055_fires_with_grpc_pass():
    assert "CVE-2026-42055" in _cves_fired("1.30.0", _GRPC)


def test_cve_2026_42055_fires_with_proxy_http_version_2_0():
    assert "CVE-2026-42055" in _cves_fired("1.30.0", _PROXY_HTTP2_UPSTREAM)


def test_cve_2026_42055_silent_without_grpc_or_http2_upstream():
    assert "CVE-2026-42055" not in _cves_fired("1.31.1", _PLAIN)


def test_cve_2026_42055_silent_on_stable_fix():
    assert "CVE-2026-42055" not in _cves_fired("1.30.3", _GRPC)


def test_cve_2026_42055_silent_on_mainline_fix():
    assert "CVE-2026-42055" not in _cves_fired("1.31.2", _GRPC)


def test_cve_2026_42055_silent_before_vulnerable_range():
    """Pre-1.13.10 (no grpc module yet) must not be flagged."""
    assert "CVE-2026-42055" not in _cves_fired("1.13.9", _PLAIN)


def test_cve_2026_48142_fires_with_charset_on():
    assert "CVE-2026-48142" in _cves_fired("1.31.0", _CHARSET_ON)


def test_cve_2026_48142_silent_with_charset_off():
    assert "CVE-2026-48142" not in _cves_fired("1.31.0", _CHARSET_OFF)


def test_cve_2026_48142_silent_without_charset_directive():
    assert "CVE-2026-48142" not in _cves_fired("1.31.0", _PLAIN)


def test_cve_2026_48142_silent_on_stable_fix():
    assert "CVE-2026-48142" not in _cves_fired("1.30.3", _CHARSET_ON)


def test_cve_2026_48142_silent_on_mainline_fix():
    assert "CVE-2026-48142" not in _cves_fired("1.31.2", _CHARSET_ON)


def test_2026_06_release_cves_silent_on_full_patched_versions():
    """Spot-check: a config exercising every trigger at fixed versions
    must not surface any of the three 2026-06 CVEs."""
    multi = """events {}
http {
    http3 on;
    server {
        listen 443 quic reuseport;
        charset utf-8;
        location /grpc { grpc_pass grpc://upstream:50051; }
        location /h2 {
            proxy_http_version 2.0;
            proxy_pass http://upstream;
        }
    }
}
"""
    new_cves = {"CVE-2026-42055", "CVE-2026-48142", "CVE-2026-42530"}
    assert new_cves.isdisjoint(_cves_fired("1.30.3", multi))
    assert new_cves.isdisjoint(_cves_fired("1.31.2", multi))
