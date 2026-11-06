"""ssl_ecdh_curve: startup safety, classical-only lists and preference tiers."""

import io

import pytest

import gixy
from gixy.core.config import Config
from gixy.core.manager import Manager


def _issues(curve_list):
    conf = (
        f"http {{ server {{ listen 443 ssl; ssl_ecdh_curve {curve_list}; }} }}"
    ).encode()
    with Manager(config=Config(plugins=["ssl_ecdh_curve"])) as manager:
        manager.audit("example.invalid.conf", io.BytesIO(conf), is_stdin=True)
        return [
            issue
            for plugin in manager.auditor.plugins
            if plugin.name == "ssl_ecdh_curve"
            for issue in plugin.issues
        ]


def _only(curve_list):
    issues = _issues(curve_list)
    assert len(issues) == 1, [i.summary for i in issues]
    return issues[0]


@pytest.mark.parametrize(
    "curve_list,expected",
    [
        (
            "X25519MLKEM768:X25519:prime256v1",
            "?X25519MLKEM768/X25519:prime256v1",
        ),
        (
            "X25519/X25519MLKEM768",
            "?X25519MLKEM768/X25519",
        ),
        (
            "X25519MLKEM768:?SecP256r1MLKEM768/X25519:secp384r1/prime256v1",
            "?X25519MLKEM768:?SecP256r1MLKEM768/X25519:secp384r1/prime256v1",
        ),
        (
            "*X25519MLKEM768:*X25519",
            "?*X25519MLKEM768/*X25519",
        ),
    ],
)
def test_unprefixed_pq_group_is_high_with_tiered_fix(curve_list, expected):
    issue = _only(curve_list)
    assert issue.severity == gixy.severity.HIGH
    assert "may prevent nginx from starting" in issue.summary
    assert issue.fixes[0].replace == f"ssl_ecdh_curve {expected}"


@pytest.mark.parametrize(
    "curve_list",
    ["X25519:prime256v1:secp384r1", "secp384r1", "X25519/prime256v1"],
)
def test_classical_only_list_is_medium(curve_list):
    issue = _only(curve_list)
    assert issue.severity == gixy.severity.MEDIUM
    assert "disabling post-quantum" in issue.summary
    assert issue.fixes[0].search == f"ssl_ecdh_curve {curve_list};"
    assert issue.fixes[0].replace == ""
    assert issue.fixes[1].replace == f"ssl_ecdh_curve ?X25519MLKEM768/{curve_list}"


@pytest.mark.parametrize(
    "curve_list,expected",
    [
        (
            "?X25519MLKEM768:X25519:prime256v1",
            "?X25519MLKEM768/X25519:prime256v1",
        ),
        (
            "X25519:?X25519MLKEM768",
            "?X25519MLKEM768/X25519",
        ),
        (
            "?X25519MLKEM768:?SecP256r1MLKEM768:X25519/prime256v1",
            "?X25519MLKEM768:?SecP256r1MLKEM768/X25519/prime256v1",
        ),
    ],
)
def test_pq_sharing_a_tier_with_classical_is_low(curve_list, expected):
    issue = _only(curve_list)
    assert issue.severity == gixy.severity.LOW
    assert "no higher than classical" in issue.summary
    assert issue.fixes[0].replace == f"ssl_ecdh_curve {expected}"


@pytest.mark.parametrize(
    "curve_list",
    [
        "auto",
        "?X25519MLKEM768/X25519:prime256v1",
        "?X25519MLKEM768:?SecP256r1MLKEM768/X25519:prime256v1",
        "?*X25519MLKEM768/*X25519:prime256v1",
        "DEFAULT",
        "DEFAULT:-X448",
        "?X25519MLKEM768",
    ],
)
def test_safe_post_quantum_lists_are_clean(curve_list):
    assert _issues(curve_list) == []
