"""Plugin to detect ssl_ecdh_curve group lists that can stop nginx from starting.

nginx passes the value of `ssl_ecdh_curve` straight to OpenSSL's
`SSL_CTX_set1_curves_list()`. OpenSSL rejects the *entire* list when a single
group name is unknown to the linked library, and nginx treats that rejection as
`NGX_LOG_EMERG` (`src/event/ngx_event_openssl.c`) — the master process refuses
to start. Post-quantum hybrid group names such as `X25519MLKEM768` only exist
in OpenSSL 3.5+, so a config copied from a "post-quantum nginx" blog post takes
a site offline on Debian 12, Ubuntu 24.04 or RHEL 9, which ship OpenSSL 3.0/3.2.
"""

import gixy
from gixy.plugins.plugin import Plugin

# Substrings that mark a group name as post-quantum, i.e. only present in
# recent OpenSSL builds (and absent from LibreSSL/BoringSSL-based nginx).
PQ_GROUP_MARKERS = ("MLKEM", "KYBER")

# Prefix that tells OpenSSL 3.3+ to ignore an unrecognised group instead of
# failing the whole list.
TOLERANT_PREFIX = "?"


class ssl_ecdh_curve(Plugin):
    """Detect post-quantum ssl_ecdh_curve groups used without the `?` prefix."""

    summary = (
        "ssl_ecdh_curve names a post-quantum group that may prevent nginx from starting"
    )
    severity = gixy.severity.HIGH
    description = (
        "nginx passes `ssl_ecdh_curve` to OpenSSL's `SSL_CTX_set1_curves_list()`, "
        "which rejects the whole list if any single group name is unknown to the "
        "linked OpenSSL. nginx logs that failure at emergency level and refuses to "
        "start. Post-quantum hybrids (`X25519MLKEM768`, `SecP256r1MLKEM768`, the "
        "`X25519Kyber768*` drafts) require OpenSSL 3.5+; on OpenSSL 3.0/3.2 — what "
        "Debian 12, Ubuntu 24.04 and RHEL 9 ship — the same config is a hard outage. "
        "Prefix such groups with `?` so OpenSSL skips the ones it does not know. "
        "The `?` prefix itself needs OpenSSL 3.3+."
    )
    directives = ["ssl_ecdh_curve"]

    def audit(self, directive):
        """Report post-quantum groups that are not `?`-prefixed.

        Args:
            directive: The `ssl_ecdh_curve` Directive to audit.
        """
        if not directive.args:
            return

        curve_list = directive.args[0]
        groups = [g for g in curve_list.split(":") if g]

        risky = [g for g in groups if self._is_risky(g)]
        if not risky:
            return

        tolerant_list = ":".join(
            TOLERANT_PREFIX + g if self._is_risky(g) else g for g in groups
        )

        self.add_issue(
            severity=gixy.severity.HIGH,
            directive=[directive, directive.parent],
            reason=(
                "Group(s) {groups} are post-quantum hybrids that only exist in "
                "OpenSSL 3.5+. If the running OpenSSL does not know one of them, "
                "SSL_CTX_set1_curves_list() rejects the entire list, nginx logs it "
                "as an emergency and the master process fails to start — the site "
                "goes down, it does not merely lose post-quantum support.".format(
                    groups=", ".join(risky)
                )
            ),
            fixes=[
                self.make_fix(
                    title="Make unknown groups tolerable with the `?` prefix",
                    search=f"ssl_ecdh_curve {curve_list}",
                    replace=f"ssl_ecdh_curve {tolerant_list}",
                    description=(
                        "OpenSSL 3.3+ skips a `?`-prefixed group it does not "
                        "recognise instead of failing the whole list. On older "
                        "OpenSSL, drop the post-quantum groups entirely."
                    ),
                ),
            ],
        )

    @staticmethod
    def _is_risky(group):
        """Return True when a group name is post-quantum and not `?`-prefixed.

        Args:
            group: A single group name as written in the config.

        Returns:
            True if the group is a post-quantum hybrid without the tolerant
            `?` prefix.
        """
        if group.startswith(TOLERANT_PREFIX):
            return False
        upper = group.upper()
        return any(marker in upper for marker in PQ_GROUP_MARKERS)
