"""Plugin to audit ssl_ecdh_curve group lists for post-quantum key exchange.

nginx passes the value of `ssl_ecdh_curve` straight to OpenSSL's
`SSL_CTX_set1_curves_list()`. OpenSSL rejects the *entire* list when a single
group name is unknown to the linked library, and nginx treats that rejection as
`NGX_LOG_EMERG` (`src/event/ngx_event_openssl.c`) — the master process refuses
to start. Post-quantum hybrid group names such as `X25519MLKEM768` only exist
in OpenSSL 3.5+, so a config copied from a "post-quantum nginx" blog post takes
a site offline on Debian 12, Ubuntu 24.04 or RHEL 8, which ship OpenSSL 1.1.1-3.0.

The opposite mistake is quieter. On OpenSSL 3.5+ the default group list leads
with `X25519MLKEM768`, and an explicit list replaces that default: a list of
classical groups only turns post-quantum key exchange off for every client.

OpenSSL 3.5 also reads the list as preference tiers: `:` joins groups in one
tier, `/` starts the next. Inside a tier the server takes the key share the
client sent first, so a hybrid that shares a tier with `X25519` loses to any
client that leads with an X25519 key share.
"""

import gixy
from gixy.plugins.plugin import Plugin

# Substrings that mark a group name as post-quantum, i.e. only present in
# recent OpenSSL builds (and absent from LibreSSL/BoringSSL-based nginx).
PQ_GROUP_MARKERS = ("MLKEM", "KYBER")

# Prefix that tells OpenSSL 3.3+ to ignore an unrecognised group instead of
# failing the whole list.
TOLERANT_PREFIX = "?"

# Other OpenSSL 3.5 group-list prefixes: `*` requests a key share for the
# group, `-` removes it from a DEFAULT expansion.
NAME_PREFIXES = "?*-"

# OpenSSL 3.5 keyword that expands to its built-in list, which leads with the
# post-quantum hybrid.
DEFAULT_KEYWORD = "DEFAULT"

RECOMMENDED_PQ_TIER = TOLERANT_PREFIX + "X25519MLKEM768"


class ssl_ecdh_curve(Plugin):
    """Audit ssl_ecdh_curve group lists for startup safety and post-quantum use."""

    summary = (
        "ssl_ecdh_curve names a post-quantum group that may prevent nginx from starting"
    )
    severity = gixy.severity.HIGH
    description = (
        "nginx passes `ssl_ecdh_curve` to OpenSSL's `SSL_CTX_set1_curves_list()`, "
        "which rejects the whole list if any single group name is unknown to the "
        "linked OpenSSL. nginx logs that failure at emergency level and refuses to "
        "start. Post-quantum hybrids (`X25519MLKEM768`, `SecP256r1MLKEM768`, the "
        "`X25519Kyber768*` drafts) require OpenSSL 3.5+; on older OpenSSL the same "
        "config is a hard outage. Prefix such groups with `?` so OpenSSL 3.3+ skips "
        "the ones it does not know, and keep them in their own top preference tier "
        "(`?X25519MLKEM768/X25519:prime256v1`). On OpenSSL 3.0/3.2 neither `?` nor "
        "`/` parses: name only classical groups there, or leave the directive unset."
    )
    directives = ["ssl_ecdh_curve"]

    classical_only_summary = (
        "ssl_ecdh_curve pins classical groups only, disabling post-quantum key exchange"
    )
    classical_only_description = (
        "An explicit `ssl_ecdh_curve` list replaces OpenSSL's default instead of "
        "extending it. On nginx linked against OpenSSL 3.5+, whose default leads "
        "with the `X25519MLKEM768` hybrid, a list of classical groups only (the "
        "hardening advice of the pre-ML-KEM era) silently turns post-quantum key "
        "exchange off for every client, browsers included. `nginx -t` passes and "
        "nothing is logged. Remove the directive to follow the library default, "
        "which is sane on every OpenSSL version."
    )

    shared_tier_summary = (
        "ssl_ecdh_curve ranks post-quantum groups no higher than classical ones"
    )
    shared_tier_description = (
        "OpenSSL 3.5 reads the group list as preference tiers: `:` joins groups "
        "in one tier and `/` starts the next. Inside a tier the server takes the "
        "key share the client sent first, so a client that offers the hybrid but "
        "leads with an X25519 key share negotiates classical X25519. Current "
        "Chrome, Firefox, curl, Go and Java send a hybrid key share and are "
        "unaffected; clients that lead with X25519, such as Cloudflare's origin "
        "connections before mid-2026, are not. Put the post-quantum groups in "
        "their own top tier and the server asks for the hybrid share with a "
        "HelloRetryRequest instead."
    )

    def audit(self, directive):
        """Report startup-unsafe and post-quantum-defeating group lists.

        Args:
            directive: The `ssl_ecdh_curve` Directive to audit.
        """
        if not directive.args:
            return

        curve_list = directive.args[0]
        tiers = [[g for g in tier.split(":") if g] for tier in curve_list.split("/")]
        tiers = [tier for tier in tiers if tier]
        groups = [g for tier in tiers for g in tier]
        if not groups or curve_list.lower() == "auto":
            return
        if any(self._name(g).upper() == DEFAULT_KEYWORD for g in groups):
            return

        pq_groups = [g for g in groups if self._is_pq(g)]
        if not pq_groups:
            self._report_classical_only(directive, curve_list)
            return

        risky = [g for g in pq_groups if not g.startswith(TOLERANT_PREFIX)]
        if risky:
            self._report_risky(directive, curve_list, tiers, risky)
        elif not all(self._is_pq(g) for g in tiers[0]):
            self._report_shared_tier(directive, curve_list, tiers)

    def _report_risky(self, directive, curve_list, tiers, risky):
        self.add_issue(
            directive=[directive, directive.parent],
            summary=self.summary,
            severity=gixy.severity.HIGH,
            description=self.description,
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
                    title="Make unknown groups tolerable and rank post-quantum first",
                    search=f"ssl_ecdh_curve {curve_list}",
                    replace=f"ssl_ecdh_curve {self._tiered(tiers)}",
                    description=(
                        "OpenSSL 3.3+ skips a `?`-prefixed group it does not "
                        "recognise instead of failing the whole list, and the `/` "
                        "gives the hybrids their own top preference tier (OpenSSL "
                        "3.5+). On older OpenSSL, drop the post-quantum groups "
                        "entirely."
                    ),
                ),
            ],
        )

    def _report_classical_only(self, directive, curve_list):
        self.add_issue(
            directive=[directive, directive.parent],
            summary=self.classical_only_summary,
            severity=gixy.severity.MEDIUM,
            description=self.classical_only_description,
            reason=(
                f"`{curve_list}` names no post-quantum group, so nginx linked against "
                "OpenSSL 3.5+ never negotiates X25519MLKEM768, even with clients "
                "that offer it."
            ),
            fixes=[
                self.make_fix(
                    title="Remove ssl_ecdh_curve and use the OpenSSL default",
                    search=f"ssl_ecdh_curve {curve_list};",
                    replace="",
                    description=(
                        "The default leads with X25519MLKEM768 on OpenSSL 3.5+ "
                        "and is a classical list on older versions."
                    ),
                ),
                self.make_fix(
                    title="Add a post-quantum top tier (OpenSSL 3.5+ only)",
                    search=f"ssl_ecdh_curve {curve_list}",
                    replace=f"ssl_ecdh_curve {RECOMMENDED_PQ_TIER}/{curve_list}",
                    description=(
                        "Keeps the pinned classical groups as the fallback tier. "
                        "OpenSSL 3.0/3.2 cannot parse this form."
                    ),
                ),
            ],
        )

    def _report_shared_tier(self, directive, curve_list, tiers):
        self.add_issue(
            directive=[directive, directive.parent],
            summary=self.shared_tier_summary,
            severity=gixy.severity.LOW,
            description=self.shared_tier_description,
            reason=(
                f"The first preference tier of `{curve_list}` mixes post-quantum and "
                "classical groups, so a client's leading classical key share "
                "wins."
            ),
            fixes=[
                self.make_fix(
                    title="Give post-quantum groups their own top tier",
                    search=f"ssl_ecdh_curve {curve_list}",
                    replace=f"ssl_ecdh_curve {self._tiered(tiers)}",
                ),
            ],
        )

    @classmethod
    def _tiered(cls, tiers):
        """Rebuild a group list with every post-quantum group `?`-prefixed in
        its own top tier, keeping the classical tiers in their original order.
        """
        pq = []
        rest = []
        for tier in tiers:
            classical = []
            for group in tier:
                if not cls._is_pq(group):
                    classical.append(group)
                elif group.startswith(TOLERANT_PREFIX):
                    pq.append(group)
                else:
                    pq.append(TOLERANT_PREFIX + group)
            if classical:
                rest.append(":".join(classical))
        return "/".join([":".join(pq)] + rest)

    @staticmethod
    def _name(group):
        """Strip OpenSSL group-list prefixes from one group token."""
        return group.lstrip(NAME_PREFIXES)

    @classmethod
    def _is_pq(cls, group):
        """Return True when a group token names a post-quantum hybrid.

        Args:
            group: A single group token as written in the config.

        Returns:
            True for post-quantum groups, with or without list prefixes.
        """
        upper = cls._name(group).upper()
        return any(marker in upper for marker in PQ_GROUP_MARKERS)
