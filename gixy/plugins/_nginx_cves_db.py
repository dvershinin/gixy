"""nginx CVE database and config-trigger helpers.

This module is intentionally underscore-prefixed: the plugin loader in
``gixy/core/plugins_manager.py`` only imports ``gixy/plugins/*.py`` files
that do **not** start with ``_``. Keeping the CVE table here lets us
ship a large database without making ``nginx_cves.py`` unreadable.

Each CVE record in ``CVES`` is a dict with the following keys:

    id              CVE identifier (string).
    nickname        Optional short marketing name; '' if none.
    summary         One-line issue description (string).
    severity        gixy severity constant.
    advisory        Authoritative URL (string).
    vulnerable_oss  Tuple of inclusive ``(low, high)`` version-tuple
                    ranges as published in the nginx.org "Vulnerable"
                    column. Disjoint branches (mainline + stable
                    backport) are represented as multiple ranges.
    fixed_oss       Iterable of fixed OSS versions in string form.
                    Used both for the human-readable message *and* to
                    subtract per-branch post-fix tails when computing
                    the final ``affected_oss`` ranges.
    fixed_plus      Iterable of fixed Plus versions in string form.
    config_check    Optional callable
                    ``(root) -> iterable[(primary, related)]`` that
                    yields directive pairs the CVE attaches to.
                    ``None`` for binary-only CVEs (version match alone
                    fires).

After module load each record additionally carries an
``affected_oss`` key, computed as
``ranges_excluding_fixes(vulnerable_oss, fixed_oss)``. This is the
range the plugin actually consults — users whose version sits in a
patched-stable-branch hole are correctly excluded.
"""

import re

import gixy


def parse_oss(version_str):
    """Parse an nginx OSS version string like ``1.29.8`` into a tuple.

    Args:
        version_str: Version in ``X.Y.Z`` form. A leading ``v`` is tolerated.

    Returns:
        Tuple of three ints, or ``None`` if the string is not parseable.
    """
    if not version_str:
        return None
    cleaned = version_str.strip().lstrip("v")
    parts = cleaned.split(".")
    if len(parts) != 3:
        return None
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def in_range(version, low, high):
    """Return True iff ``version`` falls within the inclusive ``[low, high]`` range.

    Args:
        version: Parsed version tuple.
        low: Inclusive lower bound tuple.
        high: Inclusive upper bound tuple.

    Returns:
        True iff ``low <= version <= high``.
    """
    return low <= version <= high


def in_any_range(version, ranges):
    """Return True iff ``version`` falls in any of the supplied ranges.

    Args:
        version: Parsed version tuple.
        ranges: Iterable of ``(low, high)`` inclusive bound tuples.

    Returns:
        True iff at least one range covers the version.
    """
    return any(in_range(version, low, high) for low, high in ranges)


_BRANCH_PATCH_CEIL = 999


def _predecessor(version):
    """Return the closest version strictly less than ``version``.

    Used to compute the last vulnerable version on a branch given the
    fix point. The result preserves the branch (patch decrement) when
    possible; it only drops a branch when the fix is the .0 patch.

    Args:
        version: Three-tuple of ints ``(major, minor, patch)``.

    Returns:
        Three-tuple strictly less than ``version``.
    """
    major, minor, patch = version
    if patch > 0:
        return (major, minor, patch - 1)
    if minor > 0:
        return (major, minor - 1, _BRANCH_PATCH_CEIL)
    if major > 0:
        return (major - 1, _BRANCH_PATCH_CEIL, _BRANCH_PATCH_CEIL)
    return version


def ranges_excluding_fixes(spans, fixed_versions):
    """Subtract per-branch post-fix tails from the published vulnerable spans.

    nginx.org lists vulnerable versions as a contiguous span (e.g.
    ``1.11.4-1.27.3``) and fix points as a list (``1.26.3``, ``1.27.4``).
    A user on ``1.26.3`` is inside the span but on the fixed branch.
    For each fix ``(X, Y, Z)`` this helper removes ``[(X, Y, Z), (X, Y, 999)]``
    from the spans, splitting where necessary, so ``in_any_range`` will
    not flag patched users.

    Args:
        spans: Tuple of ``(low, high)`` inclusive bound tuples.
        fixed_versions: Iterable of version-string fixes (e.g. ``"1.26.3"``).

    Returns:
        Tuple of disjoint ``(low, high)`` ranges with fix tails removed.
    """
    fix_tuples = []
    for fixed in fixed_versions:
        parsed = parse_oss(fixed)
        if parsed is not None:
            fix_tuples.append(parsed)
    if not fix_tuples:
        return tuple(spans)
    result = list(spans)
    for fix in sorted(set(fix_tuples)):
        major, minor, _ = fix
        exclude_low = fix
        exclude_high = (major, minor, _BRANCH_PATCH_CEIL)
        new_result = []
        for low, high in result:
            if exclude_high < low or exclude_low > high:
                new_result.append((low, high))
                continue
            if low < exclude_low:
                left_high = _predecessor(exclude_low)
                if low <= left_high:
                    new_result.append((low, left_high))
            if exclude_high < high:
                right_low = (major, minor + 1, 0)
                if right_low <= high:
                    new_result.append((right_low, high))
        result = new_result
    return tuple(result)


# --------------------------------------------------------------------------
# Trigger helpers. Each yields ``(primary, related)`` directive tuples; when
# only one directive is relevant the helper yields ``(d, d)`` so the
# downstream ``add_issue(directive=[primary, related])`` call stays uniform.
# --------------------------------------------------------------------------

_UNNAMED_BACKREF = re.compile(r"\$(?:[1-9]|\{[1-9]\})")
_SCRIPT_ENGINE_TRIGGERS = ("rewrite", "if", "set")


def check_rewrite_rift(root):
    """Find rewrite directives that trigger CVE-2026-42945.

    The trigger is a ``rewrite`` whose replacement contains both an
    unnamed PCRE backreference (``$1``..``$9`` or ``${1}``..``${9}``) and
    a literal ``?``, followed by another ``rewrite``/``if``/``set``
    sibling in the same parent context.

    Args:
        root: Root Block of the parsed nginx config tree.

    Yields:
        ``(rewrite_directive, follow_up_sibling)`` tuples for each match.
    """
    for rewrite in root.find_recursive("rewrite"):
        if len(rewrite.args) < 2:
            continue
        replace = rewrite.args[1]
        if "?" not in replace:
            continue
        if not _UNNAMED_BACKREF.search(replace):
            continue
        parent = rewrite.parent
        if parent is None or not parent.children:
            continue
        siblings = parent.children
        idx = next((i for i, c in enumerate(siblings) if c is rewrite), None)
        if idx is None:
            continue
        follow_up = next(
            (c for c in siblings[idx + 1 :] if c.name in _SCRIPT_ENGINE_TRIGGERS),
            None,
        )
        if follow_up is None:
            continue
        yield rewrite, follow_up


def _listens_with_arg(root, arg):
    """Yield every ``listen`` directive whose args contain ``arg``.

    Args:
        root: Root Block of the parsed config.
        arg: Listen parameter to search for (``ssl``, ``http2``, ``quic``,
            ``spdy``).

    Yields:
        Listen directive objects.
    """
    for listen in root.find_recursive("listen"):
        if arg in listen.args:
            yield listen


def _first_or_none(iterable):
    """Return the first item of ``iterable`` or ``None``.

    Args:
        iterable: Any iterable.

    Returns:
        First item, or ``None`` if exhausted.
    """
    return next(iter(iterable), None)


def _top_level_block(root, name):
    """Return the first top-level block matching ``name``, or ``None``.

    Args:
        root: Root Block of the parsed config.
        name: Block name (``mail``, ``stream``, etc.).

    Returns:
        The matching block, or ``None``.
    """
    for child in root.children:
        if child.name == name and child.is_block:
            return child
    return None


def check_mp4_module(root):
    """Yield ``mp4`` directives present anywhere in the config.

    The ``mp4`` flag directive enables the mp4 module for a location; if
    it is missing, every mp4-module CVE is irrelevant for this config.

    Args:
        root: Root Block of the parsed config.

    Yields:
        ``(mp4_directive, mp4_directive)`` tuples.
    """
    for mp4 in root.find_recursive("mp4"):
        yield mp4, mp4


def check_http2_enabled(root):
    """Yield directives that enable HTTP/2.

    Detects both the legacy ``listen ... http2`` parameter and the
    standalone ``http2 on;`` directive introduced in nginx 1.25.1.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(directive, directive)``.
    """
    for listen in _listens_with_arg(root, "http2"):
        yield listen, listen
    for directive in root.find_recursive("http2"):
        if directive.args and directive.args[0] == "on":
            yield directive, directive


def check_http3_enabled(root):
    """Yield directives that enable HTTP/3 / QUIC.

    Detects both ``listen ... quic`` and the standalone ``http3 on;``
    directive.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(directive, directive)``.
    """
    for listen in _listens_with_arg(root, "quic"):
        yield listen, listen
    for directive in root.find_recursive("http3"):
        if directive.args and directive.args[0] == "on":
            yield directive, directive


def check_resolver(root):
    """Yield every ``resolver`` directive in the config.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(resolver, resolver)``.
    """
    for resolver in root.find_recursive("resolver"):
        yield resolver, resolver


def check_ssl_session_reuse(root):
    """Yield SSL session-reuse directives that expose the config to the bug.

    Conservative heuristic: a config is at risk when either
    ``ssl_session_tickets`` is explicitly enabled (default is ``on``,
    flagged when set on or shared via ticket key) or
    ``ssl_session_cache shared:`` is used to share a cache across
    virtual hosts.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(directive, directive)``.
    """
    for tickets in root.find_recursive("ssl_session_tickets"):
        if not tickets.args or tickets.args[0] != "off":
            yield tickets, tickets
    for cache in root.find_recursive("ssl_session_cache"):
        if any(arg.startswith("shared:") for arg in cache.args):
            yield cache, cache
    for key in root.find_recursive("ssl_session_ticket_key"):
        yield key, key


def check_dav(root):
    """Yield WebDAV-enabling directives (``dav_methods``).

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(directive, directive)``.
    """
    for dav in root.find_recursive("dav_methods"):
        yield dav, dav


def check_scgi_or_uwsgi(root):
    """Yield ``scgi_pass`` and ``uwsgi_pass`` directives.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(pass_directive, pass_directive)``.
    """
    for name in ("scgi_pass", "uwsgi_pass"):
        for directive in root.find_recursive(name):
            yield directive, directive


def check_charset(root):
    """Yield ``charset`` directives whose value is not ``off``.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(charset, charset)``.
    """
    for charset in root.find_recursive("charset"):
        if not charset.args:
            continue
        if charset.args[0] == "off":
            continue
        yield charset, charset


def check_mail_block(root):
    """Yield the top-level ``mail`` block if it exists.

    Many mail-module CVEs apply whenever a mail block is configured.

    Args:
        root: Root Block of the parsed config.

    Yields:
        ``(mail_block, mail_block)``.
    """
    mail = _top_level_block(root, "mail")
    if mail is not None:
        yield mail, mail


def _mail_directive(root, name, arg_predicate=None):
    """Yield directives inside the ``mail`` block matching ``name``.

    Args:
        root: Root Block of the parsed config.
        name: Directive name to search for.
        arg_predicate: Optional callable taking the directive's args
            list and returning a truthy value for matches.

    Yields:
        Tuples of ``(directive, directive)``.
    """
    mail = _top_level_block(root, "mail")
    if mail is None:
        return
    for directive in mail.find_recursive(name):
        if arg_predicate is not None and not arg_predicate(directive.args):
            continue
        yield directive, directive


def check_mail_auth_http(root):
    """Yield ``auth_http`` directives inside the mail block.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(auth_http, auth_http)``.
    """
    yield from _mail_directive(root, "auth_http")


def check_mail_smtp(root):
    """Yield directives indicating SMTP protocol use in the mail block.

    Matches ``protocol smtp;`` or any ``smtp_*`` directive.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(directive, directive)``.
    """
    mail = _top_level_block(root, "mail")
    if mail is None:
        return
    for protocol in mail.find_recursive("protocol"):
        if protocol.args and protocol.args[0] == "smtp":
            yield protocol, protocol
    for smtp_directive in (
        "smtp_auth",
        "smtp_capabilities",
        "smtp_client_buffer",
        "smtp_greeting_delay",
    ):
        for directive in mail.find_recursive(smtp_directive):
            yield directive, directive


def check_mail_cram_md5_apop(root):
    """Yield mail auth directives selecting CRAM-MD5 or APOP.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(directive, directive)``.
    """
    mail = _top_level_block(root, "mail")
    if mail is None:
        return
    auth_directives = ("imap_auth", "pop3_auth", "smtp_auth", "auth")
    for name in auth_directives:
        for directive in mail.find_recursive(name):
            args_lower = [arg.lower() for arg in directive.args]
            if "cram-md5" in args_lower or "apop" in args_lower:
                yield directive, directive


def check_mail_starttls(root):
    """Yield ``starttls`` directives with non-``off`` value in the mail block.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(starttls, starttls)``.
    """
    yield from _mail_directive(
        root,
        "starttls",
        arg_predicate=lambda args: bool(args) and args[0] != "off",
    )


def check_stream_ssl_ocsp(root):
    """Yield ``ssl_ocsp`` directives inside the ``stream`` block.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(ssl_ocsp, ssl_ocsp)``.
    """
    stream = _top_level_block(root, "stream")
    if stream is None:
        return
    for directive in stream.find_recursive("ssl_ocsp"):
        yield directive, directive


def check_spdy_listen(root):
    """Yield ``listen`` directives that enable SPDY.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(listen, listen)``.
    """
    for listen in _listens_with_arg(root, "spdy"):
        yield listen, listen


def check_ssl_listen(root):
    """Yield directives that activate SSL/TLS on a listener.

    Matches ``listen ... ssl`` parameters and the legacy ``ssl on;``
    directive.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(directive, directive)``.
    """
    for listen in _listens_with_arg(root, "ssl"):
        yield listen, listen
    for directive in root.find_recursive("ssl"):
        if directive.args and directive.args[0] == "on":
            yield directive, directive


def check_proxy_pass(root):
    """Yield every ``proxy_pass`` directive.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(proxy_pass, proxy_pass)``.
    """
    for proxy in root.find_recursive("proxy_pass"):
        yield proxy, proxy


def check_proxy_ssl_upstream(root):
    """Yield directives indicating SSL is used toward upstream.

    Matches ``proxy_pass https://...`` and any explicit ``proxy_ssl_*``
    directive.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(directive, directive)``.
    """
    for proxy in root.find_recursive("proxy_pass"):
        if proxy.args and proxy.args[0].startswith("https://"):
            yield proxy, proxy
    for name in (
        "proxy_ssl_certificate",
        "proxy_ssl_certificate_key",
        "proxy_ssl_verify",
        "proxy_ssl_protocols",
        "proxy_ssl_ciphers",
        "proxy_ssl_session_reuse",
    ):
        for directive in root.find_recursive(name):
            yield directive, directive


def check_grpc_or_http2_upstream(root):
    """Yield directives that activate HTTP/2-based upstream proxying.

    Matches every ``grpc_pass`` directive (gRPC always travels over
    HTTP/2) and ``proxy_http_version 2.0`` settings. Used for
    CVE-2026-42055.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(directive, directive)``.
    """
    for directive in root.find_recursive("grpc_pass"):
        yield directive, directive
    for directive in root.find_recursive("proxy_http_version"):
        if directive.args and directive.args[0] == "2.0":
            yield directive, directive


def check_proxy_with_http2(root):
    """Yield ``proxy_pass`` directives if HTTP/2 is also enabled.

    CVE-2026-42926 is a request-injection bug in the proxy module
    triggered through HTTP/2; both pieces must be present for the
    config to be at risk.

    Args:
        root: Root Block of the parsed config.

    Yields:
        Tuples of ``(proxy_pass, listen_or_http2)``.
    """
    http2_directive = _first_or_none(check_http2_enabled(root))
    if http2_directive is None:
        return
    enabling = http2_directive[0]
    for proxy in root.find_recursive("proxy_pass"):
        yield proxy, enabling


# --------------------------------------------------------------------------
# CVE records. Sorted newest first so future additions land at the top
# and the historical tail stays stable across diffs.
# --------------------------------------------------------------------------

_ADVISORY_NVD = "https://nvd.nist.gov/vuln/detail/"
_ADVISORY_NGINX = "https://nginx.org/en/security_advisories.html"


def _advisory(cve_id):
    """Return the canonical advisory URL for a CVE id.

    Args:
        cve_id: CVE identifier.

    Returns:
        NVD detail URL.
    """
    return _ADVISORY_NVD + cve_id


CVES = (
    {
        "id": "CVE-2026-42530",
        "nickname": "",
        "summary": "Use-after-free in ngx_http_v3_module.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2026-42530"),
        "vulnerable_oss": (((1, 31, 0), (1, 31, 1)),),
        "fixed_oss": ("1.31.2",),
        "fixed_plus": (),
        "config_check": check_http3_enabled,
    },
    {
        "id": "CVE-2026-42055",
        "nickname": "",
        "summary": "Buffer overflow in ngx_http_proxy_v2_module and ngx_http_grpc_module.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2026-42055"),
        "vulnerable_oss": (((1, 13, 10), (1, 31, 1)),),
        "fixed_oss": ("1.30.3", "1.31.2"),
        "fixed_plus": (),
        "config_check": check_grpc_or_http2_upstream,
    },
    {
        "id": "CVE-2026-48142",
        "nickname": "",
        "summary": "Buffer overread in ngx_http_charset_module.",
        "severity": gixy.severity.LOW,
        "advisory": _advisory("CVE-2026-48142"),
        "vulnerable_oss": (((0, 3, 50), (1, 31, 1)),),
        "fixed_oss": ("1.30.3", "1.31.2"),
        "fixed_plus": (),
        "config_check": check_charset,
    },
    {
        "id": "CVE-2026-9256",
        "nickname": "",
        "summary": "Heap overflow in ngx_http_rewrite_module triggered by overlapping captures.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2026-9256"),
        "vulnerable_oss": (((0, 1, 17), (1, 31, 0)),),
        "fixed_oss": ("1.30.2", "1.31.1"),
        "fixed_plus": (),
        "config_check": None,
    },
    {
        "id": "CVE-2026-42945",
        "nickname": "NGINX Rift",
        "summary": "Heap overflow in ngx_http_rewrite_module.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2026-42945"),
        "vulnerable_oss": (((0, 6, 27), (1, 30, 0)),),
        "fixed_oss": ("1.30.1", "1.31.0"),
        "fixed_plus": ("R32 P6", "R36 P4"),
        "config_check": check_rewrite_rift,
    },
    {
        "id": "CVE-2026-42926",
        "nickname": "",
        "summary": "HTTP/2 request injection in ngx_http_proxy_module.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2026-42926"),
        "vulnerable_oss": (((1, 29, 4), (1, 30, 0)),),
        "fixed_oss": ("1.30.1", "1.31.0"),
        "fixed_plus": (),
        "config_check": check_proxy_with_http2,
    },
    {
        "id": "CVE-2026-42946",
        "nickname": "",
        "summary": "Buffer overread in ngx_http_scgi_module and ngx_http_uwsgi_module.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2026-42946"),
        "vulnerable_oss": (((0, 8, 42), (1, 30, 0)),),
        "fixed_oss": ("1.30.1", "1.31.0"),
        "fixed_plus": (),
        "config_check": check_scgi_or_uwsgi,
    },
    {
        "id": "CVE-2026-42934",
        "nickname": "",
        "summary": "Buffer overread in ngx_http_charset_module.",
        "severity": gixy.severity.LOW,
        "advisory": _advisory("CVE-2026-42934"),
        "vulnerable_oss": (((0, 3, 50), (1, 30, 0)),),
        "fixed_oss": ("1.30.1", "1.31.0"),
        "fixed_plus": (),
        "config_check": check_charset,
    },
    {
        "id": "CVE-2026-40460",
        "nickname": "",
        "summary": "HTTP/3 address spoofing.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2026-40460"),
        "vulnerable_oss": (((1, 25, 0), (1, 30, 0)),),
        "fixed_oss": ("1.30.1", "1.31.0"),
        "fixed_plus": (),
        "config_check": check_http3_enabled,
    },
    {
        "id": "CVE-2026-40701",
        "nickname": "",
        "summary": "Use-after-free in resolver during OCSP processing.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2026-40701"),
        "vulnerable_oss": (((1, 19, 0), (1, 30, 0)),),
        "fixed_oss": ("1.30.1", "1.31.0"),
        "fixed_plus": (),
        "config_check": check_resolver,
    },
    {
        "id": "CVE-2026-27654",
        "nickname": "",
        "summary": "Buffer overflow in ngx_http_dav_module.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2026-27654"),
        "vulnerable_oss": (((0, 5, 13), (1, 29, 6)),),
        "fixed_oss": ("1.28.3", "1.29.7"),
        "fixed_plus": (),
        "config_check": check_dav,
    },
    {
        "id": "CVE-2026-27784",
        "nickname": "",
        "summary": "Buffer overflow in ngx_http_mp4_module.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2026-27784"),
        "vulnerable_oss": (((1, 1, 19), (1, 29, 6)),),
        "fixed_oss": ("1.28.3", "1.29.7"),
        "fixed_plus": (),
        "config_check": check_mp4_module,
    },
    {
        "id": "CVE-2026-32647",
        "nickname": "",
        "summary": "Buffer overflow in ngx_http_mp4_module.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2026-32647"),
        "vulnerable_oss": (((1, 1, 19), (1, 29, 6)),),
        "fixed_oss": ("1.28.3", "1.29.7"),
        "fixed_plus": (),
        "config_check": check_mp4_module,
    },
    {
        "id": "CVE-2026-27651",
        "nickname": "",
        "summary": "NULL pointer dereference while using CRAM-MD5 or APOP authentication.",
        "severity": gixy.severity.LOW,
        "advisory": _advisory("CVE-2026-27651"),
        "vulnerable_oss": (((0, 5, 15), (1, 29, 6)),),
        "fixed_oss": ("1.28.3", "1.29.7"),
        "fixed_plus": (),
        "config_check": check_mail_cram_md5_apop,
    },
    {
        "id": "CVE-2026-28753",
        "nickname": "",
        "summary": "Injection in mail auth_http and XCLIENT.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2026-28753"),
        "vulnerable_oss": (((0, 6, 27), (1, 29, 6)),),
        "fixed_oss": ("1.28.3", "1.29.7"),
        "fixed_plus": (),
        "config_check": check_mail_auth_http,
    },
    {
        "id": "CVE-2026-28755",
        "nickname": "",
        "summary": "OCSP result bypass in stream module.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2026-28755"),
        "vulnerable_oss": (((1, 27, 2), (1, 29, 6)),),
        "fixed_oss": ("1.28.3", "1.29.7"),
        "fixed_plus": (),
        "config_check": check_stream_ssl_ocsp,
    },
    {
        "id": "CVE-2026-1642",
        "nickname": "",
        "summary": "SSL upstream injection.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2026-1642"),
        "vulnerable_oss": (((1, 3, 0), (1, 29, 4)),),
        "fixed_oss": ("1.28.2", "1.29.5"),
        "fixed_plus": (),
        "config_check": check_proxy_ssl_upstream,
    },
    {
        "id": "CVE-2025-53859",
        "nickname": "",
        "summary": "Buffer overread in ngx_mail_smtp_module.",
        "severity": gixy.severity.LOW,
        "advisory": _advisory("CVE-2025-53859"),
        "vulnerable_oss": (((0, 7, 22), (1, 29, 0)),),
        "fixed_oss": ("1.29.1",),
        "fixed_plus": (),
        "config_check": check_mail_smtp,
    },
    {
        "id": "CVE-2025-23419",
        "nickname": "",
        "summary": "SSL session reuse vulnerability allowing authentication bypass.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2025-23419"),
        "vulnerable_oss": (((1, 11, 4), (1, 27, 3)),),
        "fixed_oss": ("1.26.3", "1.27.4"),
        "fixed_plus": (),
        "config_check": check_ssl_session_reuse,
    },
    {
        "id": "CVE-2024-7347",
        "nickname": "",
        "summary": "Buffer overread in ngx_http_mp4_module.",
        "severity": gixy.severity.LOW,
        "advisory": _advisory("CVE-2024-7347"),
        "vulnerable_oss": (((1, 5, 13), (1, 27, 0)),),
        "fixed_oss": ("1.26.2", "1.27.1"),
        "fixed_plus": (),
        "config_check": check_mp4_module,
    },
    {
        "id": "CVE-2024-32760",
        "nickname": "",
        "summary": "Buffer overwrite in HTTP/3.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2024-32760"),
        "vulnerable_oss": (
            ((1, 25, 0), (1, 25, 5)),
            ((1, 26, 0), (1, 26, 0)),
        ),
        "fixed_oss": ("1.26.1", "1.27.0"),
        "fixed_plus": (),
        "config_check": check_http3_enabled,
    },
    {
        "id": "CVE-2024-31079",
        "nickname": "",
        "summary": "Stack overflow and use-after-free in HTTP/3.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2024-31079"),
        "vulnerable_oss": (
            ((1, 25, 0), (1, 25, 5)),
            ((1, 26, 0), (1, 26, 0)),
        ),
        "fixed_oss": ("1.26.1", "1.27.0"),
        "fixed_plus": (),
        "config_check": check_http3_enabled,
    },
    {
        "id": "CVE-2024-35200",
        "nickname": "",
        "summary": "NULL pointer dereference in HTTP/3.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2024-35200"),
        "vulnerable_oss": (
            ((1, 25, 0), (1, 25, 5)),
            ((1, 26, 0), (1, 26, 0)),
        ),
        "fixed_oss": ("1.26.1", "1.27.0"),
        "fixed_plus": (),
        "config_check": check_http3_enabled,
    },
    {
        "id": "CVE-2024-34161",
        "nickname": "",
        "summary": "Memory disclosure in HTTP/3.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2024-34161"),
        "vulnerable_oss": (
            ((1, 25, 0), (1, 25, 5)),
            ((1, 26, 0), (1, 26, 0)),
        ),
        "fixed_oss": ("1.26.1", "1.27.0"),
        "fixed_plus": (),
        "config_check": check_http3_enabled,
    },
    {
        "id": "CVE-2024-24989",
        "nickname": "",
        "summary": "NULL pointer dereference in HTTP/3.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2024-24989"),
        "vulnerable_oss": (((1, 25, 3), (1, 25, 3)),),
        "fixed_oss": ("1.25.4",),
        "fixed_plus": (),
        "config_check": check_http3_enabled,
    },
    {
        "id": "CVE-2024-24990",
        "nickname": "",
        "summary": "Use-after-free in HTTP/3.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2024-24990"),
        "vulnerable_oss": (((1, 25, 0), (1, 25, 3)),),
        "fixed_oss": ("1.25.4",),
        "fixed_plus": (),
        "config_check": check_http3_enabled,
    },
    {
        "id": "CVE-2022-41741",
        "nickname": "",
        "summary": "Memory corruption in ngx_http_mp4_module.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2022-41741"),
        "vulnerable_oss": (
            ((1, 1, 3), (1, 23, 1)),
            ((1, 0, 7), (1, 0, 15)),
        ),
        "fixed_oss": ("1.22.1", "1.23.2"),
        "fixed_plus": (),
        "config_check": check_mp4_module,
    },
    {
        "id": "CVE-2022-41742",
        "nickname": "",
        "summary": "Memory disclosure in ngx_http_mp4_module.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2022-41742"),
        "vulnerable_oss": (
            ((1, 1, 3), (1, 23, 1)),
            ((1, 0, 7), (1, 0, 15)),
        ),
        "fixed_oss": ("1.22.1", "1.23.2"),
        "fixed_plus": (),
        "config_check": check_mp4_module,
    },
    {
        "id": "CVE-2021-23017",
        "nickname": "",
        "summary": "1-byte memory overwrite in resolver.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2021-23017"),
        "vulnerable_oss": (((0, 6, 18), (1, 20, 0)),),
        "fixed_oss": ("1.20.1", "1.21.0"),
        "fixed_plus": (),
        "config_check": check_resolver,
    },
    {
        "id": "CVE-2019-9511",
        "nickname": "Data Dribble",
        "summary": "Excessive CPU usage via HTTP/2 small window updates.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2019-9511"),
        "vulnerable_oss": (((1, 9, 5), (1, 17, 2)),),
        "fixed_oss": ("1.16.1", "1.17.3"),
        "fixed_plus": (),
        "config_check": check_http2_enabled,
    },
    {
        "id": "CVE-2019-9513",
        "nickname": "Resource Loop",
        "summary": "Excessive CPU usage via HTTP/2 priority changes.",
        "severity": gixy.severity.LOW,
        "advisory": _advisory("CVE-2019-9513"),
        "vulnerable_oss": (((1, 9, 5), (1, 17, 2)),),
        "fixed_oss": ("1.16.1", "1.17.3"),
        "fixed_plus": (),
        "config_check": check_http2_enabled,
    },
    {
        "id": "CVE-2019-9516",
        "nickname": "0-Length Headers Leak",
        "summary": "Excessive memory usage via HTTP/2 zero-length headers.",
        "severity": gixy.severity.LOW,
        "advisory": _advisory("CVE-2019-9516"),
        "vulnerable_oss": (((1, 9, 5), (1, 17, 2)),),
        "fixed_oss": ("1.16.1", "1.17.3"),
        "fixed_plus": (),
        "config_check": check_http2_enabled,
    },
    {
        "id": "CVE-2018-16843",
        "nickname": "",
        "summary": "Excessive memory usage in HTTP/2 implementation.",
        "severity": gixy.severity.LOW,
        "advisory": _advisory("CVE-2018-16843"),
        "vulnerable_oss": (((1, 9, 5), (1, 15, 5)),),
        "fixed_oss": ("1.14.1", "1.15.6"),
        "fixed_plus": (),
        "config_check": check_http2_enabled,
    },
    {
        "id": "CVE-2018-16844",
        "nickname": "",
        "summary": "Excessive CPU usage in HTTP/2 implementation.",
        "severity": gixy.severity.LOW,
        "advisory": _advisory("CVE-2018-16844"),
        "vulnerable_oss": (((1, 9, 5), (1, 15, 5)),),
        "fixed_oss": ("1.14.1", "1.15.6"),
        "fixed_plus": (),
        "config_check": check_http2_enabled,
    },
    {
        "id": "CVE-2018-16845",
        "nickname": "",
        "summary": "Memory disclosure in ngx_http_mp4_module.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2018-16845"),
        "vulnerable_oss": (
            ((1, 1, 3), (1, 15, 5)),
            ((1, 0, 7), (1, 0, 15)),
        ),
        "fixed_oss": ("1.14.1", "1.15.6"),
        "fixed_plus": (),
        "config_check": check_mp4_module,
    },
    {
        "id": "CVE-2017-7529",
        "nickname": "",
        "summary": "Integer overflow in the range filter.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2017-7529"),
        "vulnerable_oss": (((0, 5, 6), (1, 13, 2)),),
        "fixed_oss": ("1.12.1", "1.13.3"),
        "fixed_plus": (),
        "config_check": None,
    },
    {
        "id": "CVE-2016-4450",
        "nickname": "",
        "summary": "NULL pointer dereference while writing client request body.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2016-4450"),
        "vulnerable_oss": (((1, 3, 9), (1, 11, 0)),),
        "fixed_oss": ("1.10.1", "1.11.1"),
        "fixed_plus": (),
        "config_check": None,
    },
    {
        "id": "CVE-2016-0742",
        "nickname": "",
        "summary": "Invalid pointer dereference in resolver.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2016-0742"),
        "vulnerable_oss": (((0, 6, 18), (1, 9, 9)),),
        "fixed_oss": ("1.8.1", "1.9.10"),
        "fixed_plus": (),
        "config_check": check_resolver,
    },
    {
        "id": "CVE-2016-0746",
        "nickname": "",
        "summary": "Use-after-free during CNAME response processing in resolver.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2016-0746"),
        "vulnerable_oss": (((0, 6, 18), (1, 9, 9)),),
        "fixed_oss": ("1.8.1", "1.9.10"),
        "fixed_plus": (),
        "config_check": check_resolver,
    },
    {
        "id": "CVE-2016-0747",
        "nickname": "",
        "summary": "Insufficient limits of CNAME resolution in resolver.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2016-0747"),
        "vulnerable_oss": (((0, 6, 18), (1, 9, 9)),),
        "fixed_oss": ("1.8.1", "1.9.10"),
        "fixed_plus": (),
        "config_check": check_resolver,
    },
    {
        "id": "CVE-2014-3616",
        "nickname": "",
        "summary": "SSL session reuse vulnerability.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2014-3616"),
        "vulnerable_oss": (((0, 5, 6), (1, 7, 4)),),
        "fixed_oss": ("1.6.2", "1.7.5"),
        "fixed_plus": (),
        "config_check": check_ssl_session_reuse,
    },
    {
        "id": "CVE-2014-3556",
        "nickname": "",
        "summary": "STARTTLS command injection.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2014-3556"),
        "vulnerable_oss": (((1, 5, 6), (1, 7, 3)),),
        "fixed_oss": ("1.6.1", "1.7.4"),
        "fixed_plus": (),
        "config_check": check_mail_starttls,
    },
    {
        "id": "CVE-2014-0133",
        "nickname": "",
        "summary": "SPDY heap buffer overflow.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2014-0133"),
        "vulnerable_oss": (((1, 3, 15), (1, 5, 11)),),
        "fixed_oss": ("1.4.7", "1.5.12"),
        "fixed_plus": (),
        "config_check": check_spdy_listen,
    },
    {
        "id": "CVE-2014-0088",
        "nickname": "",
        "summary": "SPDY memory corruption.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2014-0088"),
        "vulnerable_oss": (((1, 5, 10), (1, 5, 10)),),
        "fixed_oss": ("1.5.11",),
        "fixed_plus": (),
        "config_check": check_spdy_listen,
    },
    {
        "id": "CVE-2013-4547",
        "nickname": "",
        "summary": "Request line parsing vulnerability.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2013-4547"),
        "vulnerable_oss": (((0, 8, 41), (1, 5, 6)),),
        "fixed_oss": ("1.4.4", "1.5.7"),
        "fixed_plus": (),
        "config_check": None,
    },
    {
        "id": "CVE-2013-2070",
        "nickname": "",
        "summary": "Memory disclosure with specially crafted HTTP backend responses.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2013-2070"),
        "vulnerable_oss": (
            ((1, 1, 4), (1, 2, 8)),
            ((1, 3, 9), (1, 4, 0)),
        ),
        "fixed_oss": ("1.2.9", "1.4.1", "1.5.0"),
        "fixed_plus": (),
        "config_check": check_proxy_pass,
    },
    {
        "id": "CVE-2013-2028",
        "nickname": "",
        "summary": "Stack-based buffer overflow with specially crafted request.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2013-2028"),
        "vulnerable_oss": (((1, 3, 9), (1, 4, 0)),),
        "fixed_oss": ("1.4.1", "1.5.0"),
        "fixed_plus": (),
        "config_check": None,
    },
    {
        "id": "CVE-2012-2089",
        "nickname": "",
        "summary": "Buffer overflow in ngx_http_mp4_module.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2012-2089"),
        "vulnerable_oss": (
            ((1, 1, 3), (1, 1, 18)),
            ((1, 0, 7), (1, 0, 14)),
        ),
        "fixed_oss": ("1.0.15", "1.1.19"),
        "fixed_plus": (),
        "config_check": check_mp4_module,
    },
    {
        "id": "CVE-2012-1180",
        "nickname": "",
        "summary": "Memory disclosure with specially crafted backend responses.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2012-1180"),
        "vulnerable_oss": (((0, 1, 0), (1, 1, 16)),),
        "fixed_oss": ("1.0.14", "1.1.17"),
        "fixed_plus": (),
        "config_check": check_proxy_pass,
    },
    {
        "id": "CVE-2011-4315",
        "nickname": "",
        "summary": "Buffer overflow in resolver.",
        "severity": gixy.severity.MEDIUM,
        "advisory": _advisory("CVE-2011-4315"),
        "vulnerable_oss": (((0, 6, 18), (1, 1, 7)),),
        "fixed_oss": ("1.0.10", "1.1.8"),
        "fixed_plus": (),
        "config_check": check_resolver,
    },
    {
        "id": "CVE-2009-3898",
        "nickname": "",
        "summary": "Directory traversal vulnerability.",
        "severity": gixy.severity.LOW,
        "advisory": _advisory("CVE-2009-3898"),
        "vulnerable_oss": (((0, 1, 0), (0, 8, 16)),),
        "fixed_oss": ("0.7.63", "0.8.17"),
        "fixed_plus": (),
        "config_check": None,
    },
    {
        "id": "CVE-2009-3896",
        "nickname": "",
        "summary": "NULL pointer dereference vulnerability.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2009-3896"),
        "vulnerable_oss": (((0, 1, 0), (0, 8, 13)),),
        "fixed_oss": ("0.5.38", "0.6.39", "0.7.62", "0.8.14"),
        "fixed_plus": (),
        "config_check": None,
    },
    {
        "id": "CVE-2009-3555",
        "nickname": "",
        "summary": "TLS renegotiation vulnerability in SSL protocol.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2009-3555"),
        "vulnerable_oss": (((0, 1, 0), (0, 8, 22)),),
        "fixed_oss": ("0.7.64", "0.8.23"),
        "fixed_plus": (),
        "config_check": check_ssl_listen,
    },
    {
        "id": "CVE-2009-2629",
        "nickname": "",
        "summary": "Buffer underflow vulnerability.",
        "severity": gixy.severity.HIGH,
        "advisory": _advisory("CVE-2009-2629"),
        "vulnerable_oss": (((0, 1, 0), (0, 8, 14)),),
        "fixed_oss": ("0.5.38", "0.6.39", "0.7.62", "0.8.15"),
        "fixed_plus": (),
        "config_check": None,
    },
)


for _record in CVES:
    _record["affected_oss"] = ranges_excluding_fixes(
        _record["vulnerable_oss"], _record["fixed_oss"]
    )
del _record
