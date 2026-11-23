"""Identify configuration prerequisites in the November 2026 NGINX advisories.

These checks identify exposure, not runtime exploitability. Request contents,
connection exhaustion and backend TLS behavior are outside static analysis.
"""


def _db():
    """Return the shared helpers after database initialization completes."""
    from gixy.plugins import _nginx_cves_db

    return _nginx_cves_db


def _servers(root, subsystem):
    """Yield server blocks directly inside the named subsystem."""
    for block in root.find(subsystem, flat=False):
        yield from block.find("server", flat=False)


def _effective(context, name):
    """Return the effective directive in this context and its ancestors."""
    return _db()._effective_directive(context, name)


def _protocol(server, name, listen_argument):
    """Return the directive enabling a protocol on an HTTP server."""
    listeners = list(server.find("listen", flat=False))
    setting = _effective(server, name)
    if name == "http3":
        if setting is not None and setting.args == ["off"]:
            return None
        return next((d for d in listeners if "quic" in d.args), None)
    legacy = next((d for d in listeners if listen_argument in d.args), None)
    if legacy is not None:
        return legacy
    if setting is not None and setting.args == ["on"]:
        return setting
    return None


def check_http2(root):
    """Yield HTTP servers with effective HTTP/2 enabled."""
    for server in _servers(root, "http"):
        directive = _protocol(server, "http2", "http2")
        if directive is not None:
            yield directive, directive


def check_http3(root):
    """Yield HTTP servers with QUIC listeners and HTTP/3 enabled."""
    for server in _servers(root, "http"):
        directive = _protocol(server, "http3", "quic")
        if directive is not None:
            yield directive, directive


def check_http2_proxy(root):
    """Yield backend proxying within servers accepting HTTP/2 clients."""
    for server in _servers(root, "http"):
        protocol = _protocol(server, "http2", "http2")
        if protocol is None:
            continue
        for context in _db()._request_contexts(server):
            for name in (
                "proxy_pass",
                "grpc_pass",
                "fastcgi_pass",
                "uwsgi_pass",
                "scgi_pass",
            ):
                for proxy in context.find(name, flat=False):
                    yield proxy, protocol


def _tls13_listeners(root, version):
    """Yield HTTP TLS listeners whose effective protocols include TLS 1.3.

    Args:
        root: Parsed configuration root block.
        version: Parsed OSS version tuple, or None for an unknown Plus base.

    Yields:
        Triples of server, listener and effective protocol directive (None when
        the version default applies).
    """
    for http in root.find("http", flat=False):
        listeners, defaults = _listener_defaults(http)
        for server, listener in listeners:
            if "ssl" not in listener.args:
                continue
            protocols = _effective(defaults[_endpoint(listener)], "ssl_protocols")
            if protocols is not None:
                if "TLSv1.3" not in protocols.args:
                    continue
            elif version is not None and version < (1, 23, 4):
                continue
            yield server, listener, protocols


def check_tls13_body(root, version):
    """Yield HTTP TLS listeners whose effective protocols include TLS 1.3.

    Yields:
        Pairs of listener and effective protocol directive, or listener twice.
    """
    for _, listener, protocols in _tls13_listeners(root, version):
        yield listener, protocols if protocols is not None else listener


def check_early_data(root, version):
    """Yield HTTP TLS 1.3 servers with effective ``ssl_early_data on``.

    Yields:
        Pairs of the effective ``ssl_early_data`` directive and the listener.
    """
    seen = set()
    for server, listener, _ in _tls13_listeners(root, version):
        early_data = _effective(server, "ssl_early_data")
        if early_data is None or early_data.args != ["on"]:
            continue
        if id(server) in seen:
            continue
        seen.add(id(server))
        yield early_data, listener


def check_mail_proxy(root):
    """Yield listening mail servers using the built-in mail proxy module.

    The mail proxy module has no proxy on/off directive. A listening mail
    server is the configuration prerequisite published in the advisory.
    """
    for server in _servers(root, "mail"):
        for listener in server.find("listen", flat=False):
            yield listener, listener


def check_stream_proxy_v2(root):
    """Yield stream TLS proxies combining dynamic certificates and PROXY v2."""
    for server in _servers(root, "stream"):
        protocol = _effective(server, "proxy_protocol")
        if protocol is None or protocol.args != ["v2"]:
            continue
        if _effective(server, "proxy_pass") is None:
            continue
        if not any("ssl" in d.args for d in server.find("listen", flat=False)):
            continue
        certificates = server.find("ssl_certificate", flat=False)
        if not certificates:
            certificate = _effective(server, "ssl_certificate")
            certificates = [certificate] if certificate is not None else []
        for certificate in certificates:
            if any(_db()._variable_refs(arg) for arg in certificate.args):
                yield certificate, protocol


def _endpoint(listener):
    """Normalize equivalent wildcard listen addresses for default selection."""
    address = listener.args[0]
    if address.isdigit():
        return "*:" + address
    return address.replace("0.0.0.0:", "*:", 1)


def _listener_defaults(subsystem):
    """Return listener pairs and endpoint-specific explicit or implicit defaults."""
    listeners = [
        (server, listener)
        for server in subsystem.find("server", flat=False)
        for listener in server.find("listen", flat=False)
    ]
    defaults = {}
    for server, listener in listeners:
        endpoint = _endpoint(listener)
        if endpoint not in defaults or "default_server" in listener.args:
            defaults[endpoint] = server
    return listeners, defaults


def check_stream_client_certificate(root):
    """Yield certificate verification in non-default stream TLS virtual servers."""
    for stream in root.find("stream", flat=False):
        listeners, defaults = _listener_defaults(stream)
        for server, listener in listeners:
            verify = _effective(server, "ssl_verify_client")
            if verify is None or verify.args != ["on"]:
                continue
            if "ssl" in listener.args and defaults[_endpoint(listener)] is not server:
                yield verify, listener


def check_stream_preread(root):
    """Yield effective stream SSL preread settings with listening servers."""
    for server in _servers(root, "stream"):
        preread = _effective(server, "ssl_preread")
        if preread is not None and preread.args == ["on"]:
            for listener in server.find("listen", flat=False):
                yield preread, listener


def check_alias_try_files_map(root):
    """Yield alias and try_files contexts consuming maps with regex captures."""
    maps = []
    for http in root.find("http", flat=False):
        for mapping in http.find("map", flat=False):
            if any(
                entry.is_regex and any(group != 0 for group in entry.regex.groups)
                for entry in mapping.gather_map_directives(mapping.children)
            ):
                maps.append((http, mapping))
    seen = set()
    for server in _servers(root, "http"):
        for context in _db()._request_contexts(server):
            alias = _db()._effective_alias(context)
            files = _effective(context, "try_files")
            if alias is None or files is None:
                continue
            refs = {ref for arg in files.args for ref in _db()._variable_refs(arg)}
            for http, mapping in maps:
                if server.parent is http and mapping.variable in refs:
                    pair = (files, alias)
                    if pair not in seen:
                        seen.add(pair)
                        yield pair


def _proxy_authority(proxy):
    """Return the proxy authority expression without scheme or request path."""
    if not proxy.args:
        return ""
    return proxy.args[0].split("://", 1)[-1].split("/", 1)[0]


def _mirror_target(server, uri):
    """Resolve static exact/prefix mirror routes, returning None for unknowns."""
    if _db()._variable_refs(uri):
        return None
    path = uri.split("?", 1)[0]
    locations = list(server.find_recursive("location"))
    exact = next((d for d in locations if d.modifier == "=" and d.path == path), None)
    if exact is not None:
        return exact
    prefixes = [d for d in locations if not d.is_regex and path.startswith(d.path)]
    target = max(prefixes, key=lambda d: len(d.path)) if prefixes else server
    if any(d.is_regex for d in locations) and (
        target is server or target.modifier != "^~"
    ):
        return None
    return target


def _mirrors(context):
    """Return the effective mirror array with whole-level inheritance."""
    while context is not None:
        directives = context.find("mirror", flat=False)
        if directives:
            return [d for d in directives if d.args and d.args != ["off"]]
        context = context.parent
    return []


def check_resolver_subrequest(root):
    """Yield variable-host proxying with SSI or mirror subrequest prerequisites.

    SSI content and variable values cannot be resolved statically. Require a
    second proxy context with the same hostname expression and a resolver;
    report these configuration prerequisites without claiming a runtime match.
    """
    for server in _servers(root, "http"):
        proxies = [
            (context, proxy)
            for context in _db()._request_contexts(server)
            for proxy in context.find("proxy_pass", flat=False)
            if _db()._variable_refs(_proxy_authority(proxy))
            and _effective(context, "resolver") is not None
        ]
        for context, proxy in proxies:
            ssi = _effective(context, "ssi")
            candidates = [
                other
                for other, target in proxies
                if other is not context
                and _proxy_authority(target) == _proxy_authority(proxy)
            ]
            if ssi is not None and ssi.args == ["on"] and candidates:
                yield proxy, ssi
                continue
            for mirror in _mirrors(context):
                route = _mirror_target(server, mirror.args[0])
                if any(
                    route is None
                    or other is route
                    or (other.name == "if" and _db()._inside_block(other, route))
                    for other in candidates
                ):
                    yield proxy, mirror
                    break


CHECKERS = {
    "CVE-2026-123634": check_resolver_subrequest,
    "CVE-2026-123007": check_http2,
    "CVE-2026-121810": check_http3,
    "CVE-2026-123633": check_http2_proxy,
    "CVE-2026-118899": check_tls13_body,
    "CVE-2026-132779": check_early_data,
    "CVE-2026-113425": check_mail_proxy,
    "CVE-2026-120993": check_stream_proxy_v2,
    "CVE-2026-125283": check_alias_try_files_map,
    "CVE-2026-120967": check_stream_client_certificate,
    "CVE-2026-123640": check_stream_preread,
}
