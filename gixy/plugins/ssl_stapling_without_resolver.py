import gixy
from gixy.plugins.plugin import Plugin


class ssl_stapling_without_resolver(Plugin):
    """Detect SSL servers with ssl_stapling effectively on but no resolver in scope."""

    summary = "ssl_stapling is enabled but no resolver is configured — stapling silently fails."
    severity = gixy.severity.MEDIUM
    description = (
        "`ssl_stapling on` requires a reachable `resolver` directive in the "
        "same or a parent scope. Without it, nginx cannot fetch the OCSP "
        "response from the issuing CA and stapling becomes a no-op — clients "
        "fall back to making their own OCSP requests, defeating the purpose "
        "of stapling. Add a *local* resolver — `resolver 127.0.0.1 valid=300s ipv6=off;` or your provider's internal DNS — to "
        "the server or http block. For production hardening also set "
        "`ssl_stapling_verify on;` and `resolver_timeout 5s;`."
    )
    directives = ["server"]

    def audit(self, server):
        """Report SSL servers where ssl_stapling is effectively on without a resolver.

        Audits at the server-block grain. `ssl_stapling` is inheritable from
        http to server, so a directive declared at http scope can enable
        stapling for many servers; conversely a server can override with
        `ssl_stapling off`. We resolve the effective state per server, then
        check whether a `resolver` directive is reachable in or above the
        server scope.

        Args:
            server: The server Block to audit.
        """
        if not server.is_block:
            return

        if not self._is_ssl_server(server):
            return

        stapling = self._effective_directive(server, "ssl_stapling")
        if not stapling or not stapling.args or stapling.args[0].lower() != "on":
            return

        if self._has_in_scope(server, "resolver"):
            return

        self.add_issue(
            directive=stapling,
            reason=(
                "ssl_stapling is enabled for this SSL server, but no "
                "`resolver` directive is reachable in its scope — OCSP "
                "stapling will silently fail."
            ),
        )

    def _is_ssl_server(self, server):
        """Return True if any listen directive enables SSL/QUIC/HTTP3.

        Args:
            server: The server Block to inspect.

        Returns:
            True when at least one `listen` carries `ssl`, `quic`, or
            `http3` — the contexts where OCSP stapling is meaningful.
        """
        for listen in server.find("listen"):
            if any(arg.lower() in ("ssl", "quic", "http3") for arg in listen.args):
                return True
        return False

    def _effective_directive(self, server, name):
        """Find the directive that effectively applies at this server's scope.

        Looks at the server's own children first (an explicit override wins),
        then walks up through parent scopes (http, root) so inherited
        declarations are surfaced too.

        Args:
            server: The server Block.
            name: Directive name to resolve (e.g., "ssl_stapling").

        Returns:
            The matching Directive, or None when not declared anywhere.
        """
        own = server.some(name)
        if own:
            return own
        for parent in server.parents:
            inherited = parent.some(name)
            if inherited:
                return inherited
        return None

    def _has_in_scope(self, server, name):
        """Return True when `name` is declared in this server or any ancestor.

        Args:
            server: The server Block to start from.
            name: Directive name to look for (e.g., "resolver").

        Returns:
            True if the directive exists in the server's scope or any
            enclosing scope (http, root, including transparent contexts
            like `include` blocks).
        """
        if server.some(name):
            return True
        for parent in server.parents:
            if parent.some(name):
                return True
        return False
