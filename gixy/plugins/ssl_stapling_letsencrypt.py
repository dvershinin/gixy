"""Plugin to detect OCSP stapling configured for a Let's Encrypt certificate.

Let's Encrypt stopped including OCSP URLs in its certificates in early 2025 and
shut its OCSP responders down on 2025-08-06. `ssl_stapling on` for an LE
certificate therefore staples nothing: nginx has no responder URL to query, and
the directives are dead config that only costs a startup warning and confusion.
"""

import gixy
from gixy.plugins.plugin import Plugin

# Default certbot layout. Anything below this prefix is assumed to be an ACME
# certificate issued by Let's Encrypt.
LETSENCRYPT_PREFIX = "/etc/letsencrypt/"

CERT_DIRECTIVES = ("ssl_certificate", "ssl_trusted_certificate")


class ssl_stapling_letsencrypt(Plugin):
    """Detect `ssl_stapling on` paired with a Let's Encrypt certificate path."""

    summary = "OCSP stapling is enabled for a Let's Encrypt certificate, which no longer has a responder"
    severity = gixy.severity.LOW
    description = (
        "Let's Encrypt stopped putting OCSP URLs in its certificates in early 2025 "
        "and turned its OCSP responders off on 2025-08-06. With no responder URL in "
        "the certificate, nginx has nothing to fetch and `ssl_stapling on` staples "
        "nothing — the directives are dead config. Revocation for Let's Encrypt is "
        "handled through short certificate lifetimes and CRLs instead. Remove "
        "`ssl_stapling`, `ssl_stapling_verify` and any `ssl_trusted_certificate` "
        "that exists only to serve stapling. Keep stapling for commercial CAs that "
        "still run OCSP responders."
    )
    directives = ["server"]

    def audit(self, server):
        """Report SSL servers stapling a certificate that appears to be from Let's Encrypt.

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

        le_paths = self._letsencrypt_paths(server)
        if not le_paths:
            return

        self.add_issue(
            directive=[stapling, server],
            reason=(
                "Certificate path {paths} appears to be a Let's Encrypt certificate. "
                "Let's Encrypt retired its OCSP responders on 2025-08-06 and no "
                "longer publishes an OCSP URL in its certificates, so `ssl_stapling "
                "on` here is a silent no-op.".format(paths=", ".join(le_paths))
            ),
            fixes=[
                self.make_fix(
                    title="Disable OCSP stapling for this Let's Encrypt certificate",
                    search="ssl_stapling on",
                    replace="ssl_stapling off",
                    description=(
                        "Let's Encrypt has no OCSP responder to staple from; the "
                        "directive only adds startup noise."
                    ),
                ),
            ],
        )

    def _is_ssl_server(self, server):
        """Return True if any listen directive enables SSL/QUIC/HTTP3.

        Args:
            server: The server Block to inspect.

        Returns:
            True when at least one `listen` carries `ssl`, `quic`, or `http3`.
        """
        for listen in server.find("listen"):
            if any(arg.lower() in ("ssl", "quic", "http3") for arg in listen.args):
                return True
        return False

    def _effective_directive(self, server, name):
        """Find the directive that effectively applies at this server's scope.

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

    def _letsencrypt_paths(self, server):
        """Collect certificate paths under the Let's Encrypt directory.

        Looks at the server's own certificate directives and at any inherited
        from an enclosing scope.

        Args:
            server: The server Block to inspect.

        Returns:
            A list of matching path arguments, in the order found.
        """
        scopes = [server]
        scopes.extend(server.parents)

        paths = []
        for scope in scopes:
            for name in CERT_DIRECTIVES:
                for directive in scope.find(name):
                    for arg in directive.args:
                        if arg.startswith(LETSENCRYPT_PREFIX) and arg not in paths:
                            paths.append(arg)
        return paths
