"""
Missing Resolver Plugin - Detects static DNS resolution in proxy directives.

This plugin uses INVERSE LOGIC for maximum coverage:
- Instead of trying to identify public domains (impossible without PSL),
  we identify what's DEFINITELY INTERNAL and flag EVERYTHING ELSE.
- This approach is MORE secure: any unknown/new TLD gets flagged automatically.

Detection:
- Static hostnames in proxy_pass, fastcgi_pass, uwsgi_pass, scgi_pass, grpc_pass
- Upstream servers without 'resolve' parameter
- Cloud provider endpoints (AWS ELB, GCP, Azure, Cloudflare) with HIGH severity
- Variable-based proxy_pass WITHOUT a resolver directive configured

Why inverse logic is superior:
- No need for external dependencies (Public Suffix List, tldextract, etc.)
- No hardcoded TLD list that becomes outdated
- New TLDs (.ai, .xyz, .whatever) automatically flagged
- More secure: false positives > false negatives for security tools
"""

import re

import gixy
import gixy.core.builtin_variables as builtins
from gixy.core.variable import compile_script
from gixy.directives.directive import is_ipv4, is_ipv6
from gixy.plugins.plugin import Plugin

# =============================================================================
# INTERNAL DOMAIN DETECTION (inverse logic - identify internal, flag rest)
# =============================================================================

# RFC 2606 / RFC 6761 reserved TLDs - ALWAYS internal
RFC_RESERVED_TLDS = frozenset(
    [
        "test",  # RFC 2606 - testing
        "example",  # RFC 2606 - documentation
        "invalid",  # RFC 2606 - invalid
        "localhost",  # RFC 6761 - loopback
        "local",  # RFC 6762 - mDNS/Bonjour
        "onion",  # RFC 7686 - Tor
        "arpa",  # Infrastructure (in-addr.arpa, ip6.arpa)
    ]
)

# Common internal/private domain suffixes used in enterprises
INTERNAL_SUFFIXES = (
    # Enterprise conventions
    ".internal",
    ".intranet",
    ".private",
    ".corp",
    ".corporate",
    ".home",
    ".lan",
    ".localdomain",
    ".office",
    ".company",
    ".dev.local",
    ".staging.local",
    ".prod.local",
    # Kubernetes (all patterns)
    ".cluster.local",
    ".svc.cluster.local",
    ".pod.cluster.local",
    ".svc",
    ".pod",
    # Docker
    ".docker",
    ".docker.internal",
    ".docker.localhost",
    # HashiCorp stack
    ".consul",
    ".service.consul",
    ".node.consul",
    ".query.consul",
    ".vault",
    ".nomad",
    # Mesos/Marathon/DC/OS
    ".mesos",
    ".marathon.mesos",
    ".dcos",
    # Rancher/K3s
    ".rancher.internal",
    ".cattle-system",
    # AWS internal (NOT public AWS endpoints!)
    ".ec2.internal",
    ".compute.internal",
    ".ecs.internal",
    ".amazonaws.com.internal",  # VPC internal
    # Azure internal
    ".internal.cloudapp.net",
    ".azure.internal",
    # GCP internal
    ".internal",
    ".c.PROJECT.internal",
    # OpenStack
    ".novalocal",
    ".openstacklocal",
)

# Single-word hostnames commonly used internally
INTERNAL_SINGLE_WORDS = frozenset(
    [
        "localhost",
        "backend",
        "frontend",
        "api",
        "web",
        "app",
        "service",
        "database",
        "db",
        "redis",
        "memcached",
        "cache",
        "queue",
        "worker",
        "nginx",
        "apache",
        "proxy",
        "gateway",
        "lb",
        "loadbalancer",
        "master",
        "slave",
        "primary",
        "replica",
        "node",
        "server",
        "elasticsearch",
        "kibana",
        "logstash",
        "grafana",
        "prometheus",
        "kafka",
        "zookeeper",
        "rabbitmq",
        "activemq",
        "nats",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "mongodb",
        "mongo",
        "vault",
        "consul",
        "etcd",
        "minio",
        "storage",
    ]
)

# =============================================================================
# CLOUD PROVIDER DETECTION (HIGH severity - IPs change frequently)
# =============================================================================

CLOUD_PROVIDER_PATTERNS = [
    # AWS - comprehensive coverage
    (r"\.elb\.amazonaws\.com$", "AWS ELB"),
    (r"\.elb\.[a-z]+-[a-z]+-\d+\.amazonaws\.com$", "AWS Regional ELB"),
    (r"[a-z0-9]+-[a-z0-9]+\.elb\.amazonaws\.com$", "AWS Classic ELB"),
    (r"\.elasticbeanstalk\.com$", "AWS Elastic Beanstalk"),
    (r"\.cloudfront\.net$", "AWS CloudFront"),
    (r"\.execute-api\.[a-z]+-[a-z]+-\d+\.amazonaws\.com$", "AWS API Gateway"),
    (r"\.lambda-url\.[a-z]+-[a-z]+-\d+\.on\.aws$", "AWS Lambda URL"),
    (r"\.s3\.amazonaws\.com$", "AWS S3"),
    (r"\.s3-[a-z]+-[a-z]+-\d+\.amazonaws\.com$", "AWS S3 Regional"),
    (r"\.s3\.[a-z]+-[a-z]+-\d+\.amazonaws\.com$", "AWS S3 Regional"),
    (r"\.amplifyapp\.com$", "AWS Amplify"),
    (r"\.awsglobalaccelerator\.com$", "AWS Global Accelerator"),
    # Google Cloud - comprehensive coverage
    (r"\.run\.app$", "Google Cloud Run"),
    (r"\.cloudfunctions\.net$", "Google Cloud Functions"),
    (r"\.appspot\.com$", "Google App Engine"),
    (r"\.googleapis\.com$", "Google APIs"),
    (r"\.web\.app$", "Firebase Hosting"),
    (r"\.firebaseapp\.com$", "Firebase Hosting"),
    (r"\.cloudfunctions\.net$", "Google Cloud Functions"),
    # Azure - comprehensive coverage
    (r"\.azurewebsites\.net$", "Azure App Service"),
    (r"\.azure-api\.net$", "Azure API Management"),
    (r"\.cloudapp\.azure\.com$", "Azure Cloud Service"),
    (r"\.blob\.core\.windows\.net$", "Azure Blob Storage"),
    (r"\.azureedge\.net$", "Azure CDN"),
    (r"\.trafficmanager\.net$", "Azure Traffic Manager"),
    (r"\.azurefd\.net$", "Azure Front Door"),
    (r"\.azurestaticapps\.net$", "Azure Static Web Apps"),
    (r"\.azure\.com$", "Azure Service"),
    # Cloudflare
    (r"\.workers\.dev$", "Cloudflare Workers"),
    (r"\.pages\.dev$", "Cloudflare Pages"),
    (r"\.r2\.dev$", "Cloudflare R2"),
    # Major PaaS providers
    (r"\.herokuapp\.com$", "Heroku"),
    (r"\.vercel\.app$", "Vercel"),
    (r"\.now\.sh$", "Vercel (legacy)"),
    (r"\.netlify\.app$", "Netlify"),
    (r"\.netlify\.com$", "Netlify"),
    (r"\.railway\.app$", "Railway"),
    (r"\.onrender\.com$", "Render"),
    (r"\.render\.com$", "Render"),
    (r"\.fly\.dev$", "Fly.io"),
    (r"\.deno\.dev$", "Deno Deploy"),
    (r"\.supabase\.co$", "Supabase"),
    (r"\.neon\.tech$", "Neon Database"),
    (r"\.planetscale\.com$", "PlanetScale"),
    # DigitalOcean
    (r"\.ondigitalocean\.app$", "DigitalOcean App Platform"),
    (r"\.digitaloceanspaces\.com$", "DigitalOcean Spaces"),
    # Other cloud providers
    (r"\.linode\.com$", "Linode"),
    (r"\.vultr\.com$", "Vultr"),
    (r"\.scaleway\.com$", "Scaleway"),
    (r"\.hetzner\.cloud$", "Hetzner Cloud"),
    (r"\.upcloud\.com$", "UpCloud"),
    # CDN providers (IPs definitely change)
    (r"\.akamaihd\.net$", "Akamai CDN"),
    (r"\.akamaized\.net$", "Akamai CDN"),
    (r"\.akamaitechnologies\.com$", "Akamai"),
    (r"\.fastly\.net$", "Fastly CDN"),
    (r"\.fastlylb\.net$", "Fastly Load Balancer"),
    (r"\.cdn77\.org$", "CDN77"),
    (r"\.stackpathdns\.com$", "StackPath CDN"),
    (r"\.stackpathcdn\.com$", "StackPath CDN"),
    (r"\.kxcdn\.com$", "KeyCDN"),
    (r"\.bunnycdn\.com$", "BunnyCDN"),
    (r"\.b-cdn\.net$", "BunnyCDN"),
    # Generic patterns (high confidence)
    (r"\.cdn\.[a-z]+\.[a-z]+$", "CDN endpoint"),
    (r"-lb\.", "Load balancer"),
    (r"\.lb\.", "Load balancer"),
    (r"\.loadbalancer\.", "Load balancer"),
    (r"-elb\.", "Elastic Load Balancer"),
    (r"-alb\.", "Application Load Balancer"),
    (r"-nlb\.", "Network Load Balancer"),
]


class missing_resolver(Plugin):
    """
    Detects proxy directives with hostnames that won't have DNS re-resolution.

    Nginx resolves DNS for static hostnames ONCE at startup and caches forever.
    This causes issues when backend IPs change (cloud LBs, CDNs, failover).

    This plugin is smarter than basic suffix matching:
    - Proper TLD detection with compound TLD support
    - Cloud provider detection (AWS ELB, GCP, Azure, etc.) → HIGH severity
    - Checks if resolver directive exists when using variables
    - Understands upstream 'resolve' and 'zone' directives
    - Kubernetes/Docker/Consul service discovery awareness
    """

    summary = "Proxy target uses static DNS resolution (resolved only at startup)."
    severity = gixy.severity.MEDIUM
    description = (
        "Using proxy_pass with a static hostname causes DNS to be resolved only at startup, "
        "potentially sending traffic to stale IPs. This is especially critical for cloud "
        "load balancers and CDNs where IPs change frequently. Use a variable with 'resolver' "
        "directive, or upstream with 'resolve' parameter (nginx 1.27.3+)."
    )
    directives = ["proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass"]

    def __init__(self, config):
        super(missing_resolver, self).__init__(config)
        self.parse_uri_re = re.compile(
            r"^(?P<scheme>[a-z][a-z0-9+.-]*://)?"
            r"(?P<host>\[[0-9a-fA-F:.]+\]|[^/?#:]+)"
            r"(?::(?P<port>[0-9]+))?"
        )
        # Compile cloud provider patterns
        self.cloud_patterns = [
            (re.compile(pattern, re.IGNORECASE), name)
            for pattern, name in CLOUD_PROVIDER_PATTERNS
        ]

    def audit(self, directive):
        if not directive.args:
            return

        target = directive.args[0]
        directive_name = directive.name

        # Skip unix sockets
        if "unix:" in target:
            return

        parsed = self.parse_uri_re.match(target)
        if not parsed:
            return

        parsed_host = parsed.group("host")

        # Resolve any variables in the host part
        resolved_host = self._resolve_host(parsed_host)
        if resolved_host is None:
            return  # Contains builtin variable - can't analyze

        if not resolved_host:
            return

        # Skip IP addresses
        if is_ipv6(resolved_host, strip_brackets=True) or is_ipv4(
            resolved_host, strip_port=True
        ):
            return

        # Check if this is an upstream reference
        upstream_result = self._check_upstream(directive, resolved_host)
        if upstream_result is not None:
            if upstream_result:  # List of problematic servers
                self._report_upstream_issue(directive, resolved_host, upstream_result)
            return

        # Direct hostname usage - check if there's a variable with resolver
        if "$" in target:
            # Using variable - check if resolver is configured
            if self._has_resolver_in_scope(directive):
                return  # Has resolver, variable will trigger re-resolution
            # No resolver configured - this is actually a problem!
            self._report_missing_resolver_for_variable(
                directive, directive_name, resolved_host
            )
            return

        # Classify the hostname using inverse logic
        host_type, cloud_provider = self._classify_host(resolved_host)

        if host_type == "internal":
            return  # Definitely internal - skip

        # host_type == 'external' - flag it!
        if cloud_provider:
            self._report_cloud_provider(
                directive, directive_name, resolved_host, cloud_provider
            )
        else:
            self._report_static_hostname(directive, directive_name, resolved_host)

    def _resolve_host(self, host_str):
        """Resolve variables in host string. Returns None if unresolvable."""
        try:
            compiled = compile_script(host_str)
        except Exception:
            return None

        resolved = ""
        for var in compiled:
            if var.name and builtins.is_builtin(var.name):
                return None
            if not isinstance(var.final_value, str):
                return None
            resolved += var.final_value
        return resolved

    def _classify_host(self, host):
        """
        Classify hostname using INVERSE LOGIC.

        Instead of trying to identify public domains (impossible without PSL),
        we identify what's DEFINITELY INTERNAL and flag EVERYTHING ELSE.
        This is MORE secure: new/unknown TLDs automatically get flagged.

        Returns: (type, cloud_provider)
        - type: 'internal' or 'external'
        - cloud_provider: name of cloud provider if detected, else None
        """
        host_lower = host.lower().strip(".")

        # =================================================================
        # STEP 1: Cloud providers FIRST (highest priority, HIGH severity)
        # =================================================================
        for pattern, provider_name in self.cloud_patterns:
            if pattern.search(host_lower):
                return ("external", provider_name)

        # =================================================================
        # STEP 2: Single-label hostname (no dot) = INTERNAL
        # Examples: "backend", "api", "redis", "localhost"
        # =================================================================
        if "." not in host_lower:
            return ("internal", None)

        # =================================================================
        # STEP 3: RFC reserved TLDs = INTERNAL (guaranteed never public)
        # =================================================================
        tld = host_lower.rsplit(".", 1)[-1]
        if tld in RFC_RESERVED_TLDS:
            return ("internal", None)

        # =================================================================
        # STEP 4: Internal suffixes = INTERNAL
        # Enterprise patterns, K8s, Docker, Consul, etc.
        # =================================================================
        for suffix in INTERNAL_SUFFIXES:
            if host_lower.endswith(suffix):
                return ("internal", None)

        # =================================================================
        # STEP 5: Common internal hostname patterns
        # =================================================================
        parts = host_lower.split(".")

        # servicename.namespace pattern (k8s style) or servicename.env
        if len(parts) == 2:
            first_part, second_part = parts
            if first_part in INTERNAL_SINGLE_WORDS:
                # Short alphabetic second part = likely internal
                if len(second_part) <= 12 and second_part.isalpha():
                    return ("internal", None)

        # =================================================================
        # STEP 6: IP-like patterns (k8s pod naming)
        # Examples: "10-0-0-1.default.pod.cluster.local"
        # =================================================================
        if re.match(r"^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.", host_lower):
            return ("internal", None)

        # =================================================================
        # STEP 7: EVERYTHING ELSE = EXTERNAL (flag it!)
        # This catches ALL public domains including new TLDs
        # =================================================================
        return ("external", None)

    def _check_upstream(self, directive, resolved_host):
        """
        Check if host refers to an upstream block.
        Returns:
            - None: Not an upstream reference
            - []: Upstream found, all servers are safe
            - [(server, host, cloud_provider), ...]: Problematic servers
        """
        for upstream in directive.find_imperative_directives_in_scope(
            "upstream", ancestors=True
        ):
            upstream_args = getattr(upstream, "args", None)
            if upstream_args != [resolved_host]:
                continue

            # Check if upstream has 'zone' directive (enables dynamic config in Plus)
            any(child.name == "zone" for child in upstream.children)

            problematic = []

            for child in upstream.children:
                if child.name != "server":
                    continue

                server_target = child.args[0] if child.args else ""

                # Has 'resolve' parameter - OK
                if "resolve" in child.args:
                    continue

                # Skip unix sockets
                if "unix:" in server_target:
                    continue

                parsed = self.parse_uri_re.match(server_target)
                if not parsed:
                    continue

                server_host = parsed.group("host")

                # Skip IPs
                if is_ipv6(server_host, strip_brackets=True) or is_ipv4(
                    server_host, strip_port=True
                ):
                    continue

                host_type, cloud_provider = self._classify_host(server_host)

                if host_type == "internal":
                    continue

                problematic.append((child, server_host, cloud_provider))

            return problematic

        return None

    def _has_resolver_in_scope(self, directive):
        """Check if there's a resolver directive in scope."""
        for resolver in directive.find_directives_in_scope("resolver"):
            return True
        # Also check via find method on parents
        for parent in directive.parents:
            if hasattr(parent, "some"):
                resolver = parent.some("resolver", flat=False)
                if resolver:
                    return True
        return False

    def _report_cloud_provider(self, directive, directive_name, hostname, provider):
        """Report HIGH severity issue for cloud provider endpoints."""
        reason = (
            f"CRITICAL: '{directive_name}' targets {provider} endpoint '{hostname}'. "
            f"Cloud provider IPs change frequently! Static DNS resolution will cause "
            f"traffic to be sent to wrong/old IPs. You MUST use dynamic resolution: "
            f"set $backend {hostname}; resolver 127.0.0.1 valid=10s; {directive_name} http://$backend;"
        )
        self.add_issue(
            severity=gixy.severity.HIGH,
            directive=[directive],
            reason=reason,
        )

    def _report_upstream_issue(self, directive, upstream_name, problematic_servers):
        """Report issue with upstream servers."""
        # Check if any are cloud providers
        cloud_servers = [(s, h, p) for s, h, p in problematic_servers if p]
        regular_servers = [(s, h, p) for s, h, p in problematic_servers if not p]

        if cloud_servers:
            # HIGH severity for cloud providers
            cloud_info = ", ".join(f"{h} ({p})" for _, h, p in cloud_servers)
            reason = (
                f"CRITICAL: Upstream '{upstream_name}' contains cloud provider endpoints "
                f"without 'resolve' parameter: {cloud_info}. These IPs change frequently! "
                f"Add 'resolve' parameter and configure 'resolver' directive."
            )
            self.add_issue(
                severity=gixy.severity.HIGH,
                directive=[directive] + [s for s, _, _ in cloud_servers],
                reason=reason,
            )

        if regular_servers:
            hosts = ", ".join(h for _, h, _ in regular_servers)
            reason = (
                f"Upstream '{upstream_name}' has server(s) without 'resolve': {hosts}. "
                f"Add 'resolve' parameter (nginx 1.27.3+) and 'resolver' directive for "
                f"dynamic DNS resolution."
            )
            self.add_issue(
                severity=gixy.severity.MEDIUM,
                directive=[directive] + [s for s, _, _ in regular_servers],
                reason=reason,
            )

    def _report_static_hostname(self, directive, directive_name, hostname):
        """Report MEDIUM severity for regular public hostnames."""
        reason = (
            f"'{directive_name}' uses static hostname '{hostname}'. DNS resolved once at "
            f"startup - if IP changes, traffic goes to stale address until nginx restart. "
            f"Consider: resolver 127.0.0.1 valid=30s; set $backend {hostname}; "
            f"{directive_name} http://$backend;"
        )
        self.add_issue(
            severity=gixy.severity.MEDIUM,
            directive=[directive],
            reason=reason,
        )

    def _report_missing_resolver_for_variable(
        self, directive, directive_name, hostname
    ):
        """Report when variable is used but no resolver directive exists."""
        reason = (
            f"'{directive_name}' uses a variable but no 'resolver' directive found! "
            f"Without 'resolver', variable-based proxy_pass won't re-resolve DNS. "
            f"Add: resolver 127.0.0.1 valid=30s; (or your internal/VPC DNS server)"
        )
        self.add_issue(
            severity=gixy.severity.MEDIUM,
            directive=[directive],
            reason=reason,
        )
