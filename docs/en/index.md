---
title: "Gixy: NGINX Security & Config Hardening Scanner"
description: "Open source NGINX analyzer that uncovers security flaws, hardening gaps, and performance gotchas before your config ships."
---

# Gixy: NGINX Security & Config Hardening Scanner

## Overview

<img width="192" height="192" alt="Gixy Mascot Logo" style="float: right;" src="../gixy.png">

Gixy is an open source NGINX analyzer that reviews your configuration for security risks, misconfigurations, and missed hardening opportunities—before they ever reach production.

You can use Gixy to run automated NGINX configuration security audits, and harden your nginx.conf against SSRF, HTTP response splitting, host header spoofing, version disclosure, and other vulnerabilities, as well as misconfigurations which lead to degraded performance and slow nginx servers.

## Why Gixy Matters for NGINX Security & Compliance

Unlike `nginx -t`, which only validates syntax, Gixy **analyzes** your configuration to surface unhardened areas, vulnerabilities, and performance pitfalls. Run it locally or in CI/CD on every change for automated NGINX security and compliance checks.

Currently supported Python versions are 3.6 through 3.13.

!!! warning "Platform Note"
    Gixy is well tested only on GNU/Linux and macOS; other operating systems may have some issues.

!!! tip "Harden NGINX with maintained RPMs"
    Use NGINX Extras by GetPageSpeed for continuously updated NGINX and modules on RHEL/CentOS/Alma/Rocky.
    [Learn more](https://nginx-extras.getpagespeed.com/).

## What Gixy Can Detect

Gixy can find various NGINX configuration security issues, as well as NGINX configuration performance issues, based on your `nginx.conf` and other NGINX configuration files. The following checks are available to detect these misconfigurations:

### Security Vulnerabilities

*   [Server Side Request Forgery (SSRF)](checks/ssrf.md)
*   [HTTP Response Splitting](checks/http-splitting.md)
*   [Request's Host Header Forgery](checks/host-spoofing.md)
*   [Problems with Referrer/Origin Validation](checks/origins.md)
*   [Path Traversal via Misconfigured Alias](checks/alias-traversal.md)
*   [Proxy Pass Path Normalization Issues](checks/proxy-pass-normalized.md)
*   [Regular Expression Denial of Service (ReDoS)](checks/regex-redos.md)

### Header & Response Security

*   [Redefining Response Headers by "add_header" Directive](checks/add-header-redefinition.md)
*   [Multiline Response Headers](checks/add-header-multiline.md)
*   [Setting Content-Type via add_header](checks/add-header-content-type.md)
*   [Missing or Weak HSTS Header](checks/hsts-header.md)

### SSL/TLS Security

*   [Weak SSL/TLS Configuration](checks/weak-ssl-tls.md)
*   [HTTP/2 Misdirected Request Safeguard](checks/http2-misdirected-request.md)
*   [OCSP Stapling Without Resolver](checks/ssl-stapling-without-resolver.md)

### Access Control & Validation

*   [none in valid_referers](checks/valid-referers.md)
*   [Allow Specified Without Deny](checks/allow-without-deny.md)
*   [Return Bypasses allow/deny](checks/return-bypasses-allow-deny.md)
*   [Status Page Exposed](checks/status-page-exposed.md)

### Configuration Best Practices

*   [If is Evil When Used in Location Context](checks/if-is-evil.md)
*   [Using Insecure Values for server_tokens](checks/version-disclosure.md)
*   [Using External DNS Nameservers](checks/resolver-external.md)
*   [Static DNS Resolution in proxy_pass](checks/missing-resolver.md)
*   [Missing default_server Flag](checks/default-server-flag.md)
*   [Error Log Disabled](checks/error-log-off.md)
*   [Hash Directive Without Default](checks/hash-without-default.md)

### Regex & Pattern Issues

*   [Regex Can Be Exact Match](checks/regex-exact-match.md)
*   [Unanchored Regex in Location](checks/unanchored-regex.md)
*   [Invalid Regex Capture Groups](checks/invalid-regex.md)

### Performance Checks

*   [try_files Without open_file_cache](checks/try-files-is-evil-too.md)
*   [Worker Connections vs rlimit](checks/worker-rlimit-nofile-vs-connections.md)
*   [Low keepalive_requests Value](checks/low-keepalive-requests.md)

Something not detected? Please open an issue on our [GitHub repository](https://github.com/dvershinin/gixy/issues?q=is%3Aissue+is%3Aopen+label%3A%22new+check%22) with the "new check" label.

## Installation

### CentOS/RHEL and other RPM-based Systems

```bash
yum -y install https://extras.getpagespeed.com/release-latest.rpm
yum -y install gixy

# Optional: add ReDoctor-backed deep ReDoS analysis
yum -y install gixy-deep
```

The base RPM includes Gixy's default fast ReDoS heuristics and does not require
ReDoctor. The signed [`gixy-deep` RPM](https://extras.getpagespeed.com/redhat/repoview/gixy-deep.html)
adds ReDoctor for `gixy --deep` without changing the base package dependency set.

### macOS / Linux (Homebrew)

```bash
brew install gixy
```

Bottles are pre-built for macOS (Apple Silicon + Intel) and Linux (`x86_64`, `arm64`).

### Alpine Linux

```bash
apk add gixy
```

Packaged as `gixy` in the `community` repository. Currently available on Alpine
**edge**; it landed after `v3.24` branched, so it will reach stable with the next
Alpine release. On a stable release, install from PyPI (below) until then.

### Arch Linux (AUR)

```bash
yay -S gixy-ng
```

Published as `gixy-ng` (the legacy `gixy` AUR slot is held by a different
maintainer at the old 0.1.20 release); it declares `provides=('gixy')` and
`conflicts=('gixy')`, so it's a drop-in replacement. Any AUR helper works
(`paru`, `yay`, manual `makepkg -si`).

### Other Systems (pip)

Gixy is distributed on [PyPI](https://pypi.python.org/pypi/gixy-ng). The best way to install it is with pip:

```bash
pip install gixy-ng
```

For optional ReDoctor-backed deep ReDoS analysis, install:

```bash
pip install 'gixy-ng[deep]'
```

Run Gixy and check results:

```bash
gixy
```

## Usage

By default, Gixy will try to analyze Nginx configuration placed in `/etc/nginx/nginx.conf`.

But you can always specify needed path:
```
$ gixy /etc/nginx/nginx.conf

==================== Results ===================

Problem: [http_splitting] Possible HTTP-Splitting vulnerability.
Description: Using variables that can contain "\n" may lead to http injection.
Additional info: https://github.com/dvershinin/gixy/blob/master/docs/en/checks/http-splitting.md
Reason: At least variable "$action" can contain "\n"
Pseudo config:
include /etc/nginx/sites/default.conf;

	server {

		location ~ /v1/((?<action>[^.]*)\.json)?$ {
			add_header X-Action $action;
		}
	}


==================== Summary ===================
Total issues:
    Unspecified: 0
    Low: 0
    Medium: 0
    High: 1
```

Or skip some checks:
```
$ gixy --skips http_splitting /etc/nginx/nginx.conf

==================== Results ===================
No issues found.

==================== Summary ===================
Total issues:
    Unspecified: 0
    Low: 0
    Medium: 0
    High: 0
```

Or something else, you can find all other `gixy` arguments with the help command: `gixy --help`

You can also make `gixy` use pipes (stdin), like so:

```bash
echo "resolver 1.1.1.1;" | gixy -
```

### Docker Usage

Gixy is available as a Docker image [from the Docker Hub](https://hub.docker.com/r/getpagespeed/gixy/). To use it, mount the configuration that you want to analyze as a volume and provide the path to the configuration file when running the Gixy image.
```
$ docker run --rm -v `pwd`/nginx.conf:/etc/nginx/conf/nginx.conf getpagespeed/gixy /etc/nginx/conf/nginx.conf
```

If you have an image that already contains your nginx configuration, you can share the configuration
with the Gixy container as a volume.
```
$  docker run --rm --name nginx -d -v /etc/nginx nginx:alpine
f68f2833e986ae69c0a5375f9980dc7a70684a6c233a9535c2a837189f14e905

$  docker run --rm --volumes-from nginx dvershinin/gixy /etc/nginx/nginx.conf

==================== Results ===================
No issues found.

==================== Summary ===================
Total issues:
    Unspecified: 0
    Low: 0
    Medium: 0
    High: 0

```

## Continuous Monitoring

Once Gixy is part of your CI pipeline, the next gap is production drift. Pair it with [GetPageSpeed Amplify](continuous-monitoring.md) for scheduled Gixy scans across every NGINX host plus runtime metrics and alerts. Amplify is drop-in compatible with the deprecated `nginx-amplify-agent`.

## Contributing

Contributions to Gixy are always welcome! You can help us in different ways:

- Open an issue with suggestions for improvements and errors you're facing in the [GitHub repository](https://github.com/dvershinin/gixy);
- Fork this repository and submit a pull request;
- Improve the documentation.

### Code Guidelines

- Python code style should follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) standards whenever possible;
- Pull requests with new checks must have unit tests for them.

### Community Guidelines

- Be respectful and constructive in discussions;
- This project uses AI-assisted development - disparaging remarks about AI tooling are unwelcome;
- Focus on the code and ideas, not the tools used to create them.
