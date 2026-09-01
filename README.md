GIXY
====


[![Mozilla Public License 2.0](https://img.shields.io/badge/license-MPLv2.0-brightgreen?style=flat-square)](https://github.com/dvershinin/gixy/blob/master/LICENSE)
[![Python tests](https://github.com/dvershinin/gixy/actions/workflows/pythonpackage.yml/badge.svg)](https://github.com/dvershinin/gixy/actions/workflows/pythonpackage.yml)
[![Your feedback is greatly appreciated](https://img.shields.io/maintenance/yes/2026.svg?style=flat-square)](https://github.com/dvershinin/gixy/issues/new)
[![GitHub issues](https://img.shields.io/github/issues/dvershinin/gixy.svg?style=flat-square)](https://github.com/dvershinin/gixy/issues)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/dvershinin/gixy.svg?style=flat-square)](https://github.com/dvershinin/gixy/pulls)
[![NGINX Extras](https://img.shields.io/badge/NGINX%20Extras-Subscribe-blue?logo=nginx&style=flat-square)](https://nginx-extras.getpagespeed.com/)

> [!NOTE]
> Keep NGINX secure and up-to-date with maintained modules via [NGINX Extras RPM repository by GetPageSpeed](https://nginx-extras.getpagespeed.com/).

# Overview
<img align="right" width="192" height="192" src="docs/gixy.png">

Gixy is a tool to analyze NGINX configuration.
The main goal of Gixy is to prevent security misconfiguration and automate flaw detection.

Currently supported Python versions are 3.6 through 3.13.

Disclaimer: Gixy is well tested only on GNU/Linux, other OSs may have some issues.

# What it can do

Gixy detects a wide range of security issues across these categories:

| Category | Security Checks |
|----------|-----------------|
| 🔓 **Injection & Forgery** | [SSRF][ssrf] &#183; [HTTP Splitting][http_splitting] &#183; [Host Spoofing][host_spoofing] &#183; [Origin Bypass][origins] |
| 🚨 **Known CVEs** | [NGINX CVE Advisor][nginx_cves] (pass `--nginx-version=X.Y.Z`; mirrors the NGINX Open Source advisory database) |
| 🔐 **TLS & Encryption** | [Weak SSL/TLS][weak_ssl_tls] &#183; [Post-Quantum ssl_ecdh_curve][ssl_ecdh_curve] &#183; [HTTP/2 Misdirected Request][http2_misdirected_request] &#183; [QUIC BPF Reuseport][quic_bpf_reuseport] &#183; [OCSP Stapling Without Resolver][ssl_stapling_without_resolver] &#183; [Stapling With Let's Encrypt][ssl_stapling_letsencrypt] &#183; [Version Disclosure][version_disclosure] |
| 📂 **Path Traversal** | [Alias Traversal][alias_traversal] &#183; [Proxy Pass Normalized][proxy_pass_normalized] |
| 📋 **Header Security** | [HSTS Header][hsts_header] &#183; [Header Redefinition][add_header_redefinition] &#183; [Multiline Headers][add_header_multiline] &#183; [Content-Type via add_header][add_header_content_type] |
| 🚦 **Access Control** | [Allow Without Deny][allow_without_deny] &#183; [Return Bypasses ACL][return_bypasses_allow_deny] &#183; [Valid Referers][valid_referers] &#183; [Status Page Exposed][status_page_exposed] |
| 🌐 **DNS & Resolver** | [External Resolver][resolver_external] &#183; [Missing Resolver][missing_resolver] |
| ⚙️ **Config & Performance** | [ReDoS][regex_redos] &#183; [Regex Exact Match][regex_exact_match] &#183; [Unanchored Regex][unanchored_regex] &#183; [Invalid Regex][invalid_regex] &#183; [If Is Evil][if_is_evil] &#183; [Try Files Evil][try_files_is_evil_too] &#183; [Default Server][default_server_flag] &#183; [Hash Default][hash_without_default] &#183; [Error Log Off][error_log_off] &#183; [Worker Limits][worker_rlimit_nofile_vs_connections] &#183; [Low Keepalive][low_keepalive_requests] |

[📖 **Full documentation →**](https://gixy.getpagespeed.com/plugins/) &#183; [🆕 Upcoming checks](https://github.com/dvershinin/gixy/issues?q=is%3Aissue+is%3Aopen+label%3A%22new+plugin%22)

<!-- Plugin reference links -->
[ssrf]: https://gixy.getpagespeed.com/plugins/ssrf/
[http_splitting]: https://gixy.getpagespeed.com/plugins/httpsplitting/
[host_spoofing]: https://gixy.getpagespeed.com/plugins/hostspoofing/
[origins]: https://gixy.getpagespeed.com/plugins/origins/
[weak_ssl_tls]: https://gixy.getpagespeed.com/plugins/weak_ssl_tls/
[http2_misdirected_request]: https://gixy.getpagespeed.com/plugins/http2_misdirected_request/
[quic_bpf_reuseport]: https://gixy.getpagespeed.com/plugins/quic_bpf_reuseport/
[ssl_stapling_without_resolver]: https://gixy.getpagespeed.com/checks/ssl-stapling-without-resolver/
[ssl_stapling_letsencrypt]: https://gixy.getpagespeed.com/checks/ssl-stapling-letsencrypt/
[ssl_ecdh_curve]: https://gixy.getpagespeed.com/checks/ssl-ecdh-curve/
[nginx_cves]: https://gixy.getpagespeed.com/checks/nginx-cves/
[hsts_header]: https://gixy.getpagespeed.com/plugins/hsts_header/
[version_disclosure]: https://gixy.getpagespeed.com/plugins/version_disclosure/
[alias_traversal]: https://gixy.getpagespeed.com/plugins/aliastraversal/
[proxy_pass_normalized]: https://gixy.getpagespeed.com/plugins/proxy_pass_normalized/
[add_header_redefinition]: https://gixy.getpagespeed.com/plugins/addheaderredefinition/
[add_header_multiline]: https://gixy.getpagespeed.com/plugins/addheadermultiline/
[add_header_content_type]: https://gixy.getpagespeed.com/plugins/add_header_content_type/
[allow_without_deny]: https://gixy.getpagespeed.com/plugins/allow_without_deny/
[return_bypasses_allow_deny]: https://gixy.getpagespeed.com/plugins/return_bypasses_allow_deny/
[valid_referers]: https://gixy.getpagespeed.com/plugins/validreferers/
[status_page_exposed]: https://gixy.getpagespeed.com/plugins/status_page_exposed/
[resolver_external]: https://gixy.getpagespeed.com/plugins/resolver_external/
[missing_resolver]: https://gixy.getpagespeed.com/plugins/missing_resolver/
[regex_redos]: https://gixy.getpagespeed.com/plugins/regex_redos/
[regex_exact_match]: https://gixy.getpagespeed.com/checks/regex-exact-match/
[unanchored_regex]: https://gixy.getpagespeed.com/plugins/unanchored_regex/
[invalid_regex]: https://gixy.getpagespeed.com/plugins/invalid_regex/
[if_is_evil]: https://gixy.getpagespeed.com/plugins/if_is_evil/
[try_files_is_evil_too]: https://gixy.getpagespeed.com/plugins/try_files_is_evil_too/
[default_server_flag]: https://gixy.getpagespeed.com/plugins/default_server_flag/
[hash_without_default]: https://gixy.getpagespeed.com/plugins/hash_without_default/
[error_log_off]: https://gixy.getpagespeed.com/plugins/error_log_off/
[worker_rlimit_nofile_vs_connections]: https://gixy.getpagespeed.com/plugins/worker_rlimit_nofile_vs_connections/
[low_keepalive_requests]: https://gixy.getpagespeed.com/plugins/low_keepalive_requests/

# Installation

## CentOS/RHEL and other RPM-based systems

```bash
yum -y install https://extras.getpagespeed.com/release-latest.rpm
yum -y install gixy

# Optional: add ReDoctor-backed deep ReDoS analysis
yum -y install gixy-deep
```

The base RPM contains Gixy's default fast ReDoS heuristics and does not require
ReDoctor. The signed [`gixy-deep` RPM](https://extras.getpagespeed.com/redhat/repoview/gixy-deep.html)
adds ReDoctor for `gixy --deep` without changing the base package dependency set.

## macOS / Linux (Homebrew)

```bash
brew install gixy
```

Bottles are pre-built for macOS (Apple Silicon + Intel) and Linux (`x86_64`, `arm64`).

## Alpine Linux

```bash
apk add gixy
```

Packaged as `gixy` in the `community` repository. Currently available on Alpine
**edge**; it landed after `v3.24` branched, so it will reach stable with the next
Alpine release. On a stable release, install from PyPI (below) until then.

## Arch Linux (AUR)

```bash
yay -S gixy-ng
```

Published as `gixy-ng` (the legacy `gixy` AUR slot is held by a different
maintainer at the old 0.1.20 release); it declares `provides=('gixy')` and
`conflicts=('gixy')`, so it's a drop-in replacement. Any AUR helper works
(`paru`, `yay`, manual `makepkg -si`).

## Other systems

Gixy is distributed on [PyPI](https://pypi.python.org/pypi/gixy-ng). The best way to install it is with pip:

```bash
pip install gixy-ng
```

The base package includes Gixy's fast ReDoS heuristics. Install the optional
ReDoctor integration only when you need `--deep` analysis:

```bash
pip install 'gixy-ng[deep]'
```

# Usage

By default, Gixy will try to analyze NGINX configuration placed in `/etc/nginx/nginx.conf`.

But you can always specify the needed path:
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

Or skip some tests:
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

### Auto-fix mode 🔧

Gixy can automatically fix many issues it detects:

```bash
# Preview what fixes would be applied (dry run)
$ gixy --fix-dry-run /etc/nginx/nginx.conf

🔍 Dry run - showing fixes that would be applied:

📝 /etc/nginx/nginx.conf
   [Insecure TLS protocols enabled]
   🔧 Use only TLSv1.2 and TLSv1.3
   - ssl_protocols TLSv1 TLSv1.1
   + ssl_protocols TLSv1.2 TLSv1.3

📊 1 fix(es) available to apply.
   Run with --fix to apply them.
```

```bash
# Apply fixes (creates .bak backup files)
$ gixy --fix /etc/nginx/nginx.conf

✅ Applied 1 fix(es) to /etc/nginx/nginx.conf

🎉 Applied 1 fix(es) successfully!
   Backup files created with .bak extension.
```

Use `--no-backup` to skip creating backup files.

Or something else, you can find all other `gixy` arguments with the help command: `gixy --help`

With the optional ReDoctor dependency installed through `gixy-ng[deep]` (pip)
or `gixy-deep` (RPM), use `gixy --deep nginx.conf` for a more precise ReDoS
pass. Deep mode delegates to [ReDoctor](https://redoctor.getpagespeed.com/),
combining automata analysis with bounded fuzzing in a safe custom regex VM.
Analysis stays local, and Gixy disables ReDoctor's runtime recall step so nginx
regexes are never executed by Python's backtracking engine.

### Plugin options

Some plugins expose options which you can set via CLI flags or config file. CLI flags follow the pattern `--<PluginName>-<option>` with dashes, while config file uses `[PluginName]` sections with dashed keys.

- `origins`:
  - `--origins-domains domains`: Comma-separated list of trusted registrable domains. Use `*` to disable third‑party checks. Example: `--origins-domains example.com,foo.bar`. Default: `*`.
  - `--origins-https-only true|false`: When true, only the `https` scheme is considered valid for `Origin`/`Referer`. Default: `false`.
  - `--origins-lower-hostname true|false`: Normalize hostnames to lowercase before validation. Default: `true`.

- `add_header_redefinition`:
  - `--add-header-redefinition-headers headers`: Comma-separated allowlist of header names (case-insensitive). When set, only dropped headers from this list will be reported; when unset, all dropped headers are reported. Example: `--add-header-redefinition-headers x-frame-options,content-security-policy`. Default: unset (report all).

- `regex_redos`:
  - `--regex-redos-deep true|false`: Enable the same ReDoctor analysis as top-level `--deep`. Requires `gixy-ng[deep]` from pip or the `gixy-deep` RPM. Default: `false`.

Examples (config file):
```
[origins]
domains = example.com, example.org
https-only = true

[add_header_redefinition]
headers = x-frame-options, content-security-policy
```

You can also make `gixy` use pipes (stdin), like so:

```bash
echo "resolver 1.1.1.1;" | gixy -
```

## Docker usage
Gixy is available as a Docker image [from the Docker hub](https://hub.docker.com/r/getpagespeed/gixy/). To
use it, mount the configuration that you want to analyse as a volume and provide the path to the
configuration file when running the Gixy image.
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

## JetBrains IDEs (IntelliJ, PyCharm, WebStorm, GoLand, …)

[![JetBrains Plugin](https://img.shields.io/jetbrains/plugin/v/30510-gixy?label=JetBrains%20Marketplace&logo=jetbrains&style=flat-square)](https://plugins.jetbrains.com/plugin/30510-gixy)

Real-time NGINX security analysis in any JetBrains IDE. No Python required — the plugin auto-downloads a native Gixy binary.

**[Install from JetBrains Marketplace](https://plugins.jetbrains.com/plugin/30510-gixy)**

Or search for **"Gixy"** in your IDE's plugin settings (*Settings → Plugins → Marketplace*).

See [gixy-jetbrains](https://github.com/GetPageSpeed/gixy-jetbrains) for full documentation.

## VS Code / Cursor Extension

[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/getpagespeed.gixy?label=VS%20Code%20Marketplace&logo=visualstudiocode&style=flat-square)](https://marketplace.visualstudio.com/items?itemName=getpagespeed.gixy)

Get real-time NGINX security analysis directly in your editor!

**[Install from VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=getpagespeed.gixy)**

Or via command line:

```bash
code --install-extension getpagespeed.gixy
```

See [vscode-gixy](https://github.com/dvershinin/vscode-gixy) for full documentation.

## Kubernetes usage
Given you are using the official NGINX ingress controller, not the kubernetes one, you can use this
https://github.com/nginx/kubernetes-ingress

```
kubectl exec -it my-release-nginx-ingress-controller-54d96cb5cd-pvhx5 -- /bin/bash -c "cat /etc/nginx/conf.d/*" | docker run -i getpagespeed/gixy -
```

```
==================== Results ===================

>> Problem: [version_disclosure] Do not enable server_tokens on or server_tokens build
Severity: HIGH
Description: Using server_tokens on; or server_tokens build;  allows an attacker to learn the version of NGINX you are running, which can be used to exploit known vulnerabilities.
Additional info: https://gixy.getpagespeed.com/en/plugins/version_disclosure/
Reason: Using server_tokens value which promotes information disclosure
Pseudo config:

server {
	server_name XXXXX.dev;
	server_tokens on;
}

server {
	server_name XXXXX.dev;
	server_tokens on;
}

server {
	server_name XXXXX.dev;
	server_tokens on;
}

server {
	server_name XXXXX.dev;
	server_tokens on;
}

==================== Summary ===================
Total issues:
    Unspecified: 0
    Low: 0
    Medium: 0
    High: 4

```

# Continuous Monitoring

Pair Gixy with **GetPageSpeed Amplify** for continuous, scheduled Gixy scans plus full NGINX monitoring. Amplify is drop-in compatible with the deprecated `nginx-amplify-agent`, so existing hosts can be migrated with an `api_url` swap.

* Scheduled Gixy security scans across every monitored host, surfaced in one dashboard.
* NGINX runtime metrics, alerts, and historical trends alongside the Gixy report.

Migration guide and screenshots: <https://gixy.org/guides/nginx-monitoring-amplify>.

# Contributing
Contributions to Gixy are always welcome! You can help us in different ways:
  * Open an issue with suggestions for improvements and errors you're facing;
  * Fork this repository and submit a pull request;
  * Improve the documentation.

Code guidelines:
  * Python code style should follow [pep8](https://www.python.org/dev/peps/pep-0008/) standards whenever possible;
  * Pull requests with new plugins must have unit tests for them.

Community guidelines:
  * Be respectful and constructive in discussions;
  * This project uses AI-assisted development - disparaging remarks about AI tooling are unwelcome;
  * Focus on the code and ideas, not the tools used to create them.
