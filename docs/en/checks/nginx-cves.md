---
title: "NGINX CVEs"
description: "Report CVEs that affect a specific installed NGINX version and configuration."
---

# NGINX CVEs

_Gixy Check ID: `nginx_cves`_


## Overview

The `nginx_cves` check mirrors the NGINX Open Source security advisory
database. Pass `--nginx-version=1.31.6` so gixy knows which NGINX binary
will load the config; without it, the check stays silent (gixy is a static config
analyzer and has no view of the binary).

The explicit `--nginx-version` also informs the QUIC BPF reload check. The
older `--nginx-cves-version` option remains a shared fallback when the global
option is absent. An invalid version remains unknown.

To opt into detecting the local binary once for all scanned files and checks,
use `--nginx-version=auto` or `nginx-version = auto` in Gixy's config. This runs
`nginx -V` from `PATH` with a five-second timeout and recognizes the advertised
version and bundled flavor. Opting in asserts that this binary is the target;
use an explicit version for offline or remote scans. Detection is disabled by
default and rejected in `--server` mode. Failures warn on stderr and keep the
version unknown, blocking the legacy fallback. No packages or feeds are queried.

Use `--nginx-flavor=nginx-mod` with an explicit version for an offline vendor
build, or `--nginx-flavor=upstream` to force upstream rules over detection.
Unknown vendor banners use upstream rules; invalid explicit flavor names fail.
Bundled flavor fixes apply only to exact CVE IDs at or after their recorded fix
version. All other affected ranges and configuration triggers still apply.
The initial `nginx-mod` data records only the QUIC reload fix at 1.30.6 and has
no CVE exemptions. The real advertised version is preserved. Identity and
`--debug` fix diagnostics go to stderr, keeping JSON stdout clean. See
[target version configuration](../configuration.md#target-nginx-version-and-flavor).

Pure binary-level CVEs are reported whenever the supplied version falls
in an affected range. CVEs tied to a module or configuration pattern are
reported only when both the version and trigger match. Those reports
attach to the offending directives so you can see where the exposure is
enabled.

## Usage

```
gixy --nginx-version=1.31.6 /etc/nginx/nginx.conf
```

If your binary is patched, the check
stays silent for any CVE that has been fixed in that release, even if
the config still contains the trigger pattern. Without `--nginx-version`,
the check is silent altogether — there is nothing safe to assert about
a version we don't know.

## Current database

As of November 2026, the database contains 73 of the 77 CVE IDs on the
[official NGINX Open Source security advisory page](https://nginx.org/en/security_advisories.html),
including fixed stable-branch version corrections. Four entries are intentionally
excluded: Windows-only CVE-2011-4963, CVE-2010-2266 and CVE-2010-2263, and
CVE-2009-4487 (log escaping, severity none, all versions, no fixed release).
These exclusions do not imply complete coverage of every NGINX-related product.

The November 2026 update adds ten CVEs. The configuration prerequisites
follow the individual [F5 CNA records](https://github.com/CVEProject/cvelistV5/tree/main/cves/2026);
OSS affected ranges follow the official advisory page.

| CVE | Configuration prerequisites checked |
| --- | --- |
| [CVE-2026-123634](https://www.cve.org/CVERecord?id=CVE-2026-123634) | Two proxy contexts in one HTTP server with the same variable-bearing hostname expression and effective resolver settings, plus effective SSI or mirror in the initiating context. Actual subrequest routing and hostname equality remain runtime prerequisites. |
| [CVE-2026-123007](https://www.cve.org/CVERecord?id=CVE-2026-123007) | HTTP/2 enabled for client connections. |
| [CVE-2026-121810](https://www.cve.org/CVERecord?id=CVE-2026-121810) | QUIC listener with effective HTTP/3 enabled. |
| [CVE-2026-123633](https://www.cve.org/CVERecord?id=CVE-2026-123633) | HTTP/2 client connections and a proxied backend in the same HTTP server. Runtime exhaustion of `worker_connections` cannot be established statically. |
| [CVE-2026-118899](https://www.cve.org/CVERecord?id=CVE-2026-118899) | HTTP `listen ... ssl` with effective `ssl_protocols` including `TLSv1.3`. |
| [CVE-2026-113425](https://www.cve.org/CVERecord?id=CVE-2026-113425) | An enabled mail proxy server. |
| [CVE-2026-120993](https://www.cve.org/CVERecord?id=CVE-2026-120993) | Stream TLS with a dynamically loaded certificate and stream proxying with effective `proxy_protocol v2` in the same server. |
| [CVE-2026-125283](https://www.cve.org/CVERecord?id=CVE-2026-125283) | Effective `alias` and `try_files` using a regex `map` variable and captures. Exact request-dependent capture combinations remain a runtime prerequisite. |
| [CVE-2026-120967](https://www.cve.org/CVERecord?id=CVE-2026-120967) | A non-default TLS stream virtual server with effective `ssl_verify_client on`. |
| [CVE-2026-123640](https://www.cve.org/CVERecord?id=CVE-2026-123640) | Effective stream `ssl_preread on`. |

Nine entries are fixed in OSS `1.30.7` and `1.31.9`.
CVE-2026-120993 affects only `1.31.4`–`1.31.8` and is fixed in `1.31.9`;
it has no affected stable branch.

HTTP, mail and stream settings stay in their own protocol contexts. Stream
checks inherit settings from the enclosing `stream` block and apply server
overrides without combining sibling servers. A stream default server is selected
per listener address and port, using explicit `default_server` or the first
server for that listener. Omitted directive values use documented NGINX defaults,
including `TLSv1.3` in the default `ssl_protocols` from OSS `1.23.4`; an
explicit `off` or nearer override is respected. Listener grouping uses literal
endpoints with numeric ports normalized to wildcard addresses; it does not
resolve DNS names or model every overlapping socket binding.

The September 2026 update includes CVE-2026-90439 in the HTTP/3 module,
fixed in Open Source `1.30.5` and `1.31.6`. The October release adds:

| CVE | Configuration prerequisites checked |
| --- | --- |
| [CVE-2026-15176](https://www.cve.org/CVERecord?id=CVE-2026-15176) | Effective `alias`, same/enclosing `rewrite`, and direct `$request_filename` or `${request_filename}` in applicable `set`/`return` expressions or an active access log's named `log_format`. |
| [CVE-2026-93479](https://www.cve.org/CVERecord?id=CVE-2026-93479) | Version-only advice; alternate non-cacheable-variable paths cannot be fully modeled from configuration. |
| [CVE-2026-95101](https://www.cve.org/CVERecord?id=CVE-2026-95101) | A QUIC listener with effective HTTP/3 enabled and `proxy_pass` with effective `proxy_request_buffering on` in the same HTTP server. |
| [CVE-2026-97629](https://www.cve.org/CVERecord?id=CVE-2026-97629) | A TLS HTTP server with effective `ssl_session_cache shared:...`, session tickets enabled and no explicit `ssl_session_ticket_key` files, allowing automatic ticket-key rotation. |
| [CVE-2026-97205](https://www.cve.org/CVERecord?id=CVE-2026-97205) | Effective `ssi on` and enabled AIO in the same applicable request context. |

All five October entries are fixed in NGINX Open Source `1.30.6` and `1.31.7`.
The trigger prerequisites follow the
[F5 CNA records](https://github.com/CVEProject/cvelistV5/tree/main/cves/2026);
historical OSS version bounds follow nginx.org, including `1.23.2` for
CVE-2026-97629. HTTP/server/location inheritance and nearer overrides are
considered without combining unrelated servers or sibling locations.

The July entries remain covered: CVE-2026-42533 (regex `map` captures and
volatile outputs), CVE-2026-60005 (unnamed captures with `slice` or background
cache updates), and CVE-2026-56434 (SSI with unbuffered proxied responses),
fixed in `1.30.4` and `1.31.3`.

## Examples

### Config-triggered CVE

```
location ~(.*) {
    slice 1m;
    proxy_set_header X-Capture $1;
    proxy_set_header Range $slice_range;
    proxy_pass http://backend;
}
```

```
$ gixy --nginx-version=1.31.2 nginx.conf
==>>> Issue: [MEDIUM] Known nginx CVE affects your installed version.
CVE-2026-60005: Uninitialized memory access in ngx_http_slice_module.
Your installed version is vulnerable and the trigger pattern is present
in this config. Fixed in: 1.30.4, 1.31.3.
```

### Patched binary

```
$ gixy --nginx-version=1.30.7 nginx.conf  # silent: current fixes are present
```

## Extending the database

Append a dict to `CVES` in `gixy/plugins/_nginx_cves_db.py`:

```python
{
    "id": "CVE-YYYY-NNNNN",
    "nickname": "Optional Nickname",
    "summary": "One-line issue description.",
    "severity": gixy.severity.HIGH,
    "advisory": "https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN",
    "vulnerable_oss": (((LOW_MAJOR, LOW_MINOR, LOW_PATCH),
                        (HIGH_MAJOR, HIGH_MINOR, HIGH_PATCH)),),
    "fixed_oss": ("X.Y.Z", "A.B.C"),
    "fixed_plus": ("R<N> P<M>",),
    "config_check": check_cve_YYYY_NNNNN,  # or None for binary-only CVEs
}
```

If the CVE has a config-trigger pattern, add a small generator
function `check_cve_YYYY_NNNNN(root)` next to it that yields
`(primary_directive, related_directive)` pairs for each match.

## Limitations

- **November prerequisites are not exploit proof.** The resolver check cannot
  prove request-time hostname equality or SSI page contents. Static regex/map
  capture checks cannot prove the precise capture sequence for a request.
  HTTP/2 connection pressure, crafted protocol traffic, TLS library support,
  ASLR bypass and actual stream backend routing are not established by these
  reports. Arbitrary variable indirection is not resolved.

- **OSS version matching.** The R-track patch model for NGINX Plus needs a
  per-track comparator; messages still mention Plus fix versions in
  plain text so Plus operators can apply them manually.
- **Direct sibling scope** for CVE-2026-42945's pattern check (matches
  the per-context script-engine compilation that produces the
  exploit). A `rewrite` inside an `if {}` block whose follow-up `set`
  lives outside that `if` is not flagged.
- **Prerequisites are not exploit proof.** CVE-2026-97205 also requires SSI
  page contents containing `include virtual` commands; gixy does not inspect
  those files. CVE-2026-93479 remains a version-based advisory, not proof of
  an exploitable configuration.
- **Direct filename references.** CVE-2026-15176 checks lexical variable
  references and active named log formats; arbitrary variable indirection
  and request-time control flow are not fully modeled.
- **Target identity.** Binary detection requires the explicit
  `--nginx-version=auto` opt-in. Otherwise supply the target version yourself;
  configuration alone cannot establish binary or vendor patch identity.

--8<-- "en/snippets/nginx-extras-cta.md"
