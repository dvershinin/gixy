# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Circular `include` directives no longer crash the parser**: nginx configs that contained a cycle (e.g. a file in `/etc/nginx/conf.d/` whose body says `include /etc/nginx/conf.d/*.conf;` — the glob matches the including file itself, or A→B→A across files) sent `gixy/parser/nginx_parser.py` into unbounded recursion. On environments with enough stack budget that surfaced as `RecursionError: maximum recursion depth exceeded` ([#113](https://github.com/dvershinin/gixy/issues/113)); on others the cycle silently inflated the parsed tree with hundreds of duplicated directives. `NginxParser` now tracks the canonical path of every file currently being parsed and skips any include that re-enters one already on the stack, emitting a single `Skipping circular include: …` WARNING per cycle. Applies to both filesystem includes and `nginx -T` dump-mode includes.

## [0.2.47] - 2026-05-23

### Added
- **`nginx_cves`**: New entry **CVE-2026-9256** — heap memory buffer overflow in `ngx_http_rewrite_module` triggered by a configuration with overlapping captures, potentially resulting in arbitrary code execution in a worker process. Affects nginx OSS `0.1.17`..`1.31.0`. Mitigation: upgrade to **1.31.1** (mainline) or **1.30.2** (stable). The check fires purely on `--nginx-version=` match — `--nginx-version=1.31.0` (previously considered patched) now reports this CVE. Advisory: <https://nvd.nist.gov/vuln/detail/CVE-2026-9256>, nginx CHANGES-1.30: <https://nginx.org/en/CHANGES-1.30>. Credit: Mufeed VH of Winfunc Research.

## [0.2.46] - 2026-05-21

### Fixed
- **`origins` false positive on host regexes anchored with `($|/)`**: A regex like `^https?://example\.com($|/)(?P<path>.*)` was reported as matching the bypass `http://example.com$aaaaa.evil.com`, even though that string does not actually match — the `$` in `($|/)` is the end-of-string anchor, not a literal `$`. Root cause was in `gixy/core/regexp.py`: `AtToken.generate()` emitted the raw `^` / `$` characters, and when an end anchor lived inside an alternation whose group had sibling tokens (e.g. the trailing `(?P<path>.*)`), `_gen_combinator` happily produced candidates with `$` stranded mid-string. The `origins` plugin then mutated these impossible-match candidates into bogus bypass URLs. Switched anchors to sentinel characters during generation; candidates with interior anchors are dropped at the top-level yielder before any plugin sees them. Semantically-equivalent regex rewrites now produce identical candidate sets ([#111](https://github.com/dvershinin/gixy/issues/111)).

## [0.2.45] - 2026-05-20

### Fixed
- **Named regex capture groups in `if` blocks**: `gixy` no longer logs a spurious `Can't find variable 'name'` INFO for configs like `if ($http_referer ~ "^https?://example\.com(?P<path>.*)") { set $x $path; }`. Server-scope prepopulate was descending into `IfBlock` to evaluate inner `set` directives before the if's regex capture groups had been registered; the block's own `provide_variables` are now registered before recursion ([#111](https://github.com/dvershinin/gixy/issues/111)).
- **Crash on Python 3.11+ for regexes generating invalid DNS labels**: `gixy/plugins/origins.py` called `candidate_match.encode("idna")` without protection. Python ≥ 3.11 idna codec rejects strings with empty or over-long labels (e.g. a regex containing `\.\.` or a 64+ char run), aborting the entire audit with `UnicodeError: label empty or too long`. The call is now guarded; on failure the raw candidate is used and downstream `parse_url` decides ([#111](https://github.com/dvershinin/gixy/issues/111)).

## [0.2.44] - 2026-05-17

### Fixed
- **Builtin variable table refresh**: Recognize 13 nginx variables that were missing from `gixy/core/builtin_variables.py`, eliminating spurious `[variable] INFO Can't find variable …` log lines. Added: `$http3` (`ngx_http_v3_module`, [#110](https://github.com/dvershinin/gixy/issues/110)), `$proxy_protocol_addr` and `$realip_remote_addr` (previously their doc comments were present but the keys were missing), `$proxy_protocol_server_addr`, `$proxy_protocol_server_port`, `$proxy_protocol_tlv_*` (PROXY protocol v2), `$sent_trailer_*`, `$upstream_trailer_*`, `$connection_time`, `$request_port`, `$is_request_port`, `$limit_conn_status`, `$limit_req_status`. List derived by diffing every `ngx_(http|stream)_variable_t` array in nginx 1.29.5 source against the existing builtin table, excluding entries flagged `NGX_HTTP_VAR_NOHASH` (internal-only, unreachable from configs).

## [0.2.43] - 2026-05-16

### Added
- **New check: `ssl_stapling_without_resolver`**: Flags SSL servers where `ssl_stapling on` is effective (either declared directly or inherited from `http`) but no `resolver` directive is reachable in scope. Without a resolver nginx cannot fetch the OCSP response and stapling silently fails — clients fall back to making their own OCSP queries, adding handshake latency and defeating the point of stapling. The check skips non-SSL servers, servers that override with `ssl_stapling off`, and any configuration where a `resolver` is visible in the server or an enclosing scope.
- **`nginx_cves` database expansion**: The CVE advisor now ships every nginx Open Source CVE listed on [nginx.org/en/security_advisories.html](https://nginx.org/en/security_advisories.html) — 50 entries spanning 2009 through 2026, up from a single entry in `0.2.42`. Config-pattern triggers cover the mp4, HTTP/2, HTTP/3/QUIC, resolver, SSL session reuse, dav, scgi/uwsgi, charset, mail, stream-OCSP, SPDY, and SSL/TLS directives; pure binary-level bugs (e.g. CVE-2013-2028 chunked parser, CVE-2009-2629 URI buffer underflow) fire from the version match alone. The CVE table lives in `gixy/plugins/_nginx_cves_db.py` and is automatically post-processed at import time to remove per-branch post-fix tails — users on patched stable branches (e.g. `1.26.3` with CVE-2025-23419, `1.22.1` with CVE-2022-41741, `1.16.1` with CVE-2019-9511) are no longer flagged for CVEs their version actually patches.

### Changed
- **`nginx_cves` gating semantics**: A CVE with a config-pattern trigger now fires *only* when the trigger is present. Previously the check would still emit a version-only issue when the binary fell in the affected range, even if the offending directive (e.g. `mp4`, `resolver`) wasn't configured. The narrower behaviour matches what users actually need to act on — if you never load the mp4 module, an mp4-module CVE is not exploitable on your server. Pure binary-level CVEs (no config trigger) continue to fire whenever the version matches.

### Fixed
- **Variable scope tracking**: Recognize `set`-like directives (`set`, `auth_request_set`, `perl_set`, `set_by_lua`, `root`) across block scopes regardless of source order. Variables defined later in a `server {}` (or any parent) block are now visible to nested `location {}` blocks that reference them, matching nginx's parse-time variable registration. Eliminates false `Can't find variable` INFO logs ([#100](https://github.com/dvershinin/gixy/issues/100)).

## [0.2.42] - 2026-05-15

### Added
- **New check: `nginx_cves`**: Unified nginx CVE advisor. Pass `--nginx-version=X.Y.Z` to enable the check; every CVE whose affected range covers your installed version is reported with the upgrade target. CVEs that also have a config-trigger pattern enrich the report with the offending directives. Without `--nginx-version`, the check stays silent (gixy is config-static and has no view of the binary). First database entry: **CVE-2026-42945 ("NGINX Rift")** — heap overflow in `ngx_http_rewrite_module` triggered by an unnamed PCRE backreference + `?` in a `rewrite` replacement followed by another `rewrite`, `if`, or `set` in the same context. Affects nginx OSS `0.6.27`..`1.30.0`; mitigation: switch to named captures (`(?<name>...)` with `${name}`), or upgrade to 1.30.1 / 1.31.0 / Plus R32 P6 / R36 P4.

## [0.2.41] - 2026-04-11

### Added
- **New check: `regex_exact_match`**: Detects regex locations like `location ~ ^/path$` that can be replaced with exact-match `location = /path` for better performance. Includes quick-fix support for IDE integrations.

## [0.2.40] - 2026-03-18

### Fixed
- **`weak_ssl_tls`**: Suppress `ssl_prefer_server_ciphers on` warning when `ssl_conf_command Options PrioritizeChaCha` is configured — OpenSSL's `SSL_OP_PRIORITIZE_CHACHA` already addresses the underlying concern ([#107](https://github.com/dvershinin/gixy/issues/107)).

## [0.2.39] - 2026-03-17

### Fixed
- **`quic_bpf_reuseport`**: Detect `quic_bpf` directive in the main context (top level) where NGINX docs place it, not only inside `events {}` ([#104](https://github.com/dvershinin/gixy/issues/104)).

## [0.2.38] - 2026-03-17

### Fixed
- **`quic_bpf_reuseport`**: Improved fix description to mention [nginx-mod](https://www.getpagespeed.com/nginx-mod-a-better-faster-nginx-build) as an alternative to disabling `quic_bpf`.

## [0.2.37] - 2026-03-17

### Added
- **New check: `quic_bpf_reuseport`**: Detects dangerous combination of `quic_bpf on` + `reuseport` on QUIC listeners + multiple workers that silently drops ~50% of QUIC connections after `nginx -s reload` ([#104](https://github.com/dvershinin/gixy/issues/104), [nginx/nginx#425](https://github.com/nginx/nginx/issues/425)).

## [0.2.34] - 2026-02-12

### Fixed
- **Documentation**: Fixed malformed Docker command in README and documentation (missing space before `nginx:alpine`).
- **Documentation**: Updated outdated `/plugins/` paths to `/checks/` with kebab-case naming across all README and doc index files.
- **Documentation**: Added missing `status_page_exposed` check to the Access Control section in English documentation index.
- **CI/CD**: Changed PyPI publish workflow trigger from `release: created` to `release: published` for consistency with Docker publish workflow.
- **Code**: Fixed double period typo in `gixy/core/variable.py` docstring.

## [0.2.33] - 2026-02-09

### Fixed
- **`status_page_exposed` false positive**: Servers listening only on Unix sockets (e.g. `listen unix:/run/nginx/status.sock`) no longer trigger the missing IP restrictions warning, since Unix domain sockets are inherently inaccessible from the network (#101).

## [0.2.32] - 2026-02-07

### Fixed
- **HSTS false positive**: `security_headers on;` (ngx_security_headers module) is now recognized as providing HSTS — no longer flags "Missing HSTS header".
- **HSTS false positive**: `more_set_headers` setting `Strict-Transport-Security` is now recognized as providing HSTS.
- **`ssl_prefer_server_ciphers` false positive**: Inverted the check — `on` is now flagged (LOW) instead of `off` (MEDIUM). All authoritative sources (Mozilla, nginx maintainers) recommend `off` for modern cipher lists.

## [0.2.29] - 2026-01-30

### Changed
- **Parser**: Use `parse_string()` API directly instead of temporary file workaround, now that ngxparse supports it.

## [0.2.28] - 2026-01-30

### Changed
- **Dependency**: Switched from `crossplane` to `ngxparse` for NGINX config parsing. ngxparse is a maintained fork with bug fixes and the same API.

### Fixed
- **Parser**: Fixed tokenization of adjacent braced variables like `${var1}${var2}` in map directives (ngxparse 0.5.16).

## [0.2.25] - 2025-12-28

### Changed
- **Terminology**: User-facing documentation now uses "checks" instead of "plugins" for clarity and consistency.
- **CLI**: `--checks` is now the primary flag for selecting checks to run (`--tests` remains as a backward-compatible alias).
- **Configuration**: Config files now prefer `checks = ...` over `tests = ...` (both still work for backward compatibility).
- **Help URLs**: Plugin help URLs are now auto-generated from class names using kebab-case slugs (e.g., `http_splitting` → `/checks/http-splitting/`).
- **Documentation URLs**: All check documentation moved from `/plugins/` to `/checks/` path with kebab-case naming.

### Fixed
- **Pre-commit hooks**: Removed hardcoded filesystem paths; hooks now work in any environment.
- **Documentation front-matter**: Fixed missing/short SEO metadata in Chinese documentation files.

### Developer
- Plugin base class now auto-generates `help_url` property from class name (no manual URL definition needed).
- Plugins can override with `_help_url` class attribute for external documentation links.
- Pre-commit check validates documentation file existence instead of URL format.

## [0.2.24] - 2025-12-25

### Added
- **New plugin: `hsts_header`**: Detects missing or weak `Strict-Transport-Security` (HSTS) configuration on HTTPS servers.
- **New plugin: `http2_misdirected_request`**: Detects `default_server` + HTTP/2 + `ssl_reject_handshake on` setups missing a defensive `location / { return 421; }`.

### Changed
- **`weak_ssl_tls` scope clarified**: HSTS checks were moved out to `hsts_header` (TLS protocols/ciphers and cipher preference remain in `weak_ssl_tls`).

### Fixed
- **HSTS false positives**: HSTS checks now correctly skip `ssl_reject_handshake on;` servers (they cannot emit HTTP response headers).

## [0.2.23] - 2024-12-19

### Added
- **New plugin: `weak_ssl_tls`**: Detects weak SSL/TLS configurations including:
  - Insecure protocols (SSLv2, SSLv3, TLSv1, TLSv1.1)
  - Weak cipher suites (NULL, DES, RC4, EXPORT, etc.)
  - Missing or weak HSTS headers
  - `ssl_prefer_server_ciphers off` configuration
- **Auto-fix mode**: New `--fix` and `--fix-dry-run` CLI options to automatically apply fixes for detected issues. Creates `.bak` backup files by default (disable with `--no-backup`).
- **Python 3.6 pre-commit check**: Full test suite now runs with Python 3.6 on every commit to ensure compatibility with minimum supported version.
- **README overhaul**: Reorganized plugin documentation into categorized table format with links to official docs.

### Changed
- `scripts/test_py36.sh` now runs the full test suite instead of a subset of tests.

### Fixed
- Added missing HSTS header to staging server in `wordpress_production.conf` integration test.

## [0.2.22] - 2024-12-16

### Added
- **Checkstyle XML output format**: New `-f checkstyle` formatter for CI/CD integration. Works natively with Jenkins, GitLab CI, GitHub Actions (reviewdog), Bitbucket Pipelines, and SonarQube. Maps severities: HIGH→error, MEDIUM→warning, LOW→info.
- **Bandit security scanner**: Added to pre-commit for local security scanning before push.
- **Hardcoded IP address check**: Custom pre-commit hook (`check_hardcoded_ips.py`) mirrors SonarCloud rule S1313 for local detection of hardcoded IPs.
- **Path filters for CI**: GitHub Actions workflow now skips tests when only docs/configs change.

### Changed
- Documentation updated (en/ru/zh) to list `checkstyle` as available output format.

### Fixed
- Added `# NOSONAR` and `# nosec` comments to suppress false positives from security scanners (SonarCloud, Bandit) for intentional patterns like test URLs, Jinja2 autoescape for CLI output, and test IP addresses.

## [0.2.21] - 2024-12-12

### Fixed
- Python 3.6 compatibility: Fixed AST parsing in `check_plugin_help_urls.py` to use `ast.Str` (Python 3.6/3.7) instead of `ast.Constant` (Python 3.8+).

## [0.2.20] - 2024-12-12

### Fixed
- Python 3.6 compatibility: Removed type comments that referenced undefined names (`List`, `Tuple`, `Optional`).

### Added
- Pre-commit configuration with Python 3.6 syntax checking using pyenv.
- CI job `py36-compat` to verify scripts work on Python 3.6 minimum version.

## [0.2.19] - 2024-12-12

### Added
- **Quick Fix Support**: Plugins now return machine-readable fix suggestions in JSON output for IDE integration.
  - `Fix` class in `gixy.core.issue` with `title`, `search`, `replace`, and optional `description` fields.
  - Plugins can use `self.make_fix()` helper to create fixes.
  - JSON formatter includes `fixes` array for each issue.
- **Plugin fixes implemented**:
  - `version_disclosure`: Set `server_tokens off`
  - `host_spoofing`: Replace `$http_host` with `$host`
  - `add_header_content_type`: Use `default_type` instead of `add_header Content-Type`
  - `allow_without_deny`: Add `deny all;` after allow directives
  - `valid_referers`: Remove `none` from referers
  - `error_log_off`: Set proper error_log path
  - `resolver_external`: Use internal DNS resolver
  - `low_keepalive_requests`: Increase keepalive_requests to 10000
- **Pre-commit hooks**: Added `.pre-commit-config.yaml` with plugin help_url validation.
- **CI checks**: Enhanced GitHub Actions workflow with plugin validation checks.

### Fixed
- `version_disclosure` plugin no longer double-reports when `server_tokens on` is at http level.
- Plugin help_url validation script now correctly handles edge cases.

### Changed
- All plugin `help_url` attributes now consistently point to `https://gixy.getpagespeed.com/plugins/`.

## [0.2.14] - 2025-12-06

### Added
- **ReDoS detection rewrite**: Complete rewrite of `regex_redos` plugin using Python's built-in `sre_parse` module - no external dependencies required. Detects nested quantifiers (exponential O(2^n)), overlapping alternatives (polynomial O(n²)), and adjacent greedy quantifiers.
- **nginx 1.29.3 support**: `add_header_redefinition` plugin now respects `add_header_inherit on;` directive.
- **Integration testing**: Added comprehensive WordPress production config (~380 lines) as integration test to catch false positives.
- **Documentation**: Added missing `try_files_is_evil_too.md`, updated plugin list in index.md (now 25 plugins).
- **`if` block variable capture**: `if` blocks with regex conditions (`~`, `~*`) now properly expose capture groups as variables with correct boundary inheritance.

### Changed
- ReDoS plugin now covers `location`, `if`, `rewrite`, `server_name`, and `map` directives.
- Documentation updated for `add_header_redefinition` with nginx 1.29.3+ solution.
- Expanded regex_redos.md with detailed vulnerability patterns and examples.

### Fixed
- Code quality improvements: explicit `autoescape=False` for Jinja2 (plain text output), noqa comments for intentional test patterns and random module usage.
- Legacy code cleanup in regexp.py: replaced alternation with character class, merged string concatenation, improved comments.

## [0.2.13] - 2025-12-06

### Added
- **Rich console formatter**: New beautiful terminal output with colors, panels, and progress indicators using the [Rich](https://github.com/Textualize/rich) library. Automatically enabled in TTY when `rich` is installed. Install with `pip install gixy-ng[rich]`.
- **Line numbers in output**: Issues now display the line number and file path where they were detected.
- **Security score**: The rich console formatter shows a security score (0-100) based on issue severity.
- Directives now track `line` and `file` attributes for better error reporting.
- New CLI tests for plugin options, boolean flag parsing, and module invocation.
- Formatter tests for the new rich console output.

### Changed
- Parser refactored: `parse()` method is now an alias for `parse_string()` for backward compatibility.
- Parser internals cleaned up with new `_build_tree_from_parsed()` method that handles both file and dump parsing uniformly.
- Line number propagation through the parser pipeline for accurate issue location reporting.

### Fixed
- README.md now lists all available plugins including `default_server_flag`, `hash_without_default`, and `return_bypasses_allow_deny`.
- Rich console formatter tests now skip gracefully when `rich` library is not installed.
- CLI default formatter selection now correctly checks if `rich_console` is actually registered (all rich submodules available), preventing argparse failures with partial rich installations.
- Lua blocks (`content_by_lua_block`, etc.) now include line number information for accurate issue location reporting.
- Fixed `TypeError: argument of type 'NoneType' is not iterable` in `add_header_multiline` plugin when header value is None ([#35](https://github.com/dvershinin/gixy/issues/35)).

### Dependencies
- Added optional `rich>=13.0.0` dependency for enhanced terminal output.

## [0.2.12] and earlier

See [GitHub Releases](https://github.com/dvershinin/gixy/releases) for previous changelog entries.
