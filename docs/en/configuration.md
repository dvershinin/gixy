---
title: "Configuration & Usage Guide"
description: "Configure Gixy to fit your workflow: tune checks, CLI options, and variable drop-ins for sharper NGINX security scans."
---

# Configuration & Usage Guide

## Configuration (gixy.cfg)

Gixy reads configuration from the following locations (first found wins):

- `/etc/gixy/gixy.cfg`
- `~/.config/gixy/gixy.conf`

You can also pass a custom config path via `-c/--config` and write out a populated template with `--write-config`.

Configuration files use simple `key = value` pairs, optional sections, and support lists with `[a, b, c]` syntax. Keys mirror long CLI flags, with dashes, for example `--disable-includes` becomes `disable-includes`.

Note: the severity filter is CLI-only via `-l` repeats (e.g. `-l`, `-ll`, `-lll`). It is not read from the config file.

## Target NGINX version and flavor

By default Gixy does not run NGINX or discover its installed version. The CVE
advisor stays silent without a known version; the QUIC BPF check retains its
conditional warning. Supply the version of the binary that will load the config:

```sh
gixy --nginx-version=1.30.6 --nginx-flavor=nginx-mod /path/to/nginx.conf
```

To opt into detecting the local `nginx` executable on `PATH`, set:

```ini
nginx-version = auto
```

Plain `gixy` then runs `nginx -V` once per invocation, with a five-second timeout,
for all scanned files and version-aware checks. Opting in asserts that this local
binary is the intended target. For offline or remote scans, supply the target's
explicit version or leave it unknown. Detection does not run for help, version
output or `--write-config`; library configuration never runs a subprocess.
`--server` rejects `auto` before emitting readiness, but accepts an explicit
numeric version and flavor at startup.

The recognized flavors are `upstream` and `nginx-mod`. The banner
`nginx version: nginx-mod by GetPageSpeed.com/1.30.6` selects `nginx-mod`.
Unknown vendor banners with a valid version use upstream rules. An explicit
`nginx-flavor = upstream` or `--nginx-flavor=upstream` overrides detection;
`nginx-flavor = nginx-mod` also works with an explicit version for offline scans.
An unknown explicit flavor is an error. No flavor setting defaults to upstream
rules unless detection recognizes another flavor.

Both settings support environment variables `GIXY_NGINX_VERSION` and
`GIXY_NGINX_FLAVOR`. For each setting, CLI arguments override environment
variables, which override config files. The shared `nginx-version` overrides
legacy `nginx-cves-version`; that fallback applies only when the shared setting
is absent. Failed `auto` therefore remains unknown even if a legacy version is
configured. Missing executables, timeouts, failed commands and invalid banners
warn on stderr and preserve unknown-version behavior. Resolved identities are
logged at INFO; applied fix overrides at DEBUG (`--debug`), always on stderr so
JSON stdout remains a report.

Flavor definitions and authoritative fix references are bundled in
[`gixy/data/nginx-flavors.json`](https://github.com/dvershinin/gixy/blob/master/gixy/data/nginx-flavors.json).
They retain the advertised version and suppress only an exact check/CVE key at
or after its recorded fix version. The initial registry records only the
`quic_bpf_reuseport` fix in `nginx-mod` 1.30.6; it contains no vendor CVE
exemptions. Older ambiguous builds retain the warning. There are no package
manager queries or online feeds. Adding an evidenced flavor requires a data
record with `flavor`, `banner_prefix` and `fixed_in`; each fix needs a `version`
in X.Y.Z form and a nonempty `sources` list of authoritative HTTP(S) URLs.
Malformed bundled definitions are errors rather than silent exemptions.

## Managing Enabled Checks

- **Run only selected checks**: set `checks` to a comma-separated list of check names (you can also use the legacy `tests` key for backward compatibility).
- **Skip specific checks**: set `skips` to a comma-separated list of check names.

Examples:

```ini
# Only these checks will run
checks = if_is_evil, http_splitting

# These checks will be excluded from the run
skips = origins, version_disclosure
```

## Check-specific Options

Check options can be provided as sectioned keys where the section name is the check name written with hyphens (underscores replaced by hyphens). Keys inside sections also use hyphens. Examples:

```ini
[origins]
domains = example.com, example.org
https-only = true

[regex-redos]
deep = true
```

The same effect can be achieved without sections by combining the check name and option with a dash, e.g. `origins-domains = ...`, but sections are easier to organize.

## Other Useful Options

- **Output format**: `format = console|text|json|json_report|checkstyle` (same as `-f/--format`)
- **Write report to file**: `output = /path/to/report.txt` (same as `-o/--output`)
- **Disable include processing**: `disable-includes = true` (same as `--disable-includes`)
- **Custom variables directories**: `vars-dirs = [/etc/gixy/vars, ~/.config/gixy/vars]` (see "Custom variables drop-ins")
- **Deep analysis**: `deep = true` (same as `--deep`; requires `gixy-ng[deep]` from pip or the `gixy-deep` RPM and enables local ReDoctor automata and bounded custom-VM analysis)

## Full Example

```ini
# gixy.cfg

format = console
output = /tmp/gixy-report.txt
disable-includes = false

# Limit analysis to a subset of checks
checks = if_is_evil, http_splitting

# Skip some checks
skips = version_disclosure

# Load custom variable definitions (see variables-dropins)
vars-dirs = [/etc/gixy/vars, ~/.config/gixy/vars]

[origins]
domains = example.com, example.org
https-only = true

[regex-redos]
deep = true
```
