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

- **Output format**: `format = console|text|json|checkstyle` (same as `-f/--format`)
- **Write report to file**: `output = /path/to/report.txt` (same as `-o/--output`)
- **Disable include processing**: `disable-includes = true` (same as `--disable-includes`)
- **Custom variables directories**: `vars-dirs = [/etc/gixy/vars, ~/.config/gixy/vars]` (see "Custom variables drop-ins")
- **Deep analysis**: `deep = true` (same as `--deep`; enables local ReDoctor automata and bounded custom-VM analysis)

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
