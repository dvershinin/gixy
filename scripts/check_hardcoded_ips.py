#!/usr/bin/env python3
"""
Check for hardcoded IP addresses in Python code (similar to SonarCloud S1313).

This catches IPs that SonarCloud would flag, allowing local detection before push.
Excludes:
- Lines with # NOSONAR comment
- Lines with # nosec comment
- Docstrings and comments (best effort)
- Known safe IPs (localhost, documentation IPs)
"""

import re
import sys
from pathlib import Path

# IP address pattern
IP_PATTERN = re.compile(r'"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"')

# IPs that are safe to hardcode (localhost, RFC 5737 documentation, etc.)
SAFE_IPS = {
    "127.0.0.1",
    "127.0.0.53",
    "0.0.0.0",  # nosec B104 - this is an allowlist, not a bind
    "255.255.255.255",
    # RFC 5737 documentation ranges (TEST-NET-1, TEST-NET-2, TEST-NET-3)
    # We allow these but SonarCloud still flags them in assertions
}

# Patterns that indicate the line is safe
SAFE_PATTERNS = [
    "# NOSONAR",
    "# nosec",
    "# noqa",
    "# nosemgrep",
    '"""',  # Docstring
    "'''",  # Docstring
]
REPO_ROOT = Path(__file__).resolve().parent.parent


def resolve_repo_path(filepath):
    """Resolve a path and require it to remain inside the repository."""
    candidate = Path(filepath).resolve()
    try:
        candidate.relative_to(REPO_ROOT)
    except ValueError:
        raise ValueError(f"Path is outside the repository: {filepath}")
    return candidate


def check_file(filepath):
    """Check a single file for hardcoded IPs."""
    issues = []
    try:
        filepath = resolve_repo_path(filepath)
        content = filepath.read_text()
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return [(filepath, 0, "invalid path", str(exc))]

    for lineno, line in enumerate(content.splitlines(), 1):
        # Skip safe patterns
        if any(pattern in line for pattern in SAFE_PATTERNS):
            continue

        # Skip comment-only lines
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue

        # Find IPs
        for match in IP_PATTERN.finditer(line):
            ip = match.group(1)
            if ip not in SAFE_IPS:
                issues.append((filepath, lineno, ip, line.strip()))

    return issues


def main():
    """Main entry point."""
    files = sys.argv[1:] if len(sys.argv) > 1 else []

    all_issues = []
    for filepath in files:
        if filepath.endswith(".py"):
            issues = check_file(filepath)
            all_issues.extend(issues)

    if all_issues:
        print("Hardcoded IP addresses found (add # NOSONAR if intentional):")
        print()
        for filepath, lineno, ip, line in all_issues:
            print(f"  {filepath}:{lineno}: {ip}")
            print(f"    {line}")
            print()
        print(f"Found {len(all_issues)} hardcoded IP(s).")
        print("To suppress: add '# NOSONAR' comment to the line.")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
