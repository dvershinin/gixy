#!/usr/bin/env python3
"""
Pre-commit hook to ensure all documentation files have proper front-matter for SEO.

Required front-matter fields:
- title: Page title for SEO
- description: Meta description for search engines (recommended 150-160 chars)

Usage:
    python scripts/check_docs_frontmatter.py [files...]

If no files are provided, checks all .md files in docs/ directory.
"""

import re
import sys
from pathlib import Path


# Files that don't need front-matter (e.g., snippets, includes)
EXCLUDED_PATTERNS = [
    "snippets/",
    "includes/",
    "_",  # Files starting with underscore
]

# Required front-matter fields
REQUIRED_FIELDS = ["title", "description"]
REPO_ROOT = Path(__file__).resolve().parent.parent

# Regex to extract YAML front-matter
FRONTMATTER_REGEX = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)  # NOSONAR


def resolve_repo_path(filepath):
    """Resolve a path and require it to remain inside the repository."""
    candidate = Path(filepath).resolve()
    try:
        candidate.relative_to(REPO_ROOT)
    except ValueError:
        raise ValueError(f"Path is outside the repository: {filepath}")
    return candidate


def is_excluded(filepath):
    """Check if file should be excluded from front-matter check."""
    filepath_str = str(filepath)
    for pattern in EXCLUDED_PATTERNS:
        if pattern in filepath_str:
            return True
    return False


def extract_frontmatter(content):
    """Extract front-matter from markdown content."""
    match = FRONTMATTER_REGEX.match(content)
    if not match:
        return None
    return match.group(1)


def parse_frontmatter(frontmatter_text):
    """Parse YAML front-matter into a dictionary."""
    fields = {}
    for line in frontmatter_text.split("\n"):
        line = line.strip()
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and value:
                fields[key] = value
    return fields


def check_file(filepath):
    """Check a single file for proper front-matter."""
    try:
        filepath = resolve_repo_path(filepath)
    except ValueError as exc:
        return [str(exc)]

    if is_excluded(filepath):
        return []

    errors = []

    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception as e:
        return [f"{filepath}: Could not read file: {e}"]

    frontmatter_text = extract_frontmatter(content)

    if frontmatter_text is None:
        return [f"{filepath}: Missing front-matter (no --- block at start of file)"]

    fields = parse_frontmatter(frontmatter_text)

    for required_field in REQUIRED_FIELDS:
        if required_field not in fields:
            errors.append(
                f"{filepath}: Missing required front-matter field: {required_field}"
            )
        elif not fields[required_field]:
            errors.append(f"{filepath}: Empty front-matter field: {required_field}")

    # Check description length (SEO best practice: 150-160 chars)
    if "description" in fields:
        desc_len = len(fields["description"])
        if desc_len < 50:
            errors.append(
                f"{filepath}: Description too short ({desc_len} chars, recommend 100-160)"
            )
        elif desc_len > 200:
            errors.append(
                f"{filepath}: Description too long ({desc_len} chars, recommend 100-160)"
            )

    return errors


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        # Find all markdown files in docs/
        docs_dir = Path(__file__).parent.parent / "docs"
        files = list(docs_dir.rglob("*.md"))

    all_errors = []

    for filepath in files:
        filepath = Path(filepath)
        # Only check files in docs/ directory
        if "docs" not in str(filepath):
            continue
        if filepath.suffix != ".md":
            continue

        errors = check_file(filepath)
        all_errors.extend(errors)

    if all_errors:
        print("Front-matter check failed:")
        print()
        for error in all_errors:
            print(f"  ❌ {error}")
        print()
        print("Each documentation file should have front-matter like:")
        print()
        print("  ---")
        print('  title: "Page Title for SEO"')
        print(
            '  description: "A compelling meta description of 100-160 characters for search engines."'
        )
        print("  ---")
        print()
        sys.exit(1)

    print(f"✅ All {len(files)} documentation files have proper front-matter")
    sys.exit(0)


if __name__ == "__main__":
    main()
