---
title: "CI/CD Integration"
description: "Integrate Gixy into your CI/CD pipeline to automatically scan NGINX configs for security issues. Supports Jenkins, GitLab CI, GitHub Actions, and more."
---

# CI/CD Integration

Gixy integrates seamlessly with CI/CD pipelines to catch NGINX security misconfigurations before they reach production.

## Checkstyle XML Output

For CI/CD integration, use the `--format checkstyle` option to generate machine-readable XML output:

```bash
gixy --format checkstyle /etc/nginx/nginx.conf > gixy-report.xml
```

The Checkstyle XML format is a widely-supported standard for static analysis tools, natively consumed by:

- **Jenkins** (Warnings Next Generation plugin)
- **GitLab CI** (Code Quality reports)
- **GitHub Actions** (via reviewdog, super-linter)
- **Bitbucket Pipelines** (Code Insights)
- **SonarQube** (External issues import)
- **Many IDEs** (IntelliJ, Eclipse, VS Code)

### Example Output

```xml
<?xml version="1.0" encoding="UTF-8"?>
<checkstyle version="8.0">
  <file name="/etc/nginx/nginx.conf">
    <error line="10" column="1" severity="error"
           message="[ssrf] SSRF vulnerability: reason"
           source="gixy.ssrf"/>
  </file>
</checkstyle>
```

## GitHub Actions

```yaml
name: NGINX Security Scan

on: [push, pull_request]

jobs:
  gixy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Gixy
        run: pip install gixy-ng

      - name: Run Gixy
        run: gixy --format checkstyle nginx/*.conf > gixy-report.xml
        continue-on-error: true

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: gixy-report
          path: gixy-report.xml
```

### With reviewdog

For inline PR comments, use [reviewdog](https://github.com/reviewdog/reviewdog):

```yaml
- name: Run Gixy with reviewdog
  uses: reviewdog/action-setup@v1

- name: Gixy
  env:
    REVIEWDOG_GITHUB_API_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    gixy --format checkstyle nginx/*.conf | \
      reviewdog -f=checkstyle -reporter=github-pr-review
```

## GitLab CI

```yaml
gixy:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install gixy-ng
  script:
    - gixy --format checkstyle nginx/*.conf > gl-code-quality-report.xml
  artifacts:
    reports:
      codequality: gl-code-quality-report.xml
    when: always
```

## Jenkins

Using the [Warnings Next Generation Plugin](https://plugins.jenkins.io/warnings-ng/):

```groovy
pipeline {
    agent any
    stages {
        stage('NGINX Security Scan') {
            steps {
                sh 'pip install gixy-ng'
                sh 'gixy --format checkstyle /etc/nginx/*.conf > gixy-report.xml || true'
            }
            post {
                always {
                    recordIssues(
                        tools: [checkStyle(pattern: 'gixy-report.xml')]
                    )
                }
            }
        }
    }
}
```

## Docker

For containerized pipelines:

```bash
docker run --rm -v /path/to/nginx:/etc/nginx:ro \
  getpagespeed/gixy --format checkstyle /etc/nginx/nginx.conf
```

## Exit Codes

Gixy uses exit codes to indicate scan results:

| Exit Code | Meaning |
|-----------|---------|
| 0 | Analysed, no issues found |
| 1 | Analysed, issues found |
| 2 | Not analysed: Gixy could not parse the configuration, the analysis failed, or the command line was invalid |

Use these in your CI/CD pipeline to fail builds on security issues:

```bash
gixy /etc/nginx/nginx.conf || exit 1
```

## JSON Report for Wrappers

`--format json` prints a bare list of issues, so an empty list `[]` alone does
not tell a clean configuration from one Gixy could not parse. Programs that wrap
Gixy should use `--format json_report`, which states the outcome explicitly:

```bash
gixy --format json_report /etc/nginx/nginx.conf
```

```json
{
  "report_version": 1,
  "gixy_version": "0.2.62",
  "status": "rejected",
  "error": {
    "kind": "invalid_configuration",
    "message": "unexpected end of file, expecting \"}\" in /etc/nginx/nginx.conf:12 (line:12, col:1)",
    "path": "/etc/nginx/nginx.conf"
  },
  "issues": []
}
```

| `status` | Meaning | Exit code |
|----------|---------|-----------|
| `analysed` | Every input was analysed; `issues` is the complete result and `error` is `null` | 0 or 1 |
| `rejected` | Gixy could not parse an input (`error.kind` is `invalid_configuration`) | 2 |
| `error` | The analysis did not complete (`error.kind` is `internal_error`) | 2 |

Treat `issues` as a result only when `status` is `analysed`. The entries of
`issues` are the same objects `--format json` prints.

### Python API

Python programs can skip the command line. `gixy.api.analyze()` returns the same
report and does not raise for anything the configuration can cause:

```python
from gixy.api import analyze

result = analyze(config_text, nginx_version="1.28.0")
if result.analysed:
    findings = result.issues
else:
    reason = result.error["message"]  # result.status is "rejected" or "error"
```

`include` directives are not followed unless `allow_includes=True` is passed,
because the text may come from an untrusted source. `checks` and `skips` select
checks by name. Use `analyze_with_config()` with a `gixy.core.config.Config` for
other options. `gixy --server` responses carry the same `status` field.

## Pre-commit Hook

Add Gixy to your pre-commit configuration:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/dvershinin/gixy
    rev: v0.2.24
    hooks:
      - id: gixy
        files: \.conf$
```

## Severity Mapping

Gixy severities map to Checkstyle severities as follows:

| Gixy Severity | Checkstyle Severity |
|---------------|---------------------|
| HIGH | error |
| MEDIUM | warning |
| LOW | info |
| UNSPECIFIED | info |

Configure your CI/CD tool to fail on specific severity levels as needed.

--8<-- "en/snippets/amplify-cta.md"
