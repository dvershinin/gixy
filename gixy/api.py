"""Stable entry point for analysing NGINX configuration text.

Services, editors and wrappers call :func:`analyze` instead of Gixy internals.
Every call answers one of two things: the configuration was analysed and these
are the findings, or it was not analysed and this is why. An empty ``issues``
list is a clean result only when ``status`` is ``analysed``.
"""

import io
import logging

import gixy
from gixy.core.config import Config
from gixy.core.exceptions import InvalidConfiguration
from gixy.core.manager import Manager
from gixy.core.nginx_version import parse_oss
from gixy.formatters.json import JsonFormatter, issue_entries

LOG = logging.getLogger(__name__)

REPORT_VERSION = 1

ANALYSED = "analysed"
REJECTED = "rejected"
ERROR = "error"

INVALID_CONFIGURATION = "invalid_configuration"
INVALID_REQUEST = "invalid_request"
INTERNAL_ERROR = "internal_error"


class AnalysisResult:
    """Outcome of one analysis.

    Attributes:
        status (str): ``analysed``, ``rejected`` (Gixy could not parse the
            configuration) or ``error`` (the analysis did not complete).
        issues (list): Findings as the dicts ``--format json`` prints; empty
            unless ``status`` is ``analysed``.
        error (dict or None): ``{"kind": ..., "message": ...}`` when the
            configuration was not analysed.
        gixy_version (str): Version of the Gixy that produced the result.
    """

    def __init__(self, status, issues=None, error=None):
        self.status = status
        self.issues = issues if issues is not None else []
        self.error = error
        self.gixy_version = gixy.version

    @property
    def analysed(self):
        return self.status == ANALYSED

    def as_dict(self):
        """Return the report object shared with ``--format json_report``.

        Returns:
            dict: JSON-serializable report.
        """
        return {
            "report_version": REPORT_VERSION,
            "gixy_version": self.gixy_version,
            "status": self.status,
            "error": self.error,
            "issues": self.issues,
        }


def describe_failure(error):
    """Classify an exception raised while auditing a configuration.

    Args:
        error (Exception): Exception raised by the audit.

    Returns:
        tuple: Result status and its ``{"kind", "message"}`` error.
    """
    if isinstance(error, InvalidConfiguration):
        return REJECTED, {"kind": INVALID_CONFIGURATION, "message": str(error)}
    return ERROR, {
        "kind": INTERNAL_ERROR,
        "message": f"{type(error).__name__}: {error}",
    }


def analyze(
    content,
    filename="<stdin>",
    nginx_version=None,
    nginx_flavor=None,
    allow_includes=False,
    checks=None,
    skips=None,
):
    """Analyse NGINX configuration text.

    Never raises for anything the configuration or these options can cause.
    Includes stay disabled by default because the text may be untrusted.

    Args:
        content (str or bytes): NGINX configuration text.
        filename (str): Name attributed to the text in findings.
        nginx_version (str or None): Explicit ``X.Y.Z`` target version, which
            enables version-dependent checks. ``auto`` is unavailable here.
        nginx_flavor (str or None): NGINX flavor; upstream when omitted.
        allow_includes (bool): Follow ``include`` directives on this host.
        checks (list or None): Run only these checks.
        skips (list or None): Skip these checks.

    Returns:
        AnalysisResult: Findings, or the reason there are none.
    """
    if nginx_version is not None and parse_oss(nginx_version) is None:
        return _invalid_request("nginx_version must be an explicit X.Y.Z version")
    try:
        config = Config(
            plugins=checks,
            skips=skips,
            allow_includes=allow_includes,
            nginx_version=nginx_version,
            nginx_flavor=nginx_flavor,
        )
    except ValueError as e:
        return _invalid_request(str(e))
    return analyze_with_config(content, config, filename=filename)


def analyze_with_config(content, config, filename="<stdin>"):
    """Analyse NGINX configuration text under a prepared ``Config``.

    Args:
        content (str or bytes): NGINX configuration text.
        config (gixy.core.config.Config): Audit configuration.
        filename (str): Name attributed to the text in findings.

    Returns:
        AnalysisResult: Findings, or the reason there are none.
    """
    if isinstance(content, str):
        content = content.encode("utf-8")
    elif not isinstance(content, (bytes, bytearray)):
        return _invalid_request("content must be text or bytes")

    try:
        with Manager(config=config) as manager:
            manager.audit(filename, io.BytesIO(content), is_stdin=True)
            formatter = JsonFormatter()
            formatter.feed(filename, manager)
            issues = issue_entries(formatter.reports)
    except InvalidConfiguration as e:
        return _not_analysed(e)
    except Exception as e:
        LOG.error("Analysis failed: %s", e, exc_info=True)
        return _not_analysed(e)
    return AnalysisResult(ANALYSED, issues=issues)


def _not_analysed(error):
    status, description = describe_failure(error)
    return AnalysisResult(status, error=description)


def _invalid_request(message):
    return AnalysisResult(ERROR, error={"kind": INVALID_REQUEST, "message": message})
