import json

from gixy.api import ANALYSED, AnalysisResult
from gixy.formatters.base import BaseFormatter
from gixy.formatters.json import issue_entries


# The underscore keeps the registered name "json_report", like "rich_console".
class Json_reportFormatter(BaseFormatter):
    """Report whether the analysis ran alongside the issues it found."""

    def format_reports(self, reports, stats):
        status, error = ANALYSED, None
        if self.failures:
            # A run is analysed only when every input was; name the first that was not.
            path, status, description = self.failures[0]
            error = dict(description, path=path)
        report = AnalysisResult(status, issues=issue_entries(reports), error=error)
        return json.dumps(
            report.as_dict(), sort_keys=True, indent=2, separators=(",", ": ")
        )
