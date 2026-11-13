import json

from gixy.formatters.base import BaseFormatter


def issue_entries(reports):
    """Flatten per-path reports into the issue dicts of the JSON formats.

    Args:
        reports (dict): Prepared reports keyed by path, as formatters collect them.

    Returns:
        list: One JSON-serializable dict per issue.
    """
    result = []
    for path, issues in reports.items():
        for issue in issues:
            entry = {
                "path": path,
                "plugin": issue["plugin"],
                "summary": issue["summary"],
                "severity": issue["severity"],
                "description": issue["description"],
                "reference": issue["help_url"],
                "reason": issue["reason"],
                "config": issue["config"],
            }
            # Include location (line number) if available
            location = issue.get("location")
            if location:
                entry["line"] = location.get("line")
                if location.get("file"):
                    entry["file"] = location["file"]

            # Include fixes if available (for IDE integrations)
            fixes = issue.get("fixes")
            if fixes:
                entry["fixes"] = fixes

            result.append(entry)

    return result


class JsonFormatter(BaseFormatter):
    def format_reports(self, reports, stats):
        return json.dumps(
            issue_entries(reports), sort_keys=True, indent=2, separators=(",", ": ")
        )
