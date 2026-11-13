"""Server mode for Gixy -- NDJSON over stdin/stdout."""

import json
import sys

import gixy
from gixy.api import analyze_with_config


def run_server(config):
    """Run gixy in server mode, reading NDJSON requests from stdin.

    Args:
        config: Gixy Config instance with severity, allow_includes, etc.
    """
    _write_response({"ready": True, "version": gixy.version})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            _write_response({"id": None, "error": str(e)})
            continue

        req_id = request.get("id")
        method = request.get("method")

        if method == "ping":
            _write_response({"id": req_id, "pong": True, "version": gixy.version})
        elif method == "analyze":
            _handle_analyze(req_id, request, config)
        else:
            _write_response({"id": req_id, "error": f"Unknown method: {method}"})


def _handle_analyze(req_id, request, config):
    """Handle an analyze request.

    Args:
        req_id: Request ID for correlation.
        request: Parsed JSON request dict.
        config: Gixy Config instance.
    """
    filename = request.get("filename", "<stdin>")
    content = request.get("content", "")

    result = analyze_with_config(content, config, filename=filename)
    _write_response(
        {
            "id": req_id,
            "status": result.status,
            "issues": result.issues,
            # A plain string: existing clients read "error" as text.
            "error": result.error["message"] if result.error else None,
        }
    )


def _write_response(obj):
    """Write a JSON response line to stdout.

    Args:
        obj: Dict to serialize as JSON.
    """
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()
