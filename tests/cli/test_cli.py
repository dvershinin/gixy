"""
Module: test_cli.py

This module demonstrates how to test Gixy's CLI using pytest.
"""

import subprocess
import sys

import pytest

from gixy.cli.main import _get_cli_parser, main


def test_cli_help(monkeypatch, capsys):
    """
    Test that running the CLI with --help displays usage information.
    """
    # Set sys.argv to simulate "gixy --help"
    monkeypatch.setattr(sys, "argv", ["gixy", "--help"])

    # If the CLI prints help and then exits, SystemExit is expected.
    with pytest.raises(SystemExit) as e:
        main()

    # Optionally check exit code (commonly 0 for --help)
    assert e.value.code == 0

    # Capture and check the output for expected help text.
    captured = capsys.readouterr()
    assert "usage:" in captured.out.lower()


def test_cli_vars_dirs_option_present():
    parser = _get_cli_parser()
    args = parser.parse_args(["--vars-dirs", "/etc/gixy/vars", "-"])
    # ensure option parsed
    assert getattr(args, "vars_dirs", None) == "/etc/gixy/vars"


def test_cli_deep_option_present():
    parser = _get_cli_parser()
    args = parser.parse_args(["--deep", "-"])
    assert args.deep is True


@pytest.mark.parametrize(
    "deep_args",
    (["--deep", "-"], ["--regex-redos-deep", "true", "-"]),
)
def test_cli_deep_requires_optional_dependency(monkeypatch, capsys, deep_args):
    monkeypatch.setattr("gixy.cli.main.REDOCTOR_AVAILABLE", False)
    monkeypatch.setattr(sys, "argv", ["gixy"] + deep_args)

    with pytest.raises(SystemExit) as error:
        main()

    assert error.value.code == 2
    assert "gixy-ng[deep]" in capsys.readouterr().err


def test_cli_help_contains_cta(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["gixy", "--help"])
    with pytest.raises(SystemExit):
        main()
    captured = capsys.readouterr()
    assert "nginx-extras.getpagespeed.com" in captured.out


def test_cli_main_runs_with_plugin_options(monkeypatch):
    """
    Ensure that main() can be invoked with plugin-specific options
    (e.g. --origins-domains) without raising a TypeError and that
    the configuration is constructed successfully.
    """

    captured = {}

    class DummyGixy:
        def __init__(self, config):
            # capture config passed into the manager
            captured["config"] = config
            # mimic real Manager.stats structure expected by formatters
            import gixy as _gixy

            self.stats = dict.fromkeys(_gixy.severity.ALL, 0)
            # minimal results attribute consumed by formatters
            self.results = []

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            # do not suppress exceptions
            return False

        def audit(self, path, fdata, is_stdin=False):
            # no-op: we are only interested in CLI wiring, not auditing
            return

    # Avoid hitting the real Manager and parser logic
    monkeypatch.setattr("gixy.cli.main.Gixy", DummyGixy, raising=True)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "gixy",
            "--deep",
            "--origins-domains",
            "example.com,foo.bar",
            "tests/integration/wordpress_production.conf",
        ],
    )

    with pytest.raises(SystemExit) as e:
        main()

    # main() should terminate with a standard exit code, not a TypeError
    assert e.value.code in (0, 1)

    # Ensure that config was constructed and contains plugin options for origins
    config = captured.get("config")
    assert config is not None
    origins_opts = config.get_for("origins")
    # Expect that domains has been split into a list
    assert origins_opts.get("domains") == ["example.com", "foo.bar"]
    assert config.get_for("regex_redos").get("deep") is True


def test_cli_module_invocation_via_python_m():
    """
    Ensure that invoking the CLI module via `python -m gixy.cli.main`
    actually calls main() and prints help when using --help.
    """
    completed = subprocess.run(
        [sys.executable, "-m", "gixy.cli.main", "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,  # text=True requires Python 3.7+
    )

    assert completed.returncode == 0
    assert "usage:" in completed.stdout.lower()


def test_cli_bool_plugin_options_true_and_false():
    """
    Ensure that boolean plugin options accept explicit true/false values.
    """
    parser = _get_cli_parser()

    args_true = parser.parse_args(["--origins-https-only", "true", "nginx.conf"])
    assert getattr(args_true, "origins:https_only") is True

    args_false = parser.parse_args(["--origins-https-only", "false", "nginx.conf"])
    assert getattr(args_false, "origins:https_only") is False


def test_cli_bool_plugin_options_alt_synonyms():
    """
    Ensure that boolean plugin options accept common synonyms like 1/0 and yes/no.
    """
    parser = _get_cli_parser()

    args_yes = parser.parse_args(["--origins-https-only", "yes", "nginx.conf"])
    assert getattr(args_yes, "origins:https_only") is True

    args_zero = parser.parse_args(["--origins-https-only", "0", "nginx.conf"])
    assert getattr(args_zero, "origins:https_only") is False


def test_cli_bool_plugin_options_reject_invalid():
    """
    Ensure that invalid boolean strings are rejected with a non-zero exit.
    """
    parser = _get_cli_parser()

    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["--origins-https-only", "maybe", "nginx.conf"])

    assert excinfo.value.code != 0
