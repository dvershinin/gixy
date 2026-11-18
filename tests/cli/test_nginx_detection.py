"""Prove local opt-in detection without an installed NGINX or network."""

import importlib
import json
import os
import shlex
import subprocess
import sys
from types import SimpleNamespace

import pytest

from gixy.cli import nginx_version
from gixy.cli.main import _get_cli_parser
from gixy.core.config import Config
from gixy.core.manager import Manager
from gixy.core.nginx_flavors import load_definitions


CONFIG = """worker_processes 2;
quic_bpf on;
events {}
http {
    server {
        listen 443 quic reuseport;
        server_tokens on;
        location / { proxy_pass http://backend; }
    }
}
"""


def parse(arguments=(), config="", environment=None):
    parser = _get_cli_parser()
    parser._default_config_files = []
    return parser.parse_args(
        list(arguments), config_file_contents=config, env_vars=environment or {}
    )


@pytest.mark.parametrize(
    "arguments,config,environment,version,flavor",
    [
        ([], "", {}, None, None),
        (["--nginx-version=auto"], "", {}, "auto", None),
        ([], "nginx-version = auto", {}, "auto", None),
        ([], "", {"GIXY_NGINX_VERSION": "auto"}, "auto", None),
        (
            ["--nginx-version=1.30.6"],
            "nginx-version = auto",
            {"GIXY_NGINX_VERSION": "1.31.7"},
            "1.30.6",
            None,
        ),
        ([], "nginx-version = 1.30.6", {"GIXY_NGINX_VERSION": "auto"}, "auto", None),
        ([], "nginx-flavor = nginx-mod", {}, None, "nginx-mod"),
        (
            [],
            "nginx-flavor = nginx-mod",
            {"GIXY_NGINX_FLAVOR": "upstream"},
            None,
            "upstream",
        ),
        (
            ["--nginx-flavor=upstream"],
            "nginx-flavor = nginx-mod",
            {"GIXY_NGINX_FLAVOR": "nginx-mod"},
            None,
            "upstream",
        ),
    ],
)
def test_version_flavor_source_precedence(
    arguments, config, environment, version, flavor
):
    args = parse(arguments, config, environment)
    assert (args.nginx_version, args.nginx_flavor) == (version, flavor)


@pytest.mark.parametrize("source", ["cli", "config", "environment"])
def test_invalid_explicit_flavor_is_cli_error(source, capsys):
    with pytest.raises(SystemExit) as error:
        parse(
            ["--nginx-flavor=typo"] if source == "cli" else [],
            "nginx-flavor = typo" if source == "config" else "",
            {"GIXY_NGINX_FLAVOR": "typo"} if source == "environment" else {},
        )
    assert error.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_malformed_definitions_are_cli_and_core_errors(monkeypatch, capsys):
    from gixy.core import nginx_flavors

    monkeypatch.setattr(nginx_flavors.pkgutil, "get_data", lambda *args: b"{}")
    with pytest.raises(SystemExit) as error:
        _get_cli_parser()
    assert error.value.code == 2
    assert "NGINX flavor definitions" in capsys.readouterr().err
    with pytest.raises(ValueError, match="NGINX flavor definitions"):
        Config()


@pytest.mark.parametrize("stream", ["stderr", "stdout"])
@pytest.mark.parametrize(
    "override,expected", [(None, "nginx-mod"), ("upstream", "upstream")]
)
def test_detect_either_stream_and_force_flavor(
    monkeypatch, caplog, stream, override, expected
):
    result = {
        "returncode": 0,
        "stdout": "built by GCC/12.1.0",
        "stderr": "OpenSSL/3.0.1",
    }
    result[stream] += "\nnginx version: nginx-mod by GetPageSpeed.com/1.30.6\n"
    calls = []

    def probe():
        calls.append(True)
        return SimpleNamespace(**result)

    monkeypatch.setattr(nginx_version, "probe_nginx", probe)
    with caplog.at_level("INFO"):
        assert nginx_version.resolve_identity("auto", override, load_definitions()) == (
            "1.30.6",
            expected,
        )
    assert len(calls) == 1
    assert "Resolved NGINX version 1.30.6, flavor " + expected in caplog.text


@pytest.mark.parametrize(
    "failure",
    [
        FileNotFoundError("missing nginx"),
        PermissionError("not executable"),
        subprocess.TimeoutExpired(["nginx", "-V"], 5),
        UnicodeError("bad encoding"),
        SimpleNamespace(returncode=1, stderr="nginx version: nginx/1.31.7", stdout=""),
        SimpleNamespace(returncode=0, stderr="OpenSSL/3.0.1", stdout="GCC/12.1.0"),
    ],
)
def test_failed_auto_is_unknown_and_blocks_legacy(monkeypatch, caplog, failure):
    def probe():
        if isinstance(failure, BaseException):
            raise failure
        return failure

    monkeypatch.setattr(nginx_version, "probe_nginx", probe)
    version, flavor = nginx_version.resolve_identity("auto", None, load_definitions())
    assert version == "auto"
    config = Config(nginx_version=version, nginx_flavor=flavor)
    config.set_for("nginx_cves", {"version": "1.31.7"})
    assert config.resolved_nginx_version is None
    assert "version remains unknown" in caplog.text


@pytest.fixture
def local_cli(tmp_path, monkeypatch, capsys):
    main = importlib.import_module("gixy.cli.main")
    config_file = tmp_path / "gixy.cfg"
    config_file.write_text("")
    nginx_file = tmp_path / "nginx.conf"
    nginx_file.write_text(CONFIG)
    calls_file = tmp_path / "calls"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable = bin_dir / "nginx"
    original = main.create_parser

    def isolated_parser():
        parser = original()
        parser._default_config_files = [str(config_file)]
        return parser

    monkeypatch.setattr(main, "create_parser", isolated_parser)
    for key in os.environ:
        if key.startswith("GIXY_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("PATH", str(bin_dir))

    def run(
        arguments=(),
        settings="",
        banner="nginx version: nginx-mod by GetPageSpeed.com/1.30.6",
        status=0,
    ):
        config_file.write_text(settings)
        executable.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "
            + shlex.quote(str(calls_file))
            + "\nprintf '%s\\n' "
            + shlex.quote(banner)
            + " >&2\nexit "
            + str(status)
            + "\n"
        )
        executable.chmod(0o755)
        monkeypatch.setattr(
            sys,
            "argv",
            ["gixy", "--no-default-vars", "-f", "json"]
            + list(arguments)
            + [str(nginx_file)],
        )
        with pytest.raises(SystemExit) as error:
            main.main()
        captured = capsys.readouterr()
        return error.value.code, captured.out, captured.err

    return SimpleNamespace(
        run=run, calls=calls_file, config=config_file, nginx_file=nginx_file
    )


@pytest.mark.parametrize(
    "banner,override,quic,october_cve",
    [
        ("nginx-mod by GetPageSpeed.com/1.30.6", None, False, False),
        ("nginx-mod by GetPageSpeed.com/1.30.5", None, True, True),
        ("nginx/1.30.6", None, True, False),
        ("nginx/1.31.7", None, False, False),
        ("mystery/1.30.6", None, True, False),
        ("nginx-mod by GetPageSpeed.com/1.30.6", "upstream", True, False),
        ("nginx/1.30.6", "nginx-mod", False, False),
    ],
)
def test_default_config_auto_drives_real_cli_checks(
    local_cli, banner, override, quic, october_cve
):
    arguments = ["--debug"] + (["--nginx-flavor=" + override] if override else [])
    code, stdout, stderr = local_cli.run(
        arguments, "nginx-version = auto", "nginx version: " + banner
    )
    assert code == 1  # The unrelated server_tokens finding always remains.
    issues = json.loads(stdout)
    plugins = {issue["plugin"] for issue in issues}
    assert ("quic_bpf_reuseport" in plugins) is quic
    reasons = [issue["reason"] for issue in issues if issue["plugin"] == "nginx_cves"]
    assert any("CVE-2026-121810" in reason for reason in reasons)
    assert any("CVE-2026-93479" in reason for reason in reasons) is october_cve
    assert "version_disclosure" in plugins
    assert local_cli.calls.read_text().splitlines() == ["-V"]
    assert "Resolved NGINX version" in stderr
    if (
        "nginx-mod/1.30.6" in banner
        or ("GetPageSpeed.com/1.30.6" in banner and override != "upstream")
        or override == "nginx-mod"
    ):
        assert "Applying NGINX flavor nginx-mod fix for quic_bpf_reuseport" in stderr


def test_one_detection_across_multiple_files_and_checks(local_cli, tmp_path):
    second = tmp_path / "second.conf"
    second.write_text(CONFIG)
    code, stdout, _ = local_cli.run(
        [str(second)], "nginx-version = auto", "nginx version: nginx/1.30.5"
    )
    assert code == 1
    issues = json.loads(stdout)
    for path in (str(local_cli.nginx_file), str(second)):
        assert {"quic_bpf_reuseport", "nginx_cves"} <= {
            issue["plugin"] for issue in issues if issue["path"] == path
        }
    assert local_cli.calls.read_text().splitlines() == ["-V"]


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["--nginx-version=1.31.7"],
        ["--nginx-version=1.30.6", "--nginx-flavor=nginx-mod"],
        ["--nginx-cves-version=1.31.7"],
    ],
)
def test_cli_default_and_numeric_never_probe(local_cli, arguments):
    code, stdout, _ = local_cli.run(arguments)
    assert code == 1
    json.loads(stdout)
    assert not local_cli.calls.exists()


@pytest.mark.parametrize("action", ["--help", "--version", "--write-config"])
def test_early_exit_actions_do_not_probe(local_cli, tmp_path, action):
    arguments = [action]
    if action == "--write-config":
        arguments.append(str(tmp_path / "written.cfg"))
    code, _, _ = local_cli.run(
        arguments, "nginx-version = auto\nnginx-flavor = nginx-mod"
    )
    assert code == 0
    assert not local_cli.calls.exists()


@pytest.mark.parametrize("source", ["cli", "config", "environment"])
def test_server_rejects_auto_before_readiness_or_execution(
    local_cli, monkeypatch, source
):
    arguments = ["--server"]
    settings = ""
    if source == "cli":
        arguments.append("--nginx-version=auto")
    elif source == "config":
        settings = "nginx-version = auto"
    else:
        monkeypatch.setenv("GIXY_NGINX_VERSION", "auto")
    code, stdout, stderr = local_cli.run(arguments, settings)
    assert code == 2
    assert stdout == ""
    assert "unavailable with --server" in stderr
    assert not local_cli.calls.exists()


@pytest.mark.parametrize(
    "status,banner", [(1, "nginx version: nginx/1.31.7"), (0, "built by GCC/12.1.0")]
)
def test_failed_detection_cli_keeps_quic_and_json(local_cli, status, banner):
    code, stdout, stderr = local_cli.run(
        [], "nginx-version = auto\nnginx-cves-version = 1.31.7", banner, status
    )
    assert code == 1
    plugins = {issue["plugin"] for issue in json.loads(stdout)}
    assert "quic_bpf_reuseport" in plugins
    assert "nginx_cves" not in plugins
    assert "version remains unknown" in stderr


def test_library_config_and_manager_never_probe(monkeypatch):
    import io

    def forbidden():
        pytest.fail("library usage must not launch nginx")

    monkeypatch.setattr(nginx_version, "probe_nginx", forbidden)
    for version in (None, "auto", "1.31.7"):
        config = Config(nginx_version=version, nginx_flavor="nginx-mod")
        with Manager(config=config) as manager:
            manager.audit("sample.conf", io.BytesIO(CONFIG.encode()), is_stdin=True)
    assert Config().resolved_nginx_flavor == "upstream"


@pytest.mark.parametrize("version", [None, "1.30.6", "invalid"])
def test_resolver_never_probes_non_auto(monkeypatch, version):
    def forbidden():
        pytest.fail("no opt-in")

    monkeypatch.setattr(nginx_version, "probe_nginx", forbidden)
    assert nginx_version.resolve_identity(version, "nginx-mod", load_definitions()) == (
        version,
        "nginx-mod",
    )


@pytest.mark.parametrize(
    "version,flavor,expected",
    [
        (None, "nginx-mod", True),
        ("1.30.6", "nginx-mod", False),
        ("1.30.6", "upstream", True),
    ],
)
def test_real_server_numeric_flavor_readiness_json(
    local_cli, monkeypatch, version, flavor, expected
):
    # A real fresh process exercises readiness and NDJSON with explicit startup identity.
    environment = dict(os.environ)
    if version is not None:
        environment["GIXY_NGINX_VERSION"] = version
    environment["GIXY_NGINX_FLAVOR"] = flavor
    result = subprocess.run(  # noqa: UP022 - retain Python 3.6 compatibility.
        [sys.executable, "-m", "gixy.cli", "--server", "--no-default-vars"],
        input=json.dumps({"id": "one", "method": "analyze", "content": CONFIG}) + "\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert responses[0]["ready"] is True
    assert responses[1]["error"] is None
    assert (
        any(issue["plugin"] == "quic_bpf_reuseport" for issue in responses[1]["issues"])
        is expected
    )
    assert not local_cli.calls.exists()


def test_probe_adapter_real_binary_streams_stdin_and_arguments(tmp_path, monkeypatch):
    executable = tmp_path / "nginx"
    executable.write_text(
        "#!/bin/sh\n"
        "if read -r unexpected; then exit 9; fi\n"
        "printf 'args:%s\\n' \"$*\"\n"
        "printf 'nginx version: nginx/1.30.6\\n' >&2\n"
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    result = nginx_version.probe_nginx()
    assert result.returncode == 0
    assert result.stdout == "args:-V\n"
    assert result.stderr == "nginx version: nginx/1.30.6\n"


@pytest.mark.parametrize("source", ["config", "environment", "cli"])
def test_write_config_preserves_identity_without_detection(
    tmp_path, monkeypatch, source
):
    def forbidden():
        pytest.fail("write-config must not launch nginx")

    monkeypatch.setattr(nginx_version, "probe_nginx", forbidden)
    output = tmp_path / "written.cfg"
    arguments = ["--write-config", str(output)]
    config = ""
    environment = {}
    if source == "config":
        config = "nginx-version = auto\nnginx-flavor = nginx-mod"
    elif source == "environment":
        environment = {"GIXY_NGINX_VERSION": "auto", "GIXY_NGINX_FLAVOR": "nginx-mod"}
    else:
        arguments += ["--nginx-version=auto", "--nginx-flavor=nginx-mod"]
    with pytest.raises(SystemExit) as error:
        parse(arguments, config, environment)
    assert error.value.code == 0
    written = output.read_text()
    assert written.count("nginx-version = auto") == 1
    assert written.count("nginx-flavor = nginx-mod") == 1
    args = parse(config=written)
    assert (args.nginx_version, args.nginx_flavor) == ("auto", "nginx-mod")
