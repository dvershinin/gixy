"""Main module for Gixy CLI"""

import argparse
import copy
import logging
import os
import sys

import gixy
from gixy.cli.argparser import create_parser
from gixy.core.config import Config
from gixy.core.exceptions import InvalidConfiguration
from gixy.core.manager import Manager as Gixy
from gixy.core.plugins_manager import PluginsManager
from gixy.formatters import get_all as formatters

LOG = logging.getLogger()


def _apply_fixes(reports, dry_run=False, create_backup=True):
    """Apply fixes from the reports to the configuration files.

    Args:
        reports: Dict mapping file paths to lists of issue reports.
        dry_run: If True, only show what would be changed without modifying files.
        create_backup: If True, create .bak backup files before modifying.

    Returns:
        Tuple of (fixes_applied, fixes_failed).
    """
    fixes_applied = 0
    fixes_failed = 0

    # Group fixes by file
    fixes_by_file = {}
    for path, issues in reports.items():
        if path == "-" or path == "<stdin>":
            # Can't fix stdin
            continue

        for issue in issues:
            if "fixes" not in issue or not issue["fixes"]:
                continue

            # Get the actual file from location if available
            location = issue.get("location", {})
            file_path = location.get("file") if location else None

            # Fall back to the report path
            if not file_path:
                file_path = path

            if file_path not in fixes_by_file:
                fixes_by_file[file_path] = []

            # Take the first (preferred) fix for each issue
            fix = issue["fixes"][0]
            fix["issue_summary"] = issue.get("summary", "Unknown issue")
            fix["line"] = location.get("line") if location else None
            fixes_by_file[file_path].append(fix)

    if not fixes_by_file:
        sys.stderr.write("No fixes available to apply.\n")
        return 0, 0

    # Apply fixes to each file
    for file_path, fixes in fixes_by_file.items():
        if not os.path.exists(file_path):
            sys.stderr.write(f"⚠️  File not found: {file_path}\n")
            fixes_failed += len(fixes)
            continue

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
        except OSError as e:
            sys.stderr.write(f"⚠️  Cannot read {file_path}: {e}\n")
            fixes_failed += len(fixes)
            continue

        original_content = content
        file_fixes_applied = 0

        for fix in fixes:
            search = fix.get("search", "")
            replace = fix.get("replace", "")
            title = fix.get("title", "Fix")
            summary = fix.get("issue_summary", "")

            if not search:
                continue

            if search in content:
                if dry_run:
                    sys.stdout.write(f"📝 {file_path}\n")
                    sys.stdout.write(f"   [{summary}]\n")
                    sys.stdout.write(f"   🔧 {title}\n")
                    sys.stdout.write(f"   - {search}\n")
                    sys.stdout.write(f"   + {replace}\n\n")
                else:
                    content = content.replace(search, replace, 1)
                file_fixes_applied += 1
            else:
                # Search pattern not found - might already be fixed or config changed
                pass

        if file_fixes_applied > 0:
            if not dry_run:
                # Create backup if requested
                if create_backup:
                    backup_path = file_path + ".bak"
                    try:
                        with open(backup_path, "w", encoding="utf-8") as f:
                            f.write(original_content)
                    except OSError as e:
                        sys.stderr.write(
                            f"⚠️  Cannot create backup {backup_path}: {e}\n"
                        )

                # Write the fixed content
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    sys.stdout.write(
                        f"✅ Applied {file_fixes_applied} fix(es) to {file_path}\n"
                    )
                    fixes_applied += file_fixes_applied
                except OSError as e:
                    sys.stderr.write(f"❌ Cannot write {file_path}: {e}\n")
                    fixes_failed += file_fixes_applied
            else:
                fixes_applied += file_fixes_applied

    return fixes_applied, fixes_failed


def _init_logger(debug=False):
    LOG.handlers = []
    log_level = logging.DEBUG if debug else logging.INFO

    LOG.setLevel(log_level)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(module)s]\t%(levelname)s\t%(message)s"))
    LOG.addHandler(handler)
    LOG.debug("logging initialized")


def _str_to_bool(value):
    """Parse flexible boolean values for plugin CLI options.

    Accepts common forms like true/false, yes/no, on/off, 1/0 (case-insensitive).
    """
    if isinstance(value, bool):
        return value

    text = str(value).strip().lower()
    truthy = {"1", "true", "yes", "y", "on"}
    falsy = {"0", "false", "no", "n", "off"}

    if text in truthy:
        return True
    if text in falsy:
        return False

    raise argparse.ArgumentTypeError(
        f"Expected a boolean value (true/false, yes/no, 1/0), got {value!r}"
    )


def _create_plugin_help(plugin_cls, opt_key, option):
    """Build help text for a plugin option, including usage hints and default.

    Attempts to use plugin-provided descriptions via optional
    `options_help` mapping on the plugin class.
    """
    if isinstance(option, (tuple, list, set)):
        default = ",".join(list(option))
        usage_hint = "Comma-separated list."
    else:
        default = str(option)
        usage_hint = None

    if isinstance(option, bool):
        usage_hint = "Boolean (true/false, yes/no, 1/0)."

    # Plugin-specific description if provided
    base_desc = ""
    if hasattr(plugin_cls, "options_help"):
        options_help = plugin_cls.options_help
        if isinstance(options_help, dict):
            base_desc = options_help.get(opt_key, "")

    parts = [p for p in [base_desc, usage_hint, f"Default: {default}"] if p]
    return " ".join(parts)


def _get_cli_parser():
    parser = create_parser()
    parser.add_argument(
        "nginx_files",
        nargs="*",
        type=str,
        default=["/etc/nginx/nginx.conf"],
        metavar="nginx.conf",
        help="Path to nginx.conf, e.g. /etc/nginx/nginx.conf",
    )

    parser.add_argument(
        "-v", "--version", action="version", version=f"Gixy v{gixy.version}"
    )

    parser.add_argument(
        "-l",
        "--level",
        dest="level",
        action="count",
        default=0,
        help="Report issues of a given severity level or higher (-l for LOW, -ll for MEDIUM, -lll for HIGH)",
    )

    # Determine available formatters first, then pick default
    available_formatters = formatters().keys()

    # Use rich_console as default for TTY if available, fallback to console
    if sys.stdout.isatty():
        # Only use rich_console if it's actually registered (all imports succeeded)
        if "rich_console" in available_formatters:
            default_formatter = "rich_console"
        else:
            default_formatter = "console"
    else:
        default_formatter = "text"
    parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=available_formatters,
        default=default_formatter,
        type=str,
        help="Specify output format",
    )

    parser.add_argument(
        "-o", "--output", dest="output_file", type=str, help="Write report to file"
    )

    parser.add_argument(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="Turn on debug mode",
    )

    parser.add_argument(
        "--deep",
        dest="deep",
        action="store_true",
        default=False,
        help=(
            "Run slower, more precise structural checks. Currently enables "
            "ReDoctor hybrid ReDoS analysis."
        ),
    )

    parser.add_argument(
        "--checks",
        "--tests",
        dest="checks",
        type=str,
        help="Comma-separated list of checks to run",
    )

    parser.add_argument(
        "--skips", dest="skips", type=str, help="Comma-separated list of checks to skip"
    )

    parser.add_argument(
        "--disable-includes",
        dest="disable_includes",
        action="store_true",
        default=False,
        help='Disable "include" directive processing',
    )

    parser.add_argument(
        "--vars-dirs",
        dest="vars_dirs",
        type=str,
        help="Comma-separated list of directories with custom variable drop-ins",
    )

    parser.add_argument(
        "--fix",
        dest="fix",
        action="store_true",
        default=False,
        help="Automatically apply suggested fixes to configuration files",
    )

    parser.add_argument(
        "--fix-dry-run",
        dest="fix_dry_run",
        action="store_true",
        default=False,
        help="Show what fixes would be applied without modifying files",
    )

    parser.add_argument(
        "--no-backup",
        dest="no_backup",
        action="store_true",
        default=False,
        help="Don't create .bak backup files when applying fixes (use with --fix)",
    )

    parser.add_argument(
        "--server",
        dest="server",
        action="store_true",
        default=False,
        help="Run in server mode (NDJSON over stdin/stdout)",
    )

    parser.add_argument(
        "--nginx-version",
        dest="nginx_version",
        type=str,
        default=None,
        metavar="X.Y.Z",
        help=(
            "Installed nginx Open Source version (e.g. 1.29.8). Enables "
            "the nginx_cves check to report CVEs that affect this "
            "version. Without this flag, nginx_cves stays silent."
        ),
    )

    group = parser.add_argument_group("check options")
    for plugin_cls in PluginsManager().plugins_classes:
        name = plugin_cls.__name__
        if not plugin_cls.options:
            continue

        options = copy.deepcopy(plugin_cls.options)
        for opt_key, opt_val in options.items():
            option_name = f"--{name}-{opt_key}".replace("_", "-")
            dst_name = f"{name}:{opt_key}"
            if isinstance(opt_val, (tuple, list, set)):
                opt_type = str
            elif isinstance(opt_val, bool):
                opt_type = _str_to_bool
            else:
                opt_type = type(opt_val)
            group.add_argument(
                option_name,
                metavar=opt_key,
                dest=dst_name,
                type=opt_type,
                help=_create_plugin_help(plugin_cls, opt_key, opt_val),
            )

    return parser


def main():
    parser = _get_cli_parser()
    args = parser.parse_args()
    _init_logger(args.debug)

    if args.server:
        try:
            severity = gixy.severity.ALL[args.level]
        except IndexError:
            severity = gixy.severity.ALL[0]

        config = Config(
            severity=severity,
            allow_includes=not args.disable_includes,
        )
        from gixy.cli.server import run_server

        run_server(config)
        sys.exit(0)

    # generate a list of user-expanded absolute paths from the nginx_files input arguments
    nginx_files = []

    for input_path in args.nginx_files:
        if input_path == "-":
            if len(args.nginx_files) > 1:
                sys.stderr.write("Expected either file paths or stdin, got both.\n")
                sys.exit(1)

            nginx_files.append("-")
        else:
            path = os.path.expanduser(os.path.abspath(input_path))

            if not os.path.exists(path):
                sys.stderr.write(
                    f"File {path!r} was not found.\nPlease specify correct path to configuration.\n"
                )
                sys.exit(1)

            nginx_files.append(path)

    try:
        severity = gixy.severity.ALL[args.level]
    except IndexError:
        sys.stderr.write(
            "Too high level filtering. Maximum level: -{0}\n".format(
                "l" * (len(gixy.severity.ALL) - 1)
            )
        )
        sys.exit(1)

    if args.checks:
        checks = [x.strip() for x in args.checks.split(",")]
    else:
        checks = None

    if args.skips:
        skips = [x.strip() for x in args.skips.split(",")]
    else:
        skips = None

    config = Config(
        severity=severity,
        output_format=args.output_format,
        output_file=args.output_file,
        plugins=checks,
        skips=skips,
        allow_includes=not args.disable_includes,
        vars_dirs=[x.strip() for x in args.vars_dirs.split(",")]
        if args.vars_dirs
        else None,
    )

    # Top-level --nginx-version aliases the auto-generated
    # --nginx-cves-version (the dest argparse uses for the per-plugin form).
    if args.nginx_version:
        setattr(args, "nginx_cves:version", args.nginx_version)

    # Top-level --deep enables the current deep-capable check while preserving
    # its auto-generated --regex-redos-deep per-plugin configuration option.
    if args.deep:
        setattr(args, "regex_redos:deep", True)

    for plugin_cls in PluginsManager().plugins_classes:
        name = plugin_cls.__name__
        options = copy.deepcopy(plugin_cls.options)
        for opt_key, opt_val in options.items():
            option_name = f"{name}:{opt_key}"
            if option_name not in vars(args):
                continue

            val = getattr(args, option_name)
            if val is None:
                continue

            if isinstance(opt_val, tuple):
                val = tuple([x.strip() for x in val.split(",")])
            elif isinstance(opt_val, set):
                val = {x.strip() for x in val.split(",")}
            elif isinstance(opt_val, list):
                val = [x.strip() for x in val.split(",")]
            options[opt_key] = val
        config.set_for(name, options)

    formatter = formatters()[config.output_format]()
    failed = False
    for path in nginx_files:
        with Gixy(config=config) as yoda:
            try:
                if path == "-":
                    with os.fdopen(sys.stdin.fileno(), "rb") as fdata:
                        yoda.audit("<stdin>", fdata, is_stdin=True)
                else:
                    with open(path, mode="rb") as fdata:
                        yoda.audit(path, fdata, is_stdin=False)
            except InvalidConfiguration as e:
                sys.stderr.write(f"Configuration error: {e}\n")
                failed = True
            formatter.feed(path, yoda)
            failed = failed or sum(yoda.stats.values()) > 0

    # Handle fix mode
    if args.fix or args.fix_dry_run:
        if args.fix and args.fix_dry_run:
            sys.stderr.write("Cannot use both --fix and --fix-dry-run\n")
            sys.exit(1)

        if "-" in nginx_files:
            sys.stderr.write("Cannot use --fix with stdin input\n")
            sys.exit(1)

        if args.fix_dry_run:
            sys.stdout.write("\n🔍 Dry run - showing fixes that would be applied:\n\n")

        fixes_applied, fixes_failed = _apply_fixes(
            formatter.reports,
            dry_run=args.fix_dry_run,
            create_backup=not args.no_backup,
        )

        if args.fix_dry_run:
            if fixes_applied > 0:
                sys.stdout.write(f"\n📊 {fixes_applied} fix(es) available to apply.\n")
                sys.stdout.write("   Run with --fix to apply them.\n")
            else:
                sys.stdout.write("No fixes available.\n")
        else:
            if fixes_applied > 0:
                sys.stdout.write(
                    f"\n🎉 Applied {fixes_applied} fix(es) successfully!\n"
                )
                if not args.no_backup:
                    sys.stdout.write("   Backup files created with .bak extension.\n")
            if fixes_failed > 0:
                sys.stdout.write(f"⚠️  {fixes_failed} fix(es) could not be applied.\n")

        # Print the report after fix summary
        if args.output_file:
            with open(config.output_file, "w") as f:
                f.write(formatter.flush())
        else:
            print(formatter.flush())

        # Exit with success if fixes were applied, even if issues were found
        if args.fix and fixes_applied > 0 and fixes_failed == 0:
            sys.exit(0)
    else:
        # Normal mode - just print results
        if args.output_file:
            with open(config.output_file, "w") as f:
                f.write(formatter.flush())
        else:
            print(formatter.flush())

    if failed:
        # If something found - exit code must be 1, otherwise 0
        sys.exit(1)
    sys.exit(0)


if (
    __name__ == "__main__"
):  # pragma: no cover - invoked only via `python -m gixy.cli.main`
    main()
