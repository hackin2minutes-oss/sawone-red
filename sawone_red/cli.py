# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
"""Command line interface: sawone-red run | validate | list-packs."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace

from . import __version__
from .config import Config, load_config, validate_config
from .errors import AuthorizationError, ConfigError, SawoneRedError
from .outputs import write_reports
from .probes import SEVERITIES, load_packs, select_probes
from .runner import meets_threshold, run as run_probes

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_CONFIG = 2
EXIT_UNREACHABLE = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sawone-red",
        description="Sawone Red: AI red-teaming gate. Use only against systems you are authorized to test.",
    )
    parser.add_argument("--version", action="version", version=f"sawone-red {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    run_cmd = commands.add_parser("run", help="run probes against a target and write reports")
    run_cmd.add_argument("--config", required=True, help="path to the YAML config")
    run_cmd.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 on findings at or above this severity")
    run_cmd.add_argument("--output-dir", help="directory for report files (overrides config)")
    run_cmd.add_argument("--sarif", help="also write SARIF 2.1.0 to this exact path")
    run_cmd.add_argument("--probes-dir", help="extra directory of probe packs")

    validate_cmd = commands.add_parser("validate", help="check the probe library and optionally a config")
    validate_cmd.add_argument("--config", help="path to a YAML config to check")
    validate_cmd.add_argument("--probes-dir", help="extra directory of probe packs")

    list_cmd = commands.add_parser("list-packs", help="list probe packs and probe counts")
    list_cmd.add_argument("--probes-dir", help="extra directory of probe packs")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "run":
            return _cmd_run(args)
        if args.command == "validate":
            return _cmd_validate(args)
        return _cmd_list_packs(args)
    except AuthorizationError as exc:
        print(f"sawone-red: refused to test: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except SawoneRedError as exc:
        print(f"sawone-red: error: {exc}", file=sys.stderr)
        return EXIT_CONFIG


def console() -> None:
    sys.exit(main())


def _cmd_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    overrides = {}
    if args.fail_on:
        overrides["fail_on"] = args.fail_on
    if args.output_dir:
        overrides["output_dir"] = args.output_dir
    if args.probes_dir:
        overrides["probes_dir"] = args.probes_dir
    config = replace(config, **overrides)
    _require_valid(config)

    result = run_probes(config)
    written = write_reports(result, config.output_dir, config.formats, args.sarif)
    _print_summary(result, written)

    if result.executed == 0 and result.errors:
        print("sawone-red: no probe reached the target; check connectivity and credentials", file=sys.stderr)
        return EXIT_UNREACHABLE
    if any(meets_threshold(finding.severity, config.fail_on) for finding in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


def _cmd_validate(args: argparse.Namespace) -> int:
    config = None
    if args.config:
        config = load_config(args.config)
        _require_valid(config)
    packs = load_packs(args.probes_dir or (config.probes_dir if config else None))
    total = sum(len(pack.probes) for pack in packs)
    print(f"probe library OK: {len(packs)} packs, {total} probes")
    if config is not None:
        select_probes(packs, config.packs)
        print(f"config OK: {args.config}")
    return EXIT_OK


def _cmd_list_packs(args: argparse.Namespace) -> int:
    packs = load_packs(args.probes_dir)
    print(f"{'PACK':<26} {'OWASP':<6} {'PROBES':>6}  TITLE")
    for pack in packs:
        print(f"{pack.name:<26} {pack.owasp:<6} {len(pack.probes):>6}  {pack.title}")
    return EXIT_OK


def _require_valid(config: Config) -> None:
    problems = validate_config(config)
    if problems:
        raise ConfigError("\n".join(problems))


def _print_summary(result, written: dict[str, str]) -> None:
    print(f"Sawone Red {__version__}: {result.config_name}")
    print(f"target: {result.target}")
    print(
        f"executed {result.executed} probes: {len(result.findings)} findings, "
        f"{result.errors} errors, {result.skipped} skipped"
    )
    print(f"risk score {result.score}/100 ({result.rating})")
    for severity in reversed(SEVERITIES):
        count = sum(1 for finding in result.findings if finding.severity == severity)
        if count:
            print(f"  {severity}: {count}")
    for kind, path in written.items():
        print(f"report [{kind}]: {path}")
