#!/usr/bin/env python3
"""Administrative and diagnostic CLI for the PineAI backend."""

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional


ASSETS_DIRECTORY = Path(__file__).resolve().parent
if str(ASSETS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(ASSETS_DIRECTORY))

from pineai_backend.config import (  # noqa: E402
    ConfigError,
    load_settings,
    public_status,
    save_api_key,
    save_settings,
)
from pineai_backend.advisor_service import AttackPathAdvisorService  # noqa: E402
from pineai_backend.engagement_store import EngagementStore  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402
from pineai_backend.service import TargetProfilerService  # noqa: E402


def _read_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as failure:
        raise BackendError("invalid_input", "Could not read input JSON: {0}".format(failure))


def _print_json(value: Any, stream: Any) -> None:
    stream.write(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    stream.write("\n")


def _options(arguments: argparse.Namespace, include_ai: bool = False) -> Dict[str, Any]:
    options = {}
    if getattr(arguments, "language", None):
        options["language"] = arguments.language
    if getattr(arguments, "share_ssids", None) is not None:
        options["share_ssids"] = arguments.share_ssids
    if include_ai and getattr(arguments, "no_ai", False):
        options["ai_enabled"] = False
    return options


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pineai")
    parser.add_argument(
        "--config-dir", help="Override /root/.PineAI for testing or development"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    configure = commands.add_parser("configure")
    configure.add_argument("--key-stdin", action="store_true")
    configure.add_argument("--model")
    configure.add_argument("--language", choices=("en", "fi"))
    sharing = configure.add_mutually_exclusive_group()
    sharing.add_argument("--share-ssids", dest="share_ssids", action="store_true")
    sharing.add_argument("--hide-ssids", dest="share_ssids", action="store_false")
    configure.set_defaults(share_ssids=None)

    commands.add_parser("status")
    commands.add_parser("advisor-capabilities")

    engagement = commands.add_parser("engagement")
    engagement_commands = engagement.add_subparsers(
        dest="engagement_command", required=True
    )
    engagement_create = engagement_commands.add_parser("create")
    engagement_create.add_argument("--input", required=True)
    engagement_get = engagement_commands.add_parser("get")
    engagement_get.add_argument("--id", required=True)
    engagement_get.add_argument("--after-sequence", type=int, default=0)
    engagement_get.add_argument("--limit", type=int, default=100)
    engagement_list = engagement_commands.add_parser("list")
    engagement_list.add_argument("--include-archived", action="store_true")
    engagement_update = engagement_commands.add_parser("update")
    engagement_update.add_argument("--id", required=True)
    engagement_update.add_argument("--revision", required=True, type=int)
    engagement_update.add_argument("--input", required=True)
    engagement_archive = engagement_commands.add_parser("archive")
    engagement_archive.add_argument("--id", required=True)
    engagement_archive.add_argument("--revision", required=True, type=int)
    engagement_event = engagement_commands.add_parser("event")
    engagement_event.add_argument("--id", required=True)
    engagement_event.add_argument("--revision", required=True, type=int)
    engagement_event.add_argument("--input", required=True)

    for name in ("prepare", "profile"):
        command = commands.add_parser(name)
        command.add_argument("--input", required=True)
        command.add_argument("--language", choices=("en", "fi"))
        sharing = command.add_mutually_exclusive_group()
        sharing.add_argument("--share-ssids", dest="share_ssids", action="store_true")
        sharing.add_argument("--hide-ssids", dest="share_ssids", action="store_false")
        command.set_defaults(share_ssids=None)
        if name == "profile":
            command.add_argument("--no-ai", action="store_true")

    for name in ("prepare-advice", "advise"):
        command = commands.add_parser(name)
        command.add_argument("--engagement-id", required=True)
        command.add_argument("--input", required=True, help="profile_recon JSON result")
        command.add_argument("--target-id", required=True, action="append")
        command.add_argument("--language", choices=("en", "fi"))
        sharing = command.add_mutually_exclusive_group()
        sharing.add_argument("--share-ssids", dest="share_ssids", action="store_true")
        sharing.add_argument("--hide-ssids", dest="share_ssids", action="store_false")
        command.set_defaults(share_ssids=None)
        if name == "advise":
            command.add_argument("--no-ai", action="store_true")
    return parser


def main(
    argv: Optional[list] = None,
    stdout: Any = sys.stdout,
    stderr: Any = sys.stderr,
) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "configure":
            settings = load_settings(arguments.config_dir)
            if arguments.model:
                settings["model"] = arguments.model
            if arguments.language:
                settings["language"] = arguments.language
            if arguments.share_ssids is not None:
                settings["share_ssids"] = arguments.share_ssids
            save_settings(settings, arguments.config_dir)
            api_key = (
                sys.stdin.readline().rstrip("\r\n")
                if arguments.key_stdin
                else getpass.getpass("OpenAI API key: ")
            )
            save_api_key(api_key, arguments.config_dir)
            _print_json(public_status(arguments.config_dir), stdout)
            return 0
        if arguments.command == "status":
            _print_json(public_status(arguments.config_dir), stdout)
            return 0
        if arguments.command == "advisor-capabilities":
            _print_json(
                AttackPathAdvisorService(arguments.config_dir).capabilities(), stdout
            )
            return 0
        if arguments.command == "engagement":
            store = EngagementStore(arguments.config_dir)
            if arguments.engagement_command == "create":
                output = store.create(_read_json(arguments.input))
            elif arguments.engagement_command == "get":
                output = store.get(
                    arguments.id, arguments.after_sequence, arguments.limit
                )
            elif arguments.engagement_command == "list":
                output = {
                    "engagements": store.list(arguments.include_archived)
                }
            elif arguments.engagement_command == "update":
                output = store.update(
                    arguments.id,
                    arguments.revision,
                    _read_json(arguments.input),
                )
            elif arguments.engagement_command == "archive":
                output = store.archive(arguments.id, arguments.revision)
            else:
                output = store.append_event(
                    arguments.id,
                    arguments.revision,
                    _read_json(arguments.input),
                )
            _print_json(output, stdout)
            return 0
        if arguments.command in ("prepare-advice", "advise"):
            profile_result = _read_json(arguments.input)
            advisor = AttackPathAdvisorService(arguments.config_dir)
            if arguments.command == "prepare-advice":
                output = advisor.prepare_advice(
                    arguments.engagement_id,
                    profile_result,
                    arguments.target_id,
                    _options(arguments),
                )
            else:
                output = advisor.advise(
                    arguments.engagement_id,
                    profile_result,
                    arguments.target_id,
                    _options(arguments, include_ai=True),
                )
            _print_json(output, stdout)
            return 0

        scan = _read_json(arguments.input)
        service = TargetProfilerService(arguments.config_dir)
        if arguments.command == "prepare":
            output = service.prepare_recon(scan, options=_options(arguments))
        else:
            output = service.profile_recon(
                scan, options=_options(arguments, include_ai=True)
            )
        _print_json(output, stdout)
        return 0
    except (BackendError, ConfigError) as failure:
        code = getattr(failure, "code", "configuration_error")
        _print_json({"error": {"code": code, "message": str(failure)}}, stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
