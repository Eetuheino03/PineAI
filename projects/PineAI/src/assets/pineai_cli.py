#!/usr/bin/env python3
"""Administrative CLI for PineAI Baseline & Drift."""

import argparse
import getpass
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Dict, Optional


ASSETS_DIRECTORY = Path(__file__).resolve().parent
if str(ASSETS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(ASSETS_DIRECTORY))

from pineai_backend.ai_analysis import AssuranceAIService  # noqa: E402
from pineai_backend.customer_store import CustomerAuditStore  # noqa: E402
from pineai_backend.assurance_service import AssuranceService  # noqa: E402
from pineai_backend.backup import (  # noqa: E402
    create_backup,
    restore_backup_staging,
    verify_backup,
)
from pineai_backend.config import (  # noqa: E402
    ConfigError,
    load_settings,
    public_status,
    save_api_key,
    save_settings,
)
from pineai_backend.errors import BackendError  # noqa: E402


MAX_CLI_JSON_INPUT_BYTES = 8 * 1024 * 1024
MAX_CLI_AUX_JSON_INPUT_BYTES = 1024 * 1024
MAX_CLI_REPORT_OUTPUT_BYTES = 8 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024


def _read_json(path: str, maximum_bytes: int = MAX_CLI_JSON_INPUT_BYTES) -> Any:
    input_path = Path(path)
    descriptor = None
    try:
        before = input_path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_size > maximum_bytes
        ):
            raise BackendError(
                "invalid_input", "JSON input must be a bounded regular file"
            )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(str(input_path), flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != before.st_size
            or getattr(opened, "st_dev", 0) != getattr(before, "st_dev", 0)
            or getattr(opened, "st_ino", 0) != getattr(before, "st_ino", 0)
        ):
            raise BackendError("invalid_input", "JSON input changed while opening")
        chunks = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) > maximum_bytes
            or len(payload) != opened.st_size
            or after.st_size != opened.st_size
            or getattr(after, "st_dev", 0) != getattr(opened, "st_dev", 0)
            or getattr(after, "st_ino", 0) != getattr(opened, "st_ino", 0)
        ):
            raise BackendError(
                "invalid_input", "JSON input exceeds its limit or changed"
            )
        return json.loads(payload.decode("utf-8"))
    except BackendError:
        raise
    except (OSError, UnicodeDecodeError, ValueError):
        raise BackendError(
            "invalid_input", "could not read JSON input"
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_private_report(path: str, content: str) -> str:
    if not isinstance(content, str):
        raise BackendError("output_write_failed", "report content is invalid")
    payload = content.encode("utf-8")
    if len(payload) > MAX_CLI_REPORT_OUTPUT_BYTES:
        raise BackendError(
            "output_too_large", "report output exceeds the safe size limit"
        )

    output_path = Path(path)
    parent = output_path.parent
    descriptor = None
    created_identity = None
    try:
        parent_absolute = Path(os.path.abspath(str(parent)))
        current = Path(parent_absolute.anchor)
        for part in parent_absolute.parts[1:]:
            current = current / part
            details = current.lstat()
            reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if stat.S_ISLNK(details.st_mode) or (
                getattr(details, "st_file_attributes", 0) & reparse_point
            ):
                raise BackendError(
                    "output_write_failed",
                    "report output directory must not contain symlinks",
                )
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise BackendError(
                "output_write_failed", "report output directory is invalid"
            )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(str(output_path), flags, 0o600)
        created_identity = os.fstat(descriptor)
        if not stat.S_ISREG(created_identity.st_mode):
            raise BackendError(
                "output_write_failed", "report output is not a regular file"
            )
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset : offset + READ_CHUNK_BYTES])
            if written <= 0:
                raise OSError("short report write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        return str(output_path)
    except FileExistsError as failure:
        raise BackendError(
            "output_exists", "report output already exists"
        ) from failure
    except BackendError:
        raise
    except OSError as failure:
        raise BackendError(
            "output_write_failed", "could not write report output"
        ) from failure
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if descriptor is not None and created_identity is not None:
            try:
                current = output_path.lstat()
                if (
                    getattr(current, "st_dev", 0)
                    == getattr(created_identity, "st_dev", 0)
                    and getattr(current, "st_ino", 0)
                    == getattr(created_identity, "st_ino", 0)
                ):
                    output_path.unlink()
            except OSError:
                pass


def _print_json(value: Any, stream: Any = sys.stdout) -> None:
    stream.write(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )


def _metadata(path: Optional[str]) -> Dict[str, Any]:
    return _read_json(path, MAX_CLI_AUX_JSON_INPUT_BYTES) if path else {}


def _add_assessment_id(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("assessment_id")


def _add_revision(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expected-revision", type=int, required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pineai")
    parser.add_argument(
        "--config-dir", help="override /root/.PineAI for development"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("status")
    configure = commands.add_parser("configure")
    configure.add_argument("--language", choices=("en", "fi"))
    configure.add_argument(
        "--share-ssids", choices=("true", "false"), default=None
    )
    configure.add_argument(
        "--set-openai-key",
        action="store_true",
        help="read an OpenAI API key from hidden input",
    )
    commands.add_parser("capabilities")

    assessment = commands.add_parser("assessment")
    assessment_commands = assessment.add_subparsers(
        dest="assessment_command", required=True
    )
    create = assessment_commands.add_parser("create")
    create.add_argument("--input", required=True)
    get = assessment_commands.add_parser("get")
    _add_assessment_id(get)
    get.add_argument("--after-sequence", type=int, default=0)
    get.add_argument("--limit", type=int, default=100)
    listing = assessment_commands.add_parser("list")
    listing.add_argument("--include-archived", action="store_true")
    update = assessment_commands.add_parser("update")
    _add_assessment_id(update)
    _add_revision(update)
    update.add_argument("--input", required=True)
    archive = assessment_commands.add_parser("archive")
    _add_assessment_id(archive)
    _add_revision(archive)

    resolve = commands.add_parser("resolve")
    resolve.add_argument("--input", required=True)
    resolve.add_argument("--metadata")

    baseline = commands.add_parser("baseline")
    baseline_commands = baseline.add_subparsers(
        dest="baseline_command", required=True
    )
    baseline_create = baseline_commands.add_parser("create")
    _add_assessment_id(baseline_create)
    _add_revision(baseline_create)
    baseline_create.add_argument("--input", required=True)
    baseline_create.add_argument("--metadata")
    baseline_create.add_argument("--label", default="")
    baseline_list = baseline_commands.add_parser("list")
    _add_assessment_id(baseline_list)
    baseline_activate = baseline_commands.add_parser("activate")
    _add_assessment_id(baseline_activate)
    _add_revision(baseline_activate)
    baseline_activate.add_argument("baseline_version")

    for name in ("compare", "analyze"):
        command = commands.add_parser(name)
        _add_assessment_id(command)
        if name == "analyze":
            _add_revision(command)
        command.add_argument("--input", required=True)
        command.add_argument("--metadata")

    findings = commands.add_parser("findings")
    finding_commands = findings.add_subparsers(
        dest="finding_command", required=True
    )
    finding_list = finding_commands.add_parser("list")
    _add_assessment_id(finding_list)
    finding_list.add_argument(
        "--status",
        choices=("open", "acknowledged", "false_positive", "resolved"),
    )
    finding_update = finding_commands.add_parser("update")
    _add_assessment_id(finding_update)
    _add_revision(finding_update)
    finding_update.add_argument("finding_id")
    finding_update.add_argument(
        "status", choices=("open", "acknowledged", "false_positive")
    )
    finding_update.add_argument("--note", default="")

    for name in ("prepare-ai", "generate-ai"):
        command = commands.add_parser(name)
        _add_assessment_id(command)
        command.add_argument("comparison_id")
        command.add_argument("--finding-ids")
        command.add_argument("--language", choices=("en", "fi"))
        command.add_argument(
            "--share-ssids", choices=("true", "false"), default=None
        )

    report = commands.add_parser("report")
    _add_assessment_id(report)
    report.add_argument("comparison_id")
    report.add_argument("--format", choices=("json", "html"), required=True)
    report.add_argument("--ai-analysis")
    report.add_argument("--output")

    backup = commands.add_parser("backup")
    backup_commands = backup.add_subparsers(
        dest="backup_command", required=True
    )
    backup_create = backup_commands.add_parser("create")
    backup_create.add_argument("--output", required=True)
    backup_verify = backup_commands.add_parser("verify")
    backup_verify.add_argument("--input", required=True)
    backup_restore = backup_commands.add_parser("restore-staging")
    backup_restore.add_argument("--input", required=True)
    backup_restore.add_argument("--target", required=True)
    return parser


def _ai_options(arguments: argparse.Namespace) -> Dict[str, Any]:
    options = {}
    if getattr(arguments, "language", None):
        options["language"] = arguments.language
    if getattr(arguments, "share_ssids", None) is not None:
        options["share_ssids"] = arguments.share_ssids == "true"
    return options


def _finding_ids(path: Optional[str]) -> Optional[Any]:
    if not path:
        return None
    value = _read_json(path, MAX_CLI_AUX_JSON_INPUT_BYTES)
    if not isinstance(value, list):
        raise BackendError("invalid_input", "finding IDs input must be an array")
    return value


def main(
    argv: Optional[Any] = None,
    stdout: Any = sys.stdout,
    stderr: Any = sys.stderr,
) -> int:
    arguments = build_parser().parse_args(argv)
    config_dir = arguments.config_dir
    if config_dir:
        os.environ["PINEAI_CONFIG_DIR"] = config_dir
    try:
        if arguments.command == "backup":
            if arguments.backup_command == "create":
                result = create_backup(config_dir, arguments.output)
            elif arguments.backup_command == "verify":
                result = verify_backup(arguments.input)
            else:
                result = restore_backup_staging(
                    arguments.input, arguments.target
                )
            _print_json(result, stdout)
            return 0

        store = CustomerAuditStore(config_dir)
        service = AssuranceService(
            config_dir=config_dir,
            store=store,
            ai_service=AssuranceAIService(config_dir),
        )
        if arguments.command == "status":
            _print_json(public_status(config_dir), stdout)
        elif arguments.command == "configure":
            settings = load_settings(config_dir)
            if arguments.language:
                settings["language"] = arguments.language
            if arguments.share_ssids is not None:
                settings["share_ssids"] = arguments.share_ssids == "true"
            save_settings(settings, config_dir)
            if arguments.set_openai_key:
                save_api_key(getpass.getpass("OpenAI API key: "), config_dir)
            _print_json(public_status(config_dir), stdout)
        elif arguments.command == "capabilities":
            _print_json(service.capabilities(), stdout)
        elif arguments.command == "assessment":
            action = arguments.assessment_command
            if action == "create":
                result = service.create_assessment(
                    _read_json(arguments.input)
                )
            elif action == "get":
                result = service.assessment_detail(
                    arguments.assessment_id,
                    arguments.after_sequence,
                    arguments.limit,
                )
            elif action == "list":
                result = {
                    "assessments": store.list(arguments.include_archived)
                }
            elif action == "update":
                result = store.update(
                    arguments.assessment_id,
                    arguments.expected_revision,
                    _read_json(arguments.input),
                )
            else:
                result = store.archive(
                    arguments.assessment_id, arguments.expected_revision
                )
            _print_json(result, stdout)
        elif arguments.command == "resolve":
            _print_json(
                service.resolve_recon(
                    _read_json(arguments.input), _metadata(arguments.metadata)
                ),
                stdout,
            )
        elif arguments.command == "baseline":
            action = arguments.baseline_command
            if action == "create":
                result = service.create_baseline_version(
                    arguments.assessment_id,
                    arguments.expected_revision,
                    _read_json(arguments.input),
                    _metadata(arguments.metadata),
                    arguments.label,
                )
                result["baseline"] = result.pop("baseline_version")
            elif action == "list":
                result = service.list_baseline_versions(
                    arguments.assessment_id
                )
            else:
                result = store.activate_baseline_version(
                    arguments.assessment_id,
                    arguments.expected_revision,
                    arguments.baseline_version,
                )
                result["baseline"] = result.pop("baseline_version")
            _print_json(result, stdout)
        elif arguments.command in ("compare", "analyze"):
            scan = _read_json(arguments.input)
            metadata = _metadata(arguments.metadata)
            if arguments.command == "compare":
                result = service.compare_recon(
                    arguments.assessment_id, scan, metadata
                )
            else:
                result = service.analyze_recon(
                    arguments.assessment_id,
                    arguments.expected_revision,
                    scan,
                    metadata,
                )
            _print_json(result, stdout)
        elif arguments.command == "findings":
            if arguments.finding_command == "list":
                statuses = [arguments.status] if arguments.status else None
                result = {
                    "findings": store.list_findings(
                        arguments.assessment_id, statuses
                    )
                }
            else:
                result = store.update_finding(
                    arguments.assessment_id,
                    arguments.expected_revision,
                    arguments.finding_id,
                    arguments.status,
                    arguments.note,
                )
            _print_json(result, stdout)
        elif arguments.command in ("prepare-ai", "generate-ai"):
            values = (
                arguments.assessment_id,
                arguments.comparison_id,
                _finding_ids(arguments.finding_ids),
                _ai_options(arguments),
            )
            result = (
                service.prepare_ai_analysis(*values)
                if arguments.command == "prepare-ai"
                else service.generate_ai_analysis(*values)
            )
            _print_json(result, stdout)
        elif arguments.command == "report":
            ai_analysis = (
                _read_json(arguments.ai_analysis, MAX_CLI_AUX_JSON_INPUT_BYTES)
                if arguments.ai_analysis
                else None
            )
            result = service.generate_report(
                arguments.assessment_id,
                arguments.comparison_id,
                arguments.format,
                ai_analysis,
            )
            if arguments.output:
                output_path = _write_private_report(
                    arguments.output, result["content"]
                )
                result = dict(result)
                result.pop("content")
                result["output"] = output_path
            _print_json(result, stdout)
        return 0
    except (BackendError, ConfigError) as failure:
        code = getattr(failure, "code", "configuration_error")
        message = getattr(failure, "safe_message", str(failure))
        _print_json({"error": {"code": code, "message": message}}, stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
