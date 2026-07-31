#!/usr/bin/env python3
"""Fail-closed UTF-8, portability, and JSON validation for documentation."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


ROOT = Path(__file__).resolve().parents[1]
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
DOCUMENT_SUFFIXES = {".json", ".md", ".txt"}
MOJIBAKE_MARKERS = (
    "\ufffd",
    "\u00c2",
    "\u00c3",
    "\u00e2\u0080",
    "\u00e2\u009d",
    "\u00e2\u0082",
)
LOCAL_LINK_PATTERNS = (
    re.compile(r"file://", re.IGNORECASE),
    re.compile(r"(?:[A-Za-z]:[\\/]|/mnt/[a-z]/)(?:Users|home)[\\/]"),
)
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def _documentation_paths() -> Iterable[Path]:
    yield ROOT / "README.md"
    for path in sorted((ROOT / "docs").rglob("*")):
        if path.is_file() and path.suffix.lower() in DOCUMENT_SUFFIXES:
            yield path


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _validate_link(path: Path, target: str) -> Optional[str]:
    value = target.strip().split()[0].strip("<>")
    if not value or value.startswith(("#", "http://", "https://", "mailto:")):
        return None
    local = value.split("#", 1)[0].split("?", 1)[0]
    if not local:
        return None
    candidate = (path.parent / local).resolve()
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError:
        return "relative link escapes repository: {0}".format(value)
    if not candidate.exists():
        return "relative link target is missing: {0}".format(value)
    return None


def _validate(path: Path) -> List[str]:
    errors = []
    try:
        payload = path.read_bytes()
    except OSError as failure:
        return ["cannot read document: {0}".format(failure)]
    if len(payload) > MAX_DOCUMENT_BYTES:
        errors.append("document exceeds {0} bytes".format(MAX_DOCUMENT_BYTES))
    if payload.startswith(b"\xef\xbb\xbf"):
        errors.append("UTF-8 BOM is not allowed")
    if b"\r" in payload:
        errors.append("CR or CRLF line endings are not allowed")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as failure:
        return errors + ["document is not valid UTF-8: {0}".format(failure)]
    for index, line in enumerate(text.splitlines(), 1):
        if line.endswith((" ", "\t")):
            errors.append("line {0} has trailing whitespace".format(index))
        if any(ord(character) < 32 and character != "\t" for character in line):
            errors.append("line {0} contains a control character".format(index))
    for marker in MOJIBAKE_MARKERS:
        if marker in text:
            errors.append("probable mojibake marker {0!r}".format(marker))
    for pattern in LOCAL_LINK_PATTERNS:
        if pattern.search(text):
            errors.append("workstation-local link or path is not allowed")
            break
    if path.suffix.lower() == ".json":
        try:
            json.loads(text)
        except ValueError as failure:
            errors.append("invalid JSON: {0}".format(failure))
    if path.suffix.lower() == ".md":
        for match in MARKDOWN_LINK.finditer(text):
            failure = _validate_link(path, match.group(1))
            if failure:
                errors.append(failure)
    return errors


def validate_documents() -> List[Tuple[str, str]]:
    failures = []
    for path in _documentation_paths():
        if not path.is_file():
            failures.append((_relative(path), "required document is missing"))
            continue
        for message in _validate(path):
            failures.append((_relative(path), message))
    return failures


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    arguments = parser.parse_args(argv)
    failures = validate_documents()
    result = {
        "schema_version": "1.0",
        "valid": not failures,
        "failure_count": len(failures),
        "failures": [
            {"path": path, "message": message}
            for path, message in failures
        ],
    }
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    elif failures:
        for path, message in failures:
            print("{0}: {1}".format(path, message), file=sys.stderr)
    else:
        print("Documentation encoding, links, whitespace, and JSON are valid.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
