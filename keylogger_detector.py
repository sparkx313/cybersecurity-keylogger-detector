#!/usr/bin/env python3
"""Audit PE import tables for APIs sometimes used by keyboard capture tools.

This is a static indicator report. It does not execute files or inspect processes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    import pefile
except ImportError:  # Give a useful message when the dependency is missing.
    pefile = None

SUPPORTED_SUFFIXES = {".exe", ".dll"}

# Imports are clues for a human reviewer, not proof of behavior. Legitimate
# accessibility, input, gaming, and security software can use the same APIs.
API_CATEGORIES = {
    "setwindowshookexa": "Windows keyboard-hook registration",
    "setwindowshookexw": "Windows keyboard-hook registration",
    "getasynckeystate": "Keyboard state polling",
    "getkeystate": "Keyboard state polling",
    "getkeyboardstate": "Keyboard state polling",
    "registerrawinputdevices": "Raw keyboard input registration",
    "getrawinputdata": "Raw keyboard input reading",
}


def decode_name(value: bytes | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_files(paths: list[Path], recursive: bool) -> tuple[list[Path], list[dict[str, str]]]:
    files: dict[str, Path] = {}
    errors: list[dict[str, str]] = []

    for supplied_path in paths:
        path = supplied_path.expanduser()
        if not path.exists():
            errors.append({"path": str(path), "error": "Path does not exist."})
            continue
        if path.is_file():
            if path.suffix.lower() in SUPPORTED_SUFFIXES:
                files[str(path.resolve())] = path
            else:
                errors.append({"path": str(path), "error": "Expected a .exe or .dll file."})
            continue
        if not path.is_dir():
            errors.append({"path": str(path), "error": "Path is not a regular file or directory."})
            continue

        candidates = path.rglob("*") if recursive else path.iterdir()
        found = 0
        try:
            for candidate in candidates:
                if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_SUFFIXES:
                    files[str(candidate.resolve())] = candidate
                    found += 1
        except OSError as exc:
            errors.append({"path": str(path), "error": f"Could not list directory: {exc}"})
        if found == 0:
            errors.append({"path": str(path), "error": "No .exe or .dll files found."})

    return sorted(files.values(), key=lambda item: str(item).casefold()), errors


def import_symbols(pe: Any) -> list[tuple[str, str]]:
    symbols: list[tuple[str, str]] = []
    for table_name in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for module in getattr(pe, table_name, []):
            dll_name = decode_name(getattr(module, "dll", None)) or "<unknown DLL>"
            for imported in getattr(module, "imports", []):
                symbol_name = decode_name(getattr(imported, "name", None))
                if symbol_name:
                    symbols.append((dll_name, symbol_name))
    return symbols


def audit_file(path: Path) -> dict[str, Any]:
    if pefile is None:
        raise RuntimeError("Missing dependency: install requirements with `python -m pip install -r requirements.txt`.")

    digest = sha256_file(path)
    file_size = path.stat().st_size
    pe = pefile.PE(str(path), fast_load=True)
    directories = [
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
    ]
    pe.parse_data_directories(directories=directories)

    all_imports = import_symbols(pe)
    matches: dict[str, list[dict[str, str]]] = {}
    for dll_name, symbol_name in all_imports:
        category = API_CATEGORIES.get(symbol_name.casefold())
        if category:
            item = {"dll": dll_name, "symbol": symbol_name}
            matches.setdefault(category, []).append(item)

    for category in matches:
        matches[category].sort(key=lambda item: (item["dll"].casefold(), item["symbol"].casefold()))

    return {
        "path": str(path),
        "sha256": digest,
        "size_bytes": file_size,
        "machine": f"0x{pe.FILE_HEADER.Machine:04x}",
        "normal_and_delay_import_count": len(all_imports),
        "status": "review-recommended" if matches else "no-matching-imports-observed",
        "indicators": matches,
    }


def render_text(report: dict[str, Any]) -> str:
    lines = ["Static PE keyboard-input import audit", "=" * 38]
    for item in report["files"]:
        label = "REVIEW RECOMMENDED" if item["indicators"] else "NO MATCHING IMPORTS OBSERVED"
        lines.extend([
            f"\n[{label}] {item['path']}",
            f"  SHA-256: {item['sha256']}",
            f"  Size: {item['size_bytes']} bytes | Machine: {item['machine']}",
            f"  Normal and delay imports parsed: {item['normal_and_delay_import_count']}",
        ])
        for category, imports in item["indicators"].items():
            names = ", ".join(f"{entry['dll']}!{entry['symbol']}" for entry in imports)
            lines.append(f"  - {category}: {names}")

    if report["errors"]:
        lines.append("\nInput or parsing errors:")
        lines.extend(f"  - {item['path']}: {item['error']}" for item in report["errors"])

    lines.extend([
        f"\nScanned: {len(report['files'])} file(s); "
        f"indicators: {report['summary']['files_with_indicators']}; "
        f"errors: {len(report['errors'])}.",
        "An import match is a lead for manual review, not proof of a keylogger.",
        "No match does not mean a file is safe; this tool does not execute files or inspect running processes.",
    ])
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Statically report keyboard-input APIs imported by Windows PE files."
    )
    parser.add_argument("paths", nargs="+", type=Path, metavar="PATH", help=".exe/.dll file or directory to inspect")
    parser.add_argument("--recursive", action="store_true", help="search subdirectories when a directory is provided")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format (default: text)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if pefile is None:
        parser.error("pefile is not installed; run `python -m pip install -r requirements.txt`.")

    paths, errors = collect_files(args.paths, args.recursive)
    files: list[dict[str, Any]] = []
    for path in paths:
        try:
            files.append(audit_file(path))
        except Exception as exc:  # Keep auditing remaining files after a malformed input.
            errors.append({"path": str(path), "error": f"{type(exc).__name__}: {exc}"})

    report = {
        "tool": "static-pe-keyboard-api-audit",
        "files": files,
        "errors": errors,
        "summary": {
            "files_scanned": len(files),
            "files_with_indicators": sum(bool(item["indicators"]) for item in files),
        },
        "limitations": [
            "Imports can be unused or belong to legitimate software.",
            "Dynamic API lookup, packing, or other techniques can hide imports.",
            "This report is not a malware verdict and does not establish that a file is safe.",
            "Files are parsed as data and are never executed by this tool.",
        ],
    }

    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))

    if errors:
        return 2
    if report["summary"]["files_with_indicators"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
