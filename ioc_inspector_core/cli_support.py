"""Interactive settings, file selection, and batch accounting for the CLI."""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import click

from . import SUPPORTED_EXTENSIONS
from .report_generator import REPORT_EXTENSIONS


@dataclass
class ScanOptions:
    files: tuple[Path, ...]
    directory: Path | None
    formats: list[str]
    output_dir: Path
    extensions: set[str] | None
    max_size_mb: int
    threads: int
    offline: bool
    batch_report: bool


def parse_extensions(value: str) -> set[str]:
    extensions = {"." + item.strip().lower().lstrip(".") for item in value.split(",") if item.strip()}
    invalid = extensions - SUPPORTED_EXTENSIONS
    if not extensions or invalid:
        raise click.BadParameter(
            "Use a comma-separated list of: " + ", ".join(sorted(SUPPORTED_EXTENSIONS))
        )
    return extensions


def parse_formats(value: str) -> list[str]:
    formats = list(dict.fromkeys(item.strip().lower() for item in value.split(",") if item.strip()))
    if set(formats) - REPORT_EXTENSIONS.keys():
        raise click.BadParameter("Choose from: " + ", ".join(REPORT_EXTENSIONS))
    return formats


def interactive_options(options: ScanOptions) -> ScanOptions:
    click.echo("IOC Inspector - interactive scan")
    if not (options.files or options.directory):
        mode = click.prompt("Scan a file or folder", type=click.Choice(["file", "folder"]), default="file")
        path = click.prompt(
            "Document path" if mode == "file" else "Folder path",
            type=click.Path(exists=True, file_okay=mode == "file", dir_okay=mode == "folder", path_type=Path),
        )
        if mode == "file":
            options.files = (path,)
        else:
            options.directory = path
    options.formats = click.prompt(
        "Report formats (comma separated; 'none' disables per-file reports)",
        default=",".join(options.formats) or "none",
        value_proc=lambda text: [] if text.strip().lower() == "none" else parse_formats(text),
    )
    options.output_dir = click.prompt(
        "Output directory", default=str(options.output_dir),
        type=click.Path(file_okay=False, path_type=Path),
    )
    options.threads = click.prompt("Worker threads", default=options.threads, type=click.IntRange(1, 32))
    options.extensions = click.prompt(
        "Document extensions (comma separated)",
        default=",".join(sorted(extension.lstrip(".") for extension in options.extensions or SUPPORTED_EXTENSIONS)),
        value_proc=parse_extensions,
    )
    options.max_size_mb = click.prompt(
        "Maximum file size in MiB (0 = unlimited)", default=options.max_size_mb, type=click.IntRange(min=0),
    )
    options.offline = click.confirm("Use offline mode (skip reputation services)?", default=options.offline)
    options.batch_report = click.confirm("Write a combined JSON batch report?", default=options.batch_report)
    return options


def select_targets(options: ScanOptions, log_dir: Path) -> tuple[list[Path], list[dict]]:
    """Prune generated directories and record every omitted or unreadable item."""
    targets: list[Path] = []
    records: list[dict] = []
    seen: set[Path] = set()
    generated_extensions = {"." + ext for ext in REPORT_EXTENSIONS.values()}

    def add(path: Path, explicit: bool = False) -> None:
        try:
            resolved = path.resolve()
        except (OSError, RuntimeError) as exc:
            records.append({"source": str(path), "status": "error", "error_stage": "selection", "error": str(exc)})
            return
        if resolved in seen:
            return
        seen.add(resolved)
        reason = ""
        if (path.stem.endswith("_report") or path.name == "batch_summary.json") and path.suffix.lower() in generated_extensions:
            reason = "generated_report"
        elif options.extensions is not None and path.suffix.lower() not in options.extensions:
            reason = "extension_filter"
        elif not explicit and path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            reason = "unsupported_extension"
        try:
            if not reason and options.max_size_mb and path.stat().st_size > options.max_size_mb * 1024 * 1024:
                reason = "size_limit"
        except OSError as exc:
            records.append({"source": str(path), "status": "error", "error_stage": "selection", "error": str(exc)})
            return
        if reason:
            records.append({"source": str(path), "status": "skipped", "reason": reason})
        else:
            targets.append(path)

    for path in options.files:
        add(path, explicit=True)
    if options.directory is not None:
        root = options.directory.resolve()
        excluded = {options.output_dir.resolve(), log_dir.resolve()}
        names = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "reports", "logs"}

        def walk_error(exc: OSError) -> None:
            records.append({"source": str(exc.filename), "status": "error", "error_stage": "selection", "error": str(exc)})

        for current, directories, files in os.walk(root, onerror=walk_error, followlinks=False):
            current_path = Path(current)
            keep = []
            for name in sorted(directories):
                child = current_path / name
                if child.is_symlink() or name in names or child.resolve() in excluded:
                    records.append({"source": str(child), "status": "skipped", "reason": "excluded_directory"})
                else:
                    keep.append(name)
            directories[:] = keep
            for name in sorted(files):
                add(current_path / name)
    return targets, records


def summarize_scan(records: list[dict]) -> dict[str, int]:
    verdicts = Counter(item["result"]["verdict"] for item in records if "result" in item)
    return {
        "scanned": sum("result" in item for item in records),
        "errors": sum(item["status"] == "error" for item in records),
        "skipped": sum(item["status"] == "skipped" for item in records),
        **{verdict: verdicts[verdict] for verdict in ("benign", "suspicious", "malicious", "unknown")},
    }
