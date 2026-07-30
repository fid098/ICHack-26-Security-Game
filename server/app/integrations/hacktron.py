from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

EXTENSIONS = {
    "javascript": ".js",
    "python": ".py",
    "java": ".java",
    "go": ".go",
    "php": ".php",
}

DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_WORKERS = 4

NOT_CONFIGURED_MESSAGE = (
    "Hacktron CLI is not configured (HACKTRON_CMD unset); "
    "static analysis was skipped for this snippet."
)


def scan_with_hacktron(tasks: Iterable[tuple[str, str]], language: str) -> list[tuple[str, str]]:
    """Scan each snippet with the Hacktron CLI, returning (task_id, log) in input order.

    Scans run concurrently: each is an independent subprocess that spends nearly
    all its wall time blocked on the scanner, so a batch of N snippets costs
    roughly one scan rather than N. A failing scan yields an error string for
    that task instead of aborting the batch, so one bad snippet cannot cost the
    player their entire audit.
    """
    task_list = list(tasks)
    if not task_list:
        return []

    command = os.getenv("HACKTRON_CMD")
    if not command:
        return [(task_id, NOT_CONFIGURED_MESSAGE) for task_id, _ in task_list]

    args = shlex.split(os.getenv("HACKTRON_ARGS", ""))
    extension = EXTENSIONS.get(language, ".txt")
    use_wsl = command.lower() == "wsl"
    workers = min(_max_workers(), len(task_list))

    def scan_one(task: tuple[str, str]) -> tuple[str, str]:
        task_id, code = task
        try:
            return task_id, _scan_snippet(task_id, code, command, args, extension, use_wsl)
        except RuntimeError as exc:
            return task_id, f"Hacktron scan failed: {exc}"

    # ThreadPoolExecutor.map preserves the ordering of its input iterable.
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(scan_one, task_list))


def _scan_snippet(
    task_id: str,
    code: str,
    command: str,
    args: list[str],
    extension: str,
    use_wsl: bool,
) -> str:
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = Path(temp_dir) / f"{task_id}{extension}"
        file_path.write_text(code, encoding="utf-8")

        target_path = _to_wsl_path(file_path) if use_wsl else str(file_path)
        return _run_command([command] + _expand_args(args, target_path))


def _max_workers() -> int:
    try:
        workers = int(os.getenv("HACKTRON_MAX_WORKERS", str(DEFAULT_MAX_WORKERS)))
    except ValueError:
        return DEFAULT_MAX_WORKERS
    return max(1, workers)


def _timeout() -> int:
    try:
        timeout = int(os.getenv("HACKTRON_TIMEOUT", str(DEFAULT_TIMEOUT_SECONDS)))
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return max(1, timeout)


def _expand_args(args: list[str], file_path: str) -> list[str]:
    if not args:
        return [file_path]
    if any("{file}" in arg for arg in args):
        return [arg.replace("{file}", file_path) for arg in args]
    return args + [file_path]


def _run_command(cmd: list[str]) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=_timeout()
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Hacktron command timed out: {' '.join(cmd)}") from exc
    except FileNotFoundError as exc:
        raise RuntimeError(f"Hacktron command not found: {cmd[0]}") from exc

    if result.returncode != 0:
        error_msg = result.stderr.strip() or "Hacktron CLI failed with no error message"
        raise RuntimeError(f"Hacktron failed (exit code {result.returncode}): {error_msg}")

    return (result.stdout or "").strip()


def _to_wsl_path(path: Path) -> str:
    cmd = ["wsl", "wslpath", "-a", str(path)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Failed to convert Windows path for WSL (timeout).") from exc
    except FileNotFoundError as exc:
        raise RuntimeError("WSL not found. Ensure WSL is installed and available.") from exc

    if result.returncode != 0:
        error_msg = result.stderr.strip() or "WSL path conversion failed."
        raise RuntimeError(error_msg)

    return result.stdout.strip()
