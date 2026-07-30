from __future__ import annotations

import subprocess
import threading
import time

import pytest

from app.integrations import hacktron
from app.integrations.hacktron import (
    NOT_CONFIGURED_MESSAGE,
    _expand_args,
    _max_workers,
    _timeout,
    scan_with_hacktron,
)


def fake_run(stdout: str = "{}", returncode: int = 0, stderr: str = "", delay: float = 0.0):
    """Build a subprocess.run replacement that records the commands it receives."""
    calls: list[list[str]] = []

    def _run(cmd, **kwargs):
        calls.append(cmd)
        if delay:
            time.sleep(delay)
        return subprocess.CompletedProcess(
            args=cmd, returncode=returncode, stdout=stdout, stderr=stderr
        )

    _run.calls = calls
    return _run


class TestExpandArgs:
    def test_no_args_returns_bare_path(self):
        assert _expand_args([], "/tmp/a.js") == ["/tmp/a.js"]

    def test_placeholder_is_substituted(self):
        args = ["hacktron", "--format", "json", "{file}"]
        assert _expand_args(args, "/tmp/a.js") == ["hacktron", "--format", "json", "/tmp/a.js"]

    def test_path_is_appended_when_no_placeholder(self):
        assert _expand_args(["--format", "json"], "/tmp/a.js") == ["--format", "json", "/tmp/a.js"]

    def test_placeholder_substituted_in_every_occurrence(self):
        assert _expand_args(["{file}", "--diff", "{file}"], "/x.js") == ["/x.js", "--diff", "/x.js"]


class TestConfiguration:
    def test_missing_command_degrades_instead_of_raising(self, monkeypatch):
        monkeypatch.delenv("HACKTRON_CMD", raising=False)

        results = scan_with_hacktron([("t1", "code"), ("t2", "code")], "javascript")

        assert [task_id for task_id, _ in results] == ["t1", "t2"]
        assert all(log == NOT_CONFIGURED_MESSAGE for _, log in results)

    def test_empty_task_list_short_circuits(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "hacktron")
        assert scan_with_hacktron([], "javascript") == []

    @pytest.mark.parametrize(
        "value,expected", [("8", 8), ("1", 1), ("0", 1), ("-4", 1), ("nonsense", 4), ("", 4)]
    )
    def test_max_workers_parsing(self, monkeypatch, value, expected):
        monkeypatch.setenv("HACKTRON_MAX_WORKERS", value)
        assert _max_workers() == expected

    @pytest.mark.parametrize(
        "value,expected", [("60", 60), ("1", 1), ("0", 1), ("bad", 30), ("", 30)]
    )
    def test_timeout_parsing(self, monkeypatch, value, expected):
        monkeypatch.setenv("HACKTRON_TIMEOUT", value)
        assert _timeout() == expected

    def test_timeout_is_passed_to_subprocess(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "hacktron")
        monkeypatch.setenv("HACKTRON_TIMEOUT", "7")
        seen = {}

        def _run(cmd, **kwargs):
            seen.update(kwargs)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr(hacktron.subprocess, "run", _run)
        scan_with_hacktron([("t1", "code")], "javascript")

        assert seen["timeout"] == 7


class TestScanning:
    def test_returns_stdout_per_task(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "hacktron")
        monkeypatch.setattr(hacktron.subprocess, "run", fake_run(stdout="  findings  "))

        results = scan_with_hacktron([("t1", "a"), ("t2", "b")], "javascript")

        assert results == [("t1", "findings"), ("t2", "findings")]

    def test_order_is_preserved_under_concurrency(self, monkeypatch):
        """Slow the first task so a naive as-completed implementation would reorder."""
        monkeypatch.setenv("HACKTRON_CMD", "hacktron")
        monkeypatch.setenv("HACKTRON_MAX_WORKERS", "4")

        def _run(cmd, **kwargs):
            # The temp filename carries the task id, so slow down only t1.
            if any("t1" in part for part in cmd):
                time.sleep(0.15)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr(hacktron.subprocess, "run", _run)
        tasks = [(f"t{i}", "code") for i in range(1, 5)]

        results = scan_with_hacktron(tasks, "javascript")

        assert [task_id for task_id, _ in results] == ["t1", "t2", "t3", "t4"]

    def test_scans_actually_run_in_parallel(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "hacktron")
        monkeypatch.setenv("HACKTRON_MAX_WORKERS", "4")

        lock = threading.Lock()
        state = {"active": 0, "peak": 0}

        def _run(cmd, **kwargs):
            with lock:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            time.sleep(0.05)
            with lock:
                state["active"] -= 1
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr(hacktron.subprocess, "run", _run)
        scan_with_hacktron([(f"t{i}", "code") for i in range(4)], "javascript")

        assert state["peak"] > 1, "scans ran sequentially"

    def test_worker_count_is_capped_by_task_count(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "hacktron")
        monkeypatch.setenv("HACKTRON_MAX_WORKERS", "16")

        lock = threading.Lock()
        state = {"active": 0, "peak": 0}

        def _run(cmd, **kwargs):
            with lock:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            time.sleep(0.05)
            with lock:
                state["active"] -= 1
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr(hacktron.subprocess, "run", _run)
        scan_with_hacktron([("t1", "code"), ("t2", "code")], "javascript")

        assert state["peak"] <= 2

    def test_language_selects_file_extension(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "hacktron")
        runner = fake_run()
        monkeypatch.setattr(hacktron.subprocess, "run", runner)

        scan_with_hacktron([("t1", "print(1)")], "python")

        assert runner.calls[0][-1].endswith("t1.py")

    def test_unknown_language_falls_back_to_txt(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "hacktron")
        runner = fake_run()
        monkeypatch.setattr(hacktron.subprocess, "run", runner)

        scan_with_hacktron([("t1", "code")], "brainfuck")

        assert runner.calls[0][-1].endswith("t1.txt")

    def test_snippet_is_written_to_a_temp_file_that_is_cleaned_up(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "hacktron")
        observed = {}

        def _run(cmd, **kwargs):
            path = cmd[-1]
            observed["path"] = path
            with open(path, encoding="utf-8") as handle:
                observed["contents"] = handle.read()
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr(hacktron.subprocess, "run", _run)
        scan_with_hacktron([("t1", "el.innerHTML = x;")], "javascript")

        assert observed["contents"] == "el.innerHTML = x;"
        assert not __import__("os").path.exists(observed["path"])


class TestFaultIsolation:
    def test_failing_scan_does_not_abort_the_batch(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "hacktron")

        def _run(cmd, **kwargs):
            if any("t2" in part for part in cmd):
                return subprocess.CompletedProcess(
                    args=cmd, returncode=2, stdout="", stderr="boom"
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="clean", stderr="")

        monkeypatch.setattr(hacktron.subprocess, "run", _run)

        results = dict(scan_with_hacktron([("t1", "a"), ("t2", "b"), ("t3", "c")], "javascript"))

        assert results["t1"] == "clean"
        assert results["t3"] == "clean"
        assert "Hacktron scan failed" in results["t2"]
        assert "boom" in results["t2"]

    def test_nonzero_exit_without_stderr_still_reports(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "hacktron")
        monkeypatch.setattr(
            hacktron.subprocess, "run", fake_run(returncode=1, stdout="", stderr="   ")
        )

        (_, log), = scan_with_hacktron([("t1", "a")], "javascript")

        assert "no error message" in log

    def test_timeout_is_reported_per_task(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "hacktron")

        def _run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)

        monkeypatch.setattr(hacktron.subprocess, "run", _run)

        (_, log), = scan_with_hacktron([("t1", "a")], "javascript")

        assert "timed out" in log

    def test_missing_binary_is_reported_per_task(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "hacktron-does-not-exist")

        def _run(cmd, **kwargs):
            raise FileNotFoundError(cmd[0])

        monkeypatch.setattr(hacktron.subprocess, "run", _run)

        (_, log), = scan_with_hacktron([("t1", "a")], "javascript")

        assert "not found" in log


class TestWslPathTranslation:
    """Windows hosts reach the scanner through WSL, so paths need converting."""

    def test_wsl_command_converts_the_path_before_scanning(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "wsl")
        monkeypatch.setenv("HACKTRON_ARGS", "hacktron --format json {file}")
        seen = []

        def _run(cmd, **kwargs):
            seen.append(cmd)
            if cmd[:2] == ["wsl", "wslpath"]:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="/mnt/c/tmp/t1.js\n", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr(hacktron.subprocess, "run", _run)

        results = scan_with_hacktron([("t1", "code")], "javascript")

        assert results == [("t1", "ok")]
        assert seen[-1] == ["wsl", "hacktron", "--format", "json", "/mnt/c/tmp/t1.js"]

    def test_conversion_is_case_insensitive_on_the_command(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "WSL")

        def _run(cmd, **kwargs):
            if cmd[:2] == ["WSL", "wslpath"] or cmd[:2] == ["wsl", "wslpath"]:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="/mnt/c/x.js", stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr(hacktron.subprocess, "run", _run)

        assert scan_with_hacktron([("t1", "code")], "javascript") == [("t1", "ok")]

    def test_conversion_failure_is_reported_per_task(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "wsl")

        def _run(cmd, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout="", stderr="bad path"
            )

        monkeypatch.setattr(hacktron.subprocess, "run", _run)

        (_, log), = scan_with_hacktron([("t1", "code")], "javascript")

        assert "bad path" in log

    def test_conversion_failure_without_stderr_still_reports(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "wsl")

        def _run(cmd, **kwargs):
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

        monkeypatch.setattr(hacktron.subprocess, "run", _run)

        (_, log), = scan_with_hacktron([("t1", "code")], "javascript")

        assert "WSL path conversion failed" in log

    def test_conversion_timeout_is_reported_per_task(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "wsl")

        def _run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=10)

        monkeypatch.setattr(hacktron.subprocess, "run", _run)

        (_, log), = scan_with_hacktron([("t1", "code")], "javascript")

        assert "timeout" in log.lower()

    def test_missing_wsl_is_reported_per_task(self, monkeypatch):
        monkeypatch.setenv("HACKTRON_CMD", "wsl")

        def _run(cmd, **kwargs):
            raise FileNotFoundError("wsl")

        monkeypatch.setattr(hacktron.subprocess, "run", _run)

        (_, log), = scan_with_hacktron([("t1", "code")], "javascript")

        assert "WSL not found" in log
