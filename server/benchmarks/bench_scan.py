"""Measure the effect of concurrent scanning on audit latency.

The Hacktron CLI is an external binary, so by default this benchmark replaces
the subprocess call with a fixed sleep. That isolates exactly what changed --
how scans are *scheduled* -- from how fast the scanner itself happens to be, and
makes the result reproducible on a machine without the CLI installed.

Pass --real to run against the actually configured HACKTRON_CMD instead.

Usage:
    python benchmarks/bench_scan.py
    python benchmarks/bench_scan.py --snippets 10 --latency 0.5
    python benchmarks/bench_scan.py --real
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.integrations import hacktron  # noqa: E402
from app.integrations.hacktron import scan_with_hacktron  # noqa: E402

SAMPLE_SNIPPET = """
app.get('/item', (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM items WHERE id = ' + id, (err, rows) => {
    res.send(rows);
  });
});
""".strip()


def install_fake_scanner(latency: float) -> None:
    real_run = subprocess.run

    def _run(cmd, **kwargs):
        # Path translation is not what we are measuring; let it run for real.
        if len(cmd) >= 2 and cmd[1] == "wslpath":
            return real_run(cmd, **kwargs)
        time.sleep(latency)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="{}", stderr="")

    hacktron.subprocess.run = _run


def time_scan(snippets: int, workers: int) -> float:
    os.environ["HACKTRON_MAX_WORKERS"] = str(workers)
    tasks = [(f"task-{i}", SAMPLE_SNIPPET) for i in range(snippets)]

    start = time.perf_counter()
    results = scan_with_hacktron(tasks, "javascript")
    elapsed = time.perf_counter() - start

    assert len(results) == snippets, "scan dropped snippets"
    assert [task_id for task_id, _ in results] == [t[0] for t in tasks], "scan reordered results"
    return elapsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snippets", type=int, default=5, help="snippets per audit (default: 5)")
    parser.add_argument(
        "--latency",
        type=float,
        default=0.8,
        help="simulated per-scan latency in seconds (default: 0.8)",
    )
    parser.add_argument("--workers", type=int, default=4, help="parallel worker count (default: 4)")
    parser.add_argument("--real", action="store_true", help="use the configured Hacktron CLI")
    args = parser.parse_args()

    if args.real:
        if not os.getenv("HACKTRON_CMD"):
            print("HACKTRON_CMD is not set; cannot run with --real.", file=sys.stderr)
            return 1
        print(f"Scanner: real CLI ({os.environ['HACKTRON_CMD']})")
    else:
        os.environ["HACKTRON_CMD"] = "hacktron-stub"
        install_fake_scanner(args.latency)
        print(f"Scanner: simulated, {args.latency:.2f}s per scan")

    print(f"Snippets per audit: {args.snippets}\n")

    sequential = time_scan(args.snippets, workers=1)
    parallel = time_scan(args.snippets, workers=args.workers)

    print(f"{'mode':<24}{'workers':>9}{'wall time':>12}")
    print("-" * 45)
    print(f"{'sequential (baseline)':<24}{1:>9}{sequential:>11.2f}s")
    print(f"{'concurrent':<24}{args.workers:>9}{parallel:>11.2f}s")
    print("-" * 45)

    if parallel > 0:
        speedup = sequential / parallel
        reduction = (1 - parallel / sequential) * 100
        print(f"\nSpeedup: {speedup:.2f}x  ({reduction:.0f}% lower audit latency)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
