#!/usr/bin/env python3
"""wobble - run a shell command N times and report whether it is deterministic.

wobble masks volatile tokens (timestamps, uuids, temp paths, pids, pointers,
hashes, ip:port pairs, ...) before comparing the output of each run, so that
real nondeterminism is visible instead of being drowned out by expected noise.

Zero third-party dependencies. Python 3.9+ standard library only.
"""

import argparse
import concurrent.futures
import difflib
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

__version__ = "1.0.0"

TIMEOUT_SENTINEL = "<WOBBLE-TIMEOUT>"

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Run:
    """A single execution of the command under test."""

    index: int
    stdout: str
    stderr: str
    returncode: Optional[int]
    elapsed: float  # seconds, via time.perf_counter


# ---------------------------------------------------------------------------
# Masking module
# ---------------------------------------------------------------------------
#
# MASKERS is an ORDERED list of (name, compiled_regex, placeholder) tuples.
# Order matters: the most specific / longest patterns run first so they cannot
# be clobbered by broader ones (e.g. a UUID must be consumed before the
# generic hex-hash pattern would eat a piece of it). Placeholders use angle
# brackets which no later pattern matches, so a left-to-right sequential
# application is sufficient to avoid re-substituting inside placeholders.

MASKERS: List[Tuple[str, "re.Pattern[str]", str]] = [
    # 1. ANSI escape sequences - stripped entirely.
    ("ansi", re.compile(r"\x1b\[[0-9;]*[A-Za-z]"), ""),
    # 2. ISO-8601 dates / datetimes (optional T, fractional seconds, tz).
    (
        "iso_ts",
        re.compile(
            r"\d{4}-\d{2}-\d{2}"
            r"(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
            r"(?:Z|[+-]\d{2}:\d{2})?)?"
        ),
        "<TS>",
    ),
    # 3. 13-digit epoch milliseconds (before 10-digit epoch and before hash).
    ("epoch_ms", re.compile(r"\b\d{13}\b"), "<EPOCHMS>"),
    # 4. 10-digit epoch seconds.
    ("epoch_s", re.compile(r"\b\d{10}\b"), "<EPOCH>"),
    # 5. UUID (before the generic hex-hash pattern).
    (
        "uuid",
        re.compile(
            r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"
        ),
        "<UUID>",
    ),
    # 6. Hex pointers like 0x7ffee (before the generic hash pattern).
    ("hexptr", re.compile(r"\b0x[0-9a-fA-F]+\b"), "<PTR>"),
    # 7. Bare hex hashes / sha fragments (7-40 hex chars). Runs after uuid and
    #    hexptr have already been consumed.
    ("sha_hex", re.compile(r"\b[0-9a-fA-F]{7,40}\b"), "<HASH>"),
    # 8. Windows absolute paths.
    ("win_path", re.compile(r"[A-Za-z]:\\[^\s:*?\"<>|]+"), "<PATH>"),
    # 9. Common temp paths.
    (
        "tmp_path",
        re.compile(r"(?:/tmp|/var/folders|%TEMP%|/private/var)[^\s:]*"),
        "<PATH>",
    ),
    # 10. IPv4 with a port.
    ("ip_port", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b"), "<IP:PORT>"),
    # 11. Bare IPv4.
    ("ipv4", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
    # 12. pid=1234 / pid: 1234 / PID 1234.
    ("pid", re.compile(r"(?i)\bpid[=:\s]+\d+"), "pid=<PID>"),
    # 13. localhost:PORT / 127.0.0.1:PORT.
    (
        "localhost_port",
        re.compile(r"(?i)(?:localhost|127\.0\.0\.1):\d+"),
        "<HOST:PORT>",
    ),
]


def mask_text(s: str) -> str:
    """Apply the ordered volatile-token substitutions to *s*."""
    if not s:
        return s
    for _name, pattern, placeholder in MASKERS:
        s = pattern.sub(placeholder, s)
    return s


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_once(cmd: str, index: int, timeout: Optional[float]) -> Run:
    """Execute *cmd* once via the shell and return a populated Run."""
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        elapsed = time.perf_counter() - start
        return Run(
            index=index,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            elapsed=elapsed,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.perf_counter() - start
        # Preserve whatever partial output was captured before the timeout.
        partial_out = exc.stdout or ""
        if isinstance(partial_out, bytes):
            partial_out = partial_out.decode("utf-8", "replace")
        return Run(
            index=index,
            stdout=partial_out,
            stderr=TIMEOUT_SENTINEL,
            returncode=None,
            elapsed=elapsed,
        )


def run_many(
    cmd: str, n: int, parallel: int = 1, timeout: Optional[float] = None
) -> List[Run]:
    """Run *cmd* *n* times, optionally in parallel, returning runs in order."""
    if parallel <= 1:
        return [run_once(cmd, i, timeout) for i in range(n)]

    results: List[Optional[Run]] = [None] * n
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as pool:
        future_to_index = {
            pool.submit(run_once, cmd, i, timeout): i for i in range(n)
        }
        for future in concurrent.futures.as_completed(future_to_index):
            run = future.result()
            results[run.index] = run
    # No None should remain, but keep the type checker and reality honest.
    return [r for r in results if r is not None]


# ---------------------------------------------------------------------------
# Clustering + analysis
# ---------------------------------------------------------------------------

VERDICT_STABLE = "STABLE"
VERDICT_VOLATILE = "VOLATILE-BUT-EQUIVALENT"
VERDICT_FLAKY = "FLAKY"


def _run_key(run: Run, mask: bool) -> str:
    """Compute the clustering hash for a run."""
    if mask:
        out = mask_text(run.stdout)
        err = mask_text(run.stderr)
    else:
        out = run.stdout
        err = run.stderr
    payload = repr((out, err, str(run.returncode))).encode("utf-8")
    return hashlib.sha1(payload).hexdigest()


@dataclass
class Cluster:
    hash: str
    run_indices: List[int] = field(default_factory=list)
    representative: Optional[Run] = None


def cluster_runs(runs: List[Run], mask: bool) -> List[Cluster]:
    """Group runs into equivalence classes keyed by their hash."""
    clusters: dict = {}
    for run in runs:
        key = _run_key(run, mask)
        if key not in clusters:
            clusters[key] = Cluster(hash=key, representative=run)
        clusters[key].run_indices.append(run.index)
    # Stable order: largest class first, ties broken by first run index.
    return sorted(
        clusters.values(),
        key=lambda c: (-len(c.run_indices), min(c.run_indices)),
    )


@dataclass
class Analysis:
    verdict: str
    n: int
    parallel: int
    flake_rate: float
    masked_classes: List[Cluster]
    raw_classes: List[Cluster]
    stdout_varied: bool
    stderr_varied: bool
    exit_varied: bool
    timing_median: float
    timing_min: float
    timing_max: float
    timing_wobbly: bool
    timing_spread: float  # (max-min)/median, ratio; 0 if undefined
    command: str
    note: str = ""


def analyze(
    runs: List[Run],
    cmd: str,
    mask: bool = True,
    timing_tolerance: float = 50.0,
    parallel: int = 1,
) -> Analysis:
    """Cluster runs and derive the verdict + supporting statistics."""
    n = len(runs)

    masked_classes = cluster_runs(runs, mask=mask)
    # Raw clustering is always computed (used to detect volatile-but-equivalent
    # and to drive the diff in that case). If masking is disabled, masked and
    # raw clustering are identical by definition.
    raw_classes = masked_classes if not mask else cluster_runs(runs, mask=False)

    largest = max((len(c.run_indices) for c in masked_classes), default=0)
    flake_rate = 1.0 - (largest / n) if n else 0.0

    # Per-dimension variance across all runs, using masked text when enabled.
    def norm(s: str) -> str:
        return mask_text(s) if mask else s

    stdout_varied = len({norm(r.stdout) for r in runs}) > 1
    stderr_varied = len({norm(r.stderr) for r in runs}) > 1
    exit_varied = len({r.returncode for r in runs}) > 1

    # Timing.
    elapsed = [r.elapsed for r in runs]
    if elapsed:
        t_median = statistics.median(elapsed)
        t_min = min(elapsed)
        t_max = max(elapsed)
    else:
        t_median = t_min = t_max = 0.0
    if t_median > 0:
        spread = (t_max - t_min) / t_median
        timing_wobbly = spread * 100.0 > timing_tolerance
    else:
        spread = 0.0
        timing_wobbly = False

    # Verdict.
    note = ""
    if exit_varied or len(masked_classes) > 1:
        verdict = VERDICT_FLAKY
    elif len(masked_classes) == 1 and len(raw_classes) > 1:
        verdict = VERDICT_VOLATILE
    else:
        verdict = VERDICT_STABLE
        if timing_wobbly:
            note = "(timing wobbly: {:.1f}x spread)".format(spread)

    return Analysis(
        verdict=verdict,
        n=n,
        parallel=parallel,
        flake_rate=flake_rate,
        masked_classes=masked_classes,
        raw_classes=raw_classes,
        stdout_varied=stdout_varied,
        stderr_varied=stderr_varied,
        exit_varied=exit_varied,
        timing_median=t_median,
        timing_min=t_min,
        timing_max=t_max,
        timing_wobbly=timing_wobbly,
        timing_spread=spread,
        command=cmd,
        note=note,
    )


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------

COLORS = {
    VERDICT_STABLE: "\x1b[32m",  # green
    VERDICT_VOLATILE: "\x1b[33m",  # yellow
    VERDICT_FLAKY: "\x1b[31m",  # red
}
COLOR_RESET = "\x1b[0m"


def _colorize(verdict: str, text: str, use_color: bool) -> str:
    if not use_color:
        return text
    code = COLORS.get(verdict, "")
    if not code:
        return text
    return "{}{}{}".format(code, text, COLOR_RESET)


def _varied_list(a: Analysis) -> str:
    dims = []
    if a.stdout_varied:
        dims.append("stdout")
    if a.stderr_varied:
        dims.append("stderr")
    if a.exit_varied:
        dims.append("exit")
    return "[{}]".format(",".join(dims))


def summary_line(a: Analysis, use_color: bool = False) -> str:
    """Build the human one-line summary."""
    timing = "{:.1f}s±{:.1f}s".format(
        a.timing_median, (a.timing_max - a.timing_min) / 2.0
    )
    verdict_text = a.verdict
    if a.note:
        verdict_text = "{} {}".format(a.verdict, a.note)
    line = (
        "{verdict}  n={n}  classes={classes}  "
        "flake_rate={rate:.2f}  varied={varied}  timing={timing}"
    ).format(
        verdict=_colorize(a.verdict, verdict_text, use_color),
        n=a.n,
        classes=len(a.masked_classes),
        rate=a.flake_rate,
        varied=_varied_list(a),
        timing=timing,
    )
    return line


def _cluster_text(cluster: Cluster, runs_by_index: dict, mask: bool) -> str:
    """Reconstruct the (stdout + stderr) text used for a cluster's diff."""
    rep = runs_by_index[cluster.run_indices[0]]
    out = mask_text(rep.stdout) if mask else rep.stdout
    err = mask_text(rep.stderr) if mask else rep.stderr
    combined = out
    if err:
        combined = combined + "\n--- stderr ---\n" + err
    return combined


def build_diff(a: Analysis, runs: List[Run], diff_lines: int) -> str:
    """Produce the minimal unified diff between two differing classes."""
    runs_by_index = {r.index: r for r in runs}

    if a.verdict == VERDICT_VOLATILE:
        # Only masked-away tokens differ: diff the two RAW representatives.
        classes = a.raw_classes
        use_mask = False
    else:
        classes = a.masked_classes
        use_mask = True

    if len(classes) < 2:
        return ""

    # Two largest differing classes.
    class_a, class_b = classes[0], classes[1]
    idx_a = class_a.run_indices[0]
    idx_b = class_b.run_indices[0]

    text_a = _cluster_text(class_a, runs_by_index, use_mask).splitlines()
    text_b = _cluster_text(class_b, runs_by_index, use_mask).splitlines()

    diff = difflib.unified_diff(
        text_a,
        text_b,
        fromfile="run #{}".format(idx_a),
        tofile="run #{}".format(idx_b),
        lineterm="",
    )
    lines = list(diff)
    if diff_lines is not None and len(lines) > diff_lines:
        lines = lines[:diff_lines]
        lines.append("... (truncated)")
    return "\n".join(lines)


def _truncate(s: str, limit: int) -> str:
    if len(s) <= limit:
        return s
    return s[:limit]


def build_json(a: Analysis, runs: List[Run]) -> dict:
    """Produce the structured JSON report."""
    runs_by_index = {r.index: r for r in runs}
    classes = []
    for c in a.masked_classes:
        rep = runs_by_index[c.run_indices[0]]
        classes.append(
            {
                "hash": c.hash,
                "size": len(c.run_indices),
                "run_indices": c.run_indices,
                "sample_stdout": _truncate(rep.stdout, 2000),
            }
        )
    return {
        "verdict": a.verdict,
        "n": a.n,
        "parallel": a.parallel,
        "flake_rate": a.flake_rate,
        "classes": classes,
        "dimensions": {
            "stdout_varied": a.stdout_varied,
            "stderr_varied": a.stderr_varied,
            "exit_varied": a.exit_varied,
        },
        "timing": {
            "median": a.timing_median,
            "min": a.timing_min,
            "max": a.timing_max,
            "wobbly": a.timing_wobbly,
        },
        "command": a.command,
    }


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


def exit_code_for(verdict: str, fail_on: str) -> int:
    """Compute the process exit code from the verdict + CI gate."""
    if fail_on == "none":
        return 0
    if fail_on == "flaky":
        return 1 if verdict == VERDICT_FLAKY else 0
    if fail_on == "volatile":
        return 1 if verdict in (VERDICT_FLAKY, VERDICT_VOLATILE) else 0
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wobble",
        description=textwrap.dedent(
            """\
            Run a shell command N times and report whether it is deterministic.
            Volatile tokens (timestamps, uuids, temp paths, pids, ...) are masked
            before comparison so that real nondeterminism stands out from noise.
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "command",
        nargs="+",
        help="the shell command to run (joined with spaces if multiple tokens)",
    )
    parser.add_argument(
        "-n", "--runs", type=int, default=10, help="number of runs (default 10)"
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="max concurrent runs (default 1)",
    )
    parser.add_argument(
        "--timing-tolerance",
        type=float,
        default=50.0,
        help="percent spread over median before timing counts as wobbly "
        "(default 50.0)",
    )
    parser.add_argument(
        "--no-mask",
        action="store_true",
        help="disable volatile-token normalization (compare raw output)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a structured JSON report instead of the summary line",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "flaky", "volatile"],
        default="none",
        help="CI gate: exit nonzero on the chosen severity (default none)",
    )
    parser.add_argument(
        "--diff-lines",
        type=int,
        default=40,
        help="max lines of the minimal diff to print (default 40)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="per-run timeout in seconds (default: none)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colorization",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress the diff, print only the verdict line",
    )
    parser.add_argument(
        "--version", action="version", version="wobble {}".format(__version__)
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits with code 2 on usage errors; preserve that but keep
        # our contract of "usage errors -> exit 2".
        if exc.code in (0, None):
            return 0
        return 2

    if args.runs < 1:
        sys.stderr.write("wobble: --runs must be >= 1\n")
        return 2
    if args.parallel < 1:
        sys.stderr.write("wobble: --parallel must be >= 1\n")
        return 2

    cmd = " ".join(args.command)
    use_mask = not args.no_mask
    use_color = (not args.no_color) and sys.stdout.isatty()

    try:
        runs = run_many(cmd, args.runs, parallel=args.parallel, timeout=args.timeout)
    except Exception as exc:  # pragma: no cover - defensive
        sys.stderr.write("wobble: error running command: {}\n".format(exc))
        return 2

    a = analyze(
        runs,
        cmd,
        mask=use_mask,
        timing_tolerance=args.timing_tolerance,
        parallel=args.parallel,
    )

    if args.json:
        sys.stdout.write(json.dumps(build_json(a, runs), indent=2) + "\n")
    else:
        sys.stdout.write(summary_line(a, use_color=use_color) + "\n")
        if not args.quiet:
            diff = build_diff(a, runs, args.diff_lines)
            if diff:
                sys.stdout.write(diff + "\n")

    return exit_code_for(a.verdict, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
