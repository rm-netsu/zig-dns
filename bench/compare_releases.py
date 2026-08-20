#!/usr/bin/env python3
"""Compile the current real-data core benchmark against multiple dns releases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import statistics
import subprocess

LINE_RE = re.compile(
    r"^(?P<name>core\.[^:]+): .* "
    r"\((?P<ops>\d+) ops, (?P<bytes>\d+) bytes, (?P<elapsed>\d+) ns\)$"
)


def run(cmd: list[str], *, cwd: pathlib.Path, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def parse_output(text: str) -> dict[str, dict[str, float]]:
    metrics: dict[str, dict[str, float]] = {}
    for line in text.splitlines():
        match = LINE_RE.match(line.strip())
        if not match:
            continue
        ops = int(match.group("ops"))
        byte_count = int(match.group("bytes"))
        elapsed = int(match.group("elapsed"))
        metrics[match.group("name")] = {
            "ns_per_op": elapsed / ops,
            "ops_per_s": ops * 1_000_000_000 / elapsed,
            "mib_per_s": byte_count * 1_000_000_000 / elapsed / (1024 * 1024),
        }
    if not metrics:
        raise RuntimeError(f"benchmark output contained no metrics:\n{text}")
    return metrics


def mad(values: list[float]) -> float:
    median = statistics.median(values)
    return statistics.median(abs(value - median) for value in values)


def median_results(samples: dict[str, list[dict[str, dict[str, float]]]]) -> dict[str, dict[str, dict[str, float]]]:
    result: dict[str, dict[str, dict[str, float]]] = {}
    for revision, runs in samples.items():
        result[revision] = {}
        for metric in runs[0]:
            values = {
                key: [run_metrics[metric][key] for run_metrics in runs]
                for key in ("ns_per_op", "ops_per_s", "mib_per_s")
            }
            result[revision][metric] = {key: statistics.median(series) for key, series in values.items()}
            result[revision][metric]["ops_per_s_mad_pct"] = (
                mad(values["ops_per_s"]) / max(result[revision][metric]["ops_per_s"], 1.0) * 100.0
            )
    return result


def paired_deltas(
    samples: dict[str, list[dict[str, dict[str, float]]]],
    baseline: str,
    candidate: str,
    metric: str,
) -> tuple[float, float]:
    baseline_runs = samples[baseline]
    candidate_runs = samples[candidate]
    if len(baseline_runs) != len(candidate_runs):
        raise RuntimeError(f"paired sample count mismatch: {baseline} vs {candidate}")
    deltas = [
        pct(candidate_run[metric]["ops_per_s"], baseline_run[metric]["ops_per_s"])
        for baseline_run, candidate_run in zip(baseline_runs, candidate_runs)
    ]
    return statistics.median(deltas), mad(deltas)


def pct(candidate: float, baseline: float) -> float:
    return (candidate / baseline - 1.0) * 100.0


def print_table(
    revisions: list[str],
    medians: dict[str, dict[str, dict[str, float]]],
    samples: dict[str, list[dict[str, dict[str, float]]]],
) -> None:
    metric_names = list(medians[revisions[0]])
    baseline = revisions[0]
    for metric in metric_names:
        print(f"\n{metric}")
        print(
            "revision\tns/op\tops/s\tMAD\tMiB/s\tmedian vs baseline\t"
            "paired vs baseline\tpaired vs previous"
        )
        previous = None
        for revision in revisions:
            value = medians[revision][metric]
            vs_baseline = pct(value["ops_per_s"], medians[baseline][metric]["ops_per_s"])
            if revision == baseline:
                paired_baseline = "-"
            else:
                baseline_median, baseline_mad = paired_deltas(samples, baseline, revision, metric)
                paired_baseline = f"{baseline_median:+.2f}% +/- {baseline_mad:.2f}%"
            if previous is None:
                paired_previous = "-"
            else:
                previous_median, previous_mad = paired_deltas(samples, previous, revision, metric)
                paired_previous = f"{previous_median:+.2f}% +/- {previous_mad:.2f}%"
            print(
                f"{revision}\t{value['ns_per_op']:.2f}\t{value['ops_per_s']:.0f}\t"
                f"{value['ops_per_s_mad_pct']:.2f}%\t{value['mib_per_s']:.1f}\t"
                f"{vs_baseline:+.2f}%\t{paired_baseline}\t{paired_previous}"
            )
            previous = revision


def paired_summary(
    revisions: list[str],
    samples: dict[str, list[dict[str, dict[str, float]]]],
) -> dict[str, dict[str, dict[str, float]]]:
    baseline = revisions[0]
    result: dict[str, dict[str, dict[str, float]]] = {}
    for metric in samples[baseline][0]:
        result[metric] = {}
        previous = None
        for revision in revisions:
            entry: dict[str, float] = {}
            if revision != baseline:
                median, spread = paired_deltas(samples, baseline, revision, metric)
                entry["vs_baseline_median_pct"] = median
                entry["vs_baseline_mad_pct"] = spread
            if previous is not None:
                median, spread = paired_deltas(samples, previous, revision, metric)
                entry["vs_previous_median_pct"] = median
                entry["vs_previous_mad_pct"] = spread
            result[metric][revision] = entry
            previous = revision
    return result


def safe_name(revision: str) -> str:
    readable = re.sub(r"[^A-Za-z0-9_.-]+", "_", revision)
    return f"{readable}-{hashlib.sha256(revision.encode()).hexdigest()[:8]}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("revisions", nargs="*", default=["v0.1.0", "v0.2.0", "v0.3.0", "v0.4.0"])
    parser.add_argument("--runs", type=int, default=9)
    parser.add_argument("--round-offset", type=int, default=0)
    parser.add_argument("--cpu", type=int, default=None, help="Pin benchmark processes to this CPU")
    parser.add_argument("--zig", default=os.environ.get("ZIG", "zig"))
    parser.add_argument("--json", type=pathlib.Path, default=None)
    parser.add_argument(
        "--merge-json",
        nargs="+",
        type=pathlib.Path,
        default=None,
        help="Merge raw JSON batches produced by this runner and exit",
    )
    parser.add_argument("--prepare-only", action="store_true", help="Compile stable per-revision binaries and exit")
    parser.add_argument("--reuse-binaries", action="store_true", help="Run previously prepared binaries without recompiling")
    parser.add_argument("--work-dir", type=pathlib.Path, default=None)
    args = parser.parse_args()

    repo = pathlib.Path(__file__).resolve().parents[1]
    benchmark = repo / "bench" / "core.zig"
    corpus_source = repo / "bench" / "real_corpus.zig"
    corpus_dir = repo / "bench" / "corpus"
    benchmark_inputs = [
        benchmark,
        corpus_source,
        *sorted(corpus_dir.glob("*.dns")),
        *sorted(corpus_dir.glob("*.rdata")),
    ]
    digest = hashlib.sha256()
    for path in benchmark_inputs:
        digest.update(path.relative_to(repo).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    benchmark_hash = digest.hexdigest()[:10]
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    if args.prepare_only and args.reuse_binaries:
        parser.error("--prepare-only and --reuse-binaries are mutually exclusive")
    if args.merge_json and (args.prepare_only or args.reuse_binaries):
        parser.error("--merge-json cannot be combined with binary preparation/reuse options")

    if args.merge_json:
        payloads = [json.loads(path.read_text()) for path in args.merge_json]
        revisions = payloads[0]["revisions"]
        cpu = payloads[0].get("cpu")
        zig_version = payloads[0].get("zig_version")
        samples: dict[str, list[dict[str, dict[str, float]]]] = {revision: [] for revision in revisions}
        for payload in payloads:
            if payload["revisions"] != revisions:
                raise RuntimeError("cannot merge batches with different revision order")
            if payload.get("benchmark_hash") != benchmark_hash:
                raise RuntimeError(
                    f"benchmark hash mismatch: expected {benchmark_hash}, got {payload.get('benchmark_hash')}"
                )
            if payload.get("cpu") != cpu:
                raise RuntimeError("cannot merge batches from different CPUs")
            if payload.get("zig_version") != zig_version:
                raise RuntimeError("cannot merge batches from different Zig versions")
            for revision in revisions:
                samples[revision].extend(payload["samples"][revision])

        medians = median_results(samples)
        runs = len(samples[revisions[0]])
        print(f"runs={runs} cpu={cpu if cpu is not None else 'unbound'} benchmark={benchmark_hash}")
        print_table(revisions, medians, samples)
        if args.json is not None:
            merged = {
                "runs": runs,
                "round_offset": None,
                "cpu": cpu,
                "revisions": revisions,
                "benchmark_hash": benchmark_hash,
                "zig_version": zig_version,
                "inputs": [path.relative_to(repo).as_posix() for path in benchmark_inputs],
                "medians": medians,
                "paired": paired_summary(revisions, samples),
                "samples": samples,
            }
            args.json.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n")
        return 0

    cpu = args.cpu
    taskset = shutil.which("taskset")
    if cpu is None and taskset:
        available = sorted(os.sched_getaffinity(0))
        if available:
            cpu = available[-1]

    root_key = hashlib.sha256(str(repo).encode()).hexdigest()[:12]
    base = args.work_dir or (pathlib.Path(tempfile_dir()) / f"zig-dns-bench-{root_key}")
    worktree_base = base / "worktrees"
    binary_base = base / "bin"
    worktree_base.mkdir(parents=True, exist_ok=True)
    binary_base.mkdir(parents=True, exist_ok=True)

    binaries: dict[str, pathlib.Path] = {}
    worktrees: list[pathlib.Path] = []
    try:
        for revision in args.revisions:
            key = safe_name(revision)
            binary = binary_base / f"{key}-{benchmark_hash}"
            binaries[revision] = binary
            if args.reuse_binaries:
                if not binary.exists():
                    raise FileNotFoundError(f"missing prepared benchmark binary for {revision}: {binary}")
                continue

            worktree = worktree_base / key
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(worktree)],
                cwd=repo,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            shutil.rmtree(worktree, ignore_errors=True)
            run(["git", "worktree", "add", "--detach", str(worktree), revision], cwd=repo)
            worktrees.append(worktree)
            run(
                [
                    args.zig,
                    "build-exe",
                    "-OReleaseFast",
                    "--dep",
                    "dns",
                    f"-Mroot={benchmark}",
                    f"-Mdns={worktree / 'src' / 'root.zig'}",
                    f"-femit-bin={binary}",
                ],
                cwd=repo,
            )
            run(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo)
            worktrees.remove(worktree)

        if args.prepare_only:
            for revision in args.revisions:
                print(f"prepared {revision}: {binaries[revision]}")
            return 0

        samples: dict[str, list[dict[str, dict[str, float]]]] = {rev: [] for rev in args.revisions}

        def execute(revision: str) -> dict[str, dict[str, float]]:
            command = [str(binaries[revision])]
            if taskset and cpu is not None:
                command = [taskset, "-c", str(cpu), *command]
            completed = run(command, cwd=repo, capture=True)
            return parse_output(completed.stdout + completed.stderr)

        for revision in args.revisions:
            execute(revision)

        count = len(args.revisions)
        for round_index in range(args.runs):
            absolute_round = args.round_offset + round_index
            shift = absolute_round % count
            order = args.revisions[shift:] + args.revisions[:shift]
            if (absolute_round // count) % 2:
                order = list(reversed(order))
            for revision in order:
                samples[revision].append(execute(revision))
    finally:
        for worktree in reversed(worktrees):
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(worktree)],
                cwd=repo,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    medians = median_results(samples)
    print(f"runs={args.runs} cpu={cpu if cpu is not None else 'unbound'} benchmark={benchmark_hash}")
    print_table(args.revisions, medians, samples)

    if args.json is not None:
        zig_version = run([args.zig, "version"], cwd=repo, capture=True).stdout.strip()
        payload = {
            "runs": args.runs,
            "round_offset": args.round_offset,
            "cpu": cpu,
            "revisions": args.revisions,
            "benchmark_hash": benchmark_hash,
            "zig_version": zig_version,
            "inputs": [path.relative_to(repo).as_posix() for path in benchmark_inputs],
            "medians": medians,
            "paired": paired_summary(args.revisions, samples),
            "samples": samples,
        }
        args.json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


def tempfile_dir() -> str:
    return os.environ.get("TMPDIR", "/tmp")


if __name__ == "__main__":
    raise SystemExit(main())
