#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Report main-push CI timings from saved Actions REST API responses.

No network access or repository writes. Input is current-run.json,
current-jobs.json, runs.json and jobs/<run id>.json in --data-dir.
Paginated responses use `gh api --paginate --slurp` (an array of page objects).
Whole-run wall time includes job queues: run_started_at through the last job's
completed_at, never updated_at (which can change after a run finishes).
Job names, including matrix labels, are the historical identity. Renames start
a new history. Only the selected run attempt is measured, including on reruns.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import statistics
import sys
from datetime import datetime, timedelta
from pathlib import Path


# Source: owner-requested CI timing trend specification (2026-11-05).
# These are tunable starting values, not externally validated alert thresholds.
HISTORY_DAYS = 14
REGRESSION_FRACTION = 0.20  # Require >20% to suppress small relative changes.
REGRESSION_SECONDS = 60  # Also require >60s to suppress noisy short jobs.
MIN_JOB_SAMPLES = 5  # Ignore sparse job histories rather than imply confidence.
# Baseline from at most the newest 20 runs in the window. Each run's jobs cost
# about two API pages, and the window can hold 75 main runs: uncapped, five
# reports an hour use about 750 of the token's 1,000 hourly requests, which
# other workflows share. Twenty runs still leave four times MIN_JOB_SAMPLES.
# https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
MAX_HISTORY_RUNS = 20
RUN_PERCENTILE = 0.90  # The requested whole-run p90.
# No external source: named, tunable percentile convention. Linear interpolation
# at (n-1)*p keeps small histories bounded by their measured minimum/maximum.
PERCENTILE_METHOD = "linear"
CI_PATH = ".github/workflows/ci.yaml"


def timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"invalid timestamp: {value!r}")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError(f"timestamp has no timezone: {value!r}")
    return result


def window_start(run: dict) -> datetime:
    return timestamp(run["run_started_at"]) - timedelta(days=HISTORY_DAYS)


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def items(payload, key: str) -> list[dict]:
    """Refuse partial API pages rather than quietly undercount evidence."""
    pages = payload if isinstance(payload, list) else [payload]
    if not pages or any(not isinstance(page, dict) for page in pages):
        raise ValueError(f"invalid {key} response pages")
    result = [item for page in pages for item in page[key]]
    if any(page["total_count"] != len(result) for page in pages):
        raise ValueError(f"incomplete {key} response: got {len(result)} records")
    return result


def is_main_ci(run: dict) -> bool:
    # A run's path can carry an @<ref> suffix; branch and event still decide
    # that it is a main push.
    workflow_path = run["path"].split("@", 1)[0]
    return (workflow_path == CI_PATH and run["head_branch"] == "main"
            and run["event"] == "push" and run["status"] == "completed")


def historical_runs(current: dict, payload) -> list[dict]:
    # Match the REST created filter: a historical run must be created inside
    # the window; reruns of older runs do not introduce older source revisions.
    start, end = window_start(current), timestamp(current["run_started_at"])
    selected = {}
    for run in items(payload, "workflow_runs"):
        if (is_main_ci(run) and run["conclusion"] == "success"
                and run["id"] != current["id"]
                and start <= timestamp(run["created_at"]) < end
                and start <= timestamp(run["run_started_at"]) < end):
            selected[run["id"]] = run
    newest = sorted(selected.values(), key=lambda run: timestamp(run["run_started_at"]), reverse=True)
    return newest[:MAX_HISTORY_RUNS]


def job_records(run: dict, payload) -> dict[str, dict]:
    jobs = items(payload, "jobs")
    result = {}
    for job in jobs:
        if job["run_id"] != run["id"] or job["run_attempt"] != run["run_attempt"]:
            raise ValueError(f"job from wrong run or attempt: {job['name']}")
        if job["name"] in result:
            # Source: owner's rule that no completion time is missing evidence.
            # Reruns can retain queued ghost records alongside a completed job.
            # Missing records add no timing; two completed names are ambiguous.
            if not job.get("completed_at"):
                continue
            if result[job["name"]].get("completed_at"):
                raise ValueError(f"ambiguous duplicate job name: {job['name']}")
        result[job["name"]] = job
    return result


def job_seconds(job: dict, measure_cancelled: bool = False) -> float | None:
    # A cancelled job in a failed main run hit its timeout-minutes; its duration
    # is real evidence. Elsewhere cancelled and skipped jobs have no timing.
    skip = ("skipped",) if measure_cancelled else ("skipped", "cancelled")
    if (job["status"] != "completed" or job["conclusion"] in skip
            or not job.get("started_at") or not job.get("completed_at")):
        return None
    seconds = (timestamp(job["completed_at"]) - timestamp(job["started_at"])).total_seconds()
    if seconds < 0:
        raise ValueError(f"negative job duration: {job['name']}")
    return seconds


def wall_seconds(run: dict, jobs: dict[str, dict]) -> float | None:
    # A completed job with no end time leaves the run's end unknown; a wall time
    # from the remaining jobs would end early and skew the median and p90.
    if any(job["status"] == "completed" and job["conclusion"] != "skipped"
           and not job.get("completed_at") for job in jobs.values()):
        return None
    ends = [timestamp(job["completed_at"]) for job in jobs.values()
            if job.get("completed_at")]
    if not ends:
        return None
    seconds = (max(ends) - timestamp(run["run_started_at"])).total_seconds()
    if seconds < 0:
        raise ValueError(f"negative run wall time: {run['id']}")
    return seconds


def percentile(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * RUN_PERCENTILE
    lower, upper = math.floor(position), math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def compute(directory: Path) -> dict:
    current = read_json(directory / "current-run.json")
    if not is_main_ci(current):
        raise ValueError("current run must be a completed main-push ci.yaml run")
    if current.get("conclusion") == "cancelled":
        # ci.yaml cancels a main run when a newer push supersedes it; its jobs
        # stopped part way, so any timing from it would be wrong.
        raise ValueError("current run was cancelled; a superseded run has no complete timing")
    current_payload = read_json(directory / "current-jobs.json")
    jobs = job_records(current, current_payload)
    samples: dict[str, list[float]] = {}
    walls = []
    history = historical_runs(current, read_json(directory / "runs.json"))
    accepted_ids = []
    for run in history:
        prior = job_records(run, read_json(directory / "jobs" / f"{run['id']}.json"))
        # A run started earlier can still have finished after the measured run
        # began. Exclude that overlapping/future evidence on delayed dispatches.
        ends = [timestamp(job["completed_at"]) for job in prior.values()
                if job.get("completed_at")]
        if ends and max(ends) >= timestamp(current["run_started_at"]):
            continue
        accepted_ids.append(run["id"])
        wall = wall_seconds(run, prior)
        if wall is not None:
            walls.append(wall)
        for name, job in prior.items():
            duration = job_seconds(job)
            if duration is not None and job["conclusion"] == "success":
                samples.setdefault(name, []).append(duration)
    rows = []
    for name, job in jobs.items():
        values = samples.get(name, [])
        duration = job_seconds(job, measure_cancelled=current["conclusion"] == "failure")
        median = statistics.median(values) if values else None
        delta = duration - median if duration is not None and median is not None else None
        # Comparing seconds also handles a legitimate zero-second median without
        # dividing by zero. A relative percentage is undefined in that case.
        regressed = (len(values) >= MIN_JOB_SAMPLES and delta is not None
                     and delta > REGRESSION_SECONDS and delta > median * REGRESSION_FRACTION)
        rows.append({"name": name, "conclusion": job["conclusion"], "seconds": duration,
                     "samples": len(values), "median_seconds": median,
                     "delta_seconds": delta,
                     "delta_percent": delta / median * 100 if delta is not None and median else None,
                     "regressed": regressed})
    rows.sort(key=lambda row: (not row["regressed"], -(row["seconds"] or 0), row["name"]))
    # Source: Actions REST job conclusions. Keep all non-neutral failures visible,
    # including timed_out/action_required, rather than only literal "failure".
    # https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run
    failed = [job["name"] for job in items(current_payload, "jobs")
              if job["conclusion"] not in (None, "success", "skipped", "cancelled", "neutral")]
    # A job that hits its timeout-minutes ends "cancelled", not "failure". A
    # superseded main run is cancelled whole and refused above, so in a failed
    # main run a cancelled job is a timeout, and hiding it would hide why main
    # went red.
    if current["conclusion"] == "failure":
        failed += [job["name"] + " (cancelled)" for job in items(current_payload, "jobs")
                   if job["conclusion"] == "cancelled"]
    return {"run_id": current["id"], "run_attempt": current["run_attempt"],
            "conclusion": current["conclusion"], "failed_jobs": sorted(set(failed)),
            "history_run_ids": sorted(accepted_ids),
            "window_start": window_start(current).isoformat(),
            "window_end": current["run_started_at"],
            "thresholds": {"history_days": HISTORY_DAYS, "max_history_runs": MAX_HISTORY_RUNS,
                           "regression_fraction": REGRESSION_FRACTION,
                           "regression_seconds": REGRESSION_SECONDS, "min_job_samples": MIN_JOB_SAMPLES,
                           "run_percentile": RUN_PERCENTILE, "percentile_method": PERCENTILE_METHOD},
            "wall": {"seconds": wall_seconds(current, jobs), "samples": len(walls),
                     "median_seconds": statistics.median(walls) if walls else None,
                     "p90_seconds": percentile(walls)}, "jobs": rows}


def cell(value: str) -> str:
    # Metadata is data, including job names that look like Markdown/HTML.
    return html.escape(value).replace("|", "&#124;").replace("\r", " ").replace("\n", " ")


def annotation(value: str) -> str:
    # GitHub workflow-command escaping; newlines must not create new commands.
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def minutes(value: float | None) -> str:
    return "missing" if value is None else f"{value / 60:.1f} min"


def summary(report: dict) -> str:
    lines = ["## Main CI timing", ""]
    if report["conclusion"] != "success":
        lines.extend([f"**CI conclusion: {cell(report['conclusion'])}.**",
                      "Failed jobs: " + (", ".join(cell(name) for name in report["failed_jobs"])
                                         or "none reported by the jobs API"), ""])
    lines.extend([f"Run {report['run_id']}, attempt {report['run_attempt']}. "
                  f"Baseline: previous {HISTORY_DAYS} days of successful main-push CI.", "",
                  "Wall time includes queues from run start through the last completed job.", "",
                  "| Run wall time | Historical median | Historical p90 | Samples |",
                  "| --- | --- | --- | --- |"])
    wall = report["wall"]
    lines.extend([f"| {minutes(wall['seconds'])} | {minutes(wall['median_seconds'])} | "
                  f"{minutes(wall['p90_seconds'])} | {wall['samples']} |", "",
                  f"Regression requires both >{REGRESSION_FRACTION:.0%} and >{REGRESSION_SECONDS}s "
                  f"above the job median, with at least {MIN_JOB_SAMPLES} samples. "
                  "Regressions first, then slowest jobs. Missing timings are never zero.", "",
                  "| Job | Conclusion | Duration | Median | Samples | Change | Result |",
                  "| --- | --- | --- | --- | --- | --- | --- |"])
    for row in report["jobs"]:
        change = (f"{row['delta_seconds']:+g}s" if row["delta_seconds"] is not None else "n/a")
        if row["delta_percent"] is not None:
            change += f" ({row['delta_percent']:+.1f}%)"
        result = "REGRESSED" if row["regressed"] else "within threshold"
        if row["seconds"] is None:
            result = "missing timing"
        if row["samples"] < MIN_JOB_SAMPLES:
            result = ("missing timing; " if row["seconds"] is None else "") + \
                f"ignored (<{MIN_JOB_SAMPLES} historical samples)"
        lines.append(f"| {cell(row['name'])} | {cell(row['conclusion'] or 'unknown')} | "
                     f"{minutes(row['seconds'])} | {minutes(row['median_seconds'])} | "
                     f"{row['samples']} | {change} | {result} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--window-start", type=Path, help="print API history cutoff for a run JSON file")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.window_start:
            print(window_start(read_json(args.window_start)).isoformat())
            return 0
        if not all((args.data_dir, args.output, args.summary)):
            parser.error("--data-dir, --output and --summary are required")
        report = compute(args.data_dir)
        args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        rendered = summary(report)
        with args.summary.open("a", encoding="utf-8") as stream:
            stream.write(rendered)
        print(rendered, end="")
        for row in report["jobs"]:
            if row["regressed"]:
                print("::warning title=CI timing regression::" + annotation(
                    f"{row['name']}: {row['seconds']:g}s, median {row['median_seconds']:g}s "
                    f"({row['delta_seconds']:+g}s; {row['samples']} samples)"))
        return 0  # Regression and CI failure are reports, never gates.
    except (OSError, ValueError, KeyError, TypeError) as error:
        message = f"Cannot compute CI timing report: {error}"
        print("::error title=CI timing report::" + annotation(message), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
