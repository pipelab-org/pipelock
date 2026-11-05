#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Compare GitHub's published accounts and live grants with the scanner contract.

Only the GitHub REST API is contacted. Redirects, including signed blob URLs,
are never followed. Output contains checked fields, never a URL, query,
response body, exception text, or unknown query key/value.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime
import http.client
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = re.compile(r"productionresultssa[a-z0-9]*\.blob\.core\.windows\.net")
# Signed fields observed 2026-11-05. rscd is artifact-only; sample job logs.
JOB_KEYS = frozenset("rsct se sig ske skoid sks skt sktid skv sp spr sr st sv".split())
RUN_LOG_HOST = "results-receiver.actions.githubusercontent.com"


class SourceError(Exception):
    """The scanner contract could not be read; not upstream drift."""


class APIError(Exception):
    """A fixed, credential-free diagnostic about failed API evidence."""


@dataclass
class Report:
    lines: list[str] = field(default_factory=list)
    drift: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = ["## Actions results grant canary", "", *self.lines]
        for title, messages in (("Drift", self.drift), ("Warning", self.warnings),
                                ("Evidence error", self.errors)):
            lines.extend(f"- {title}: {message}" for message in messages)
        outcome = "FAIL" if self.drift or self.errors else "PASS"
        return "\n".join([*lines, "", f"Result: {outcome}", ""])

    def emit(self, summary: Path | None) -> int:
        text = self.render()
        print(text, end="")
        for title, messages, level in (("Actions results drift", self.drift, "error"),
                                       ("Canary evidence error", self.errors, "error"),
                                       ("Actions results observation", self.warnings, "warning")):
            for message in messages:
                print(f"::{level} title={title}::{message}")
        if summary is not None:
            try:
                with summary.open("a", encoding="utf-8") as output:
                    output.write(text)
            except OSError:
                print("::error title=Canary evidence error::Cannot write markdown summary")
                return 2
        return 2 if self.errors else int(bool(self.drift))


def read_contract(directory: Path) -> tuple[set[str], float, int]:
    """Read literals and the simple duration/alias expressions used by Go."""
    try:
        source = (directory / "credential_audience_actions_results.go").read_text(encoding="utf-8")
        shared = (directory / "credential_audience.go").read_text(encoding="utf-8")
        hosts = re.search(r"var githubActionsResultsHosts = \[\]string\{(.*?)\n\}", source, re.S)
        if hosts is None:
            raise SourceError("Scanner needs the literal Actions results host snapshot")
        body = re.sub(r"//[^\n]*", "", hosts[1])
        literals = re.findall(r'"([^"\\]*)"\s*,', body)
        remainder = re.sub(r'"[^"\\]*"\s*,', "", body)
        if remainder.strip() or not literals or len(set(literals)) != len(literals):
            raise SourceError("Scanner host list is not a unique string-literal snapshot")
        if any(ACCOUNT.fullmatch(host) is None for host in literals):
            raise SourceError("Scanner host snapshot contains an unexpected account format")
        constants = dict(re.findall(r"^const (\w+) = ([^\n]+)", source + "\n" + shared, re.M))
        expression = constants.get("actionsResultsSASMaxLifetime", "")
        if expression in constants:
            expression = constants[expression]
        duration = re.fullmatch(r"(\d+) \* time\.(Hour|Minute|Second)", expression)
        observed = re.search(r"(\d+) seconds on every job-log", source)
        if duration is None or observed is None:
            raise SourceError("Cannot read the scanner SAS cap or observed-window comment")
        cap = int(duration[1]) * {"Hour": 3600, "Minute": 60, "Second": 1}[duration[2]]
        if cap <= 0:
            raise SourceError("Scanner SAS cap must be positive")
        return set(literals), cap, int(observed[1])
    except OSError:
        raise SourceError("Cannot read scanner contract files") from None


def compare_accounts(meta: object, compiled: set[str], report: Report) -> None:
    try:
        domains = meta["domains"]["actions"]
        if not isinstance(domains, list) or not all(isinstance(host, str) for host in domains):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise APIError("Meta API: missing or malformed domains.actions") from None
    published = {host for host in domains if ACCOUNT.fullmatch(host)}
    report.lines.append(f"- Accounts: compiled {len(compiled)}, published {len(published)}")
    for label, changed in (("Added", published - compiled), ("Removed", compiled - published)):
        report.lines.append(f"- {label} accounts: " + (", ".join(sorted(changed)) or "none"))
        if changed:
            report.drift.append(f"{label} results storage accounts: {len(changed)}")


def check_sample(location: str, compiled: set[str], cap: float, observed: int,
                 report: Report) -> None:
    try:
        url = urllib.parse.urlsplit(location)
        port = url.port
        query = urllib.parse.parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        report.drift.append("Job-log redirect is not a valid URL or query")
        return
    if (url.scheme != "https" or url.hostname not in compiled or port not in (None, 443)
            or url.username is not None or url.password is not None or url.fragment):
        report.drift.append("Job-log destination differs from the compiled HTTPS audience")
    else:
        report.lines.append(f"- Job-log account: {url.hostname}")
    if not url.path.startswith("/actions-results/"):
        report.drift.append("Job-log path no longer starts with /actions-results/")
    if set(query) != JOB_KEYS:
        # Unknown names can themselves contain credentials or workflow commands.
        report.drift.append(f"Signed key set changed: {len(set(query) - JOB_KEYS)} added, "
                            f"{len(JOB_KEYS - set(query))} missing (names and values withheld)")
    else:
        report.lines.append("- Signed key set: matches job-log baseline (signature withheld)")
    if any(len(values) != 1 or not values[0] for values in query.values()):
        report.drift.append("SAS fields must each occur once with a nonempty value")
    for key, value in (("sp", "r"), ("sr", "b"), ("spr", "https")):
        if query.get(key) != [value]:
            report.drift.append(f"SAS {key} differs from the read-only HTTPS blob contract")
    try:
        times = [datetime.fromisoformat(query[key][0].replace("Z", "+00:00")) for key in ("st", "se")]
        if any(value.utcoffset() is None for value in times):
            raise ValueError
        lifetime = (times[1] - times[0]).total_seconds()
        if lifetime <= 0:
            raise ValueError
    except (KeyError, IndexError, ValueError, OverflowError):
        report.drift.append("SAS st/se are missing or do not define a positive timezone-aware window")
        return
    report.lines.append(f"- SAS lifetime: {lifetime:g} s; scanner cap: {cap:g} s; "
                        f"Go comment baseline: {observed} s")
    if lifetime > cap:
        report.drift.append("SAS lifetime exceeds the scanner cap")
    elif lifetime != observed:
        report.warnings.append(f"Observed SAS lifetime changed from {observed} s to {lifetime:g} s; within cap")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubAPI:
    def __init__(self, token: str):
        self.token = token
        # Retains the standard environment proxy handler.
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, endpoint: str, *, redirect: bool = False):
        request = urllib.request.Request("https://api.github.com" + endpoint, headers={
            "Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "pipelock-results-grant-canary",
        })
        try:
            with self.opener.open(request, timeout=30) as response:
                if redirect:
                    raise APIError("Download API: expected a redirect, received HTTP 200")
                return json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                if redirect and error.code in (301, 302, 303, 307, 308):
                    location = error.headers.get("Location")
                    if location:
                        return location
                    raise APIError("Download API: redirect has no Location header") from None
                raise APIError(f"GitHub API: HTTP {error.code}; evidence unavailable") from None
        except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
            # Exception strings and error bodies may contain signed URLs.
            raise APIError("GitHub API: network or JSON failure; evidence unavailable") from None


def sample_live(api: GitHubAPI, repository: str, compiled: set[str], cap: float,
                observed: int, report: Report) -> None:
    base = f"/repos/{repository}/actions"
    try:
        runs = api.request(base + "/runs?status=completed&per_page=10")["workflow_runs"]
        for run in runs:
            run_id = run["id"]
            if type(run_id) is not int:
                raise ValueError
            jobs = api.request(f"{base}/runs/{run_id}/jobs?per_page=100")["jobs"]
            for job in jobs:
                if job["status"] != "completed" or job.get("conclusion") != "success" or not job.get("steps"):
                    continue
                job_id = job["id"]
                if type(job_id) is not int:
                    raise ValueError
                location = api.request(f"{base}/jobs/{job_id}/logs", redirect=True)
                report.lines.append(f"- Sample: completed run {run_id}, job {job_id}; redirect not followed")
                check_sample(location, compiled, cap, observed, report)
                run_location = api.request(f"{base}/runs/{run_id}/logs", redirect=True)
                try:
                    run_url = urllib.parse.urlsplit(run_location)
                    expected = run_url.scheme == "https" and run_url.hostname == RUN_LOG_HOST
                except ValueError:
                    expected = False
                if expected:
                    report.lines.append(f"- Run-log archive: {RUN_LOG_HOST} (outside results grant scope)")
                else:
                    report.warnings.append("Run-log archive destination changed (URL withheld); reassess scope")
                return
    except (KeyError, TypeError, ValueError):
        raise APIError("Actions API: malformed run or job evidence") from None
    raise APIError("Actions API: no sampleable completed job in the ten most recent completed runs")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner-dir", type=Path, default=ROOT / "internal/scanner",
                        help="directory containing the scanner Go contract files")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "pipelab-org/pipelock"))
    args = parser.parse_args(argv)
    report = Report()
    try:
        compiled, cap, observed = read_contract(args.scanner_dir)
        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository) is None:
            raise SourceError("Repository must be an owner/name pair")
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            raise APIError("GitHub API: GH_TOKEN or GITHUB_TOKEN is required for job logs")
        api = GitHubAPI(token)
        try:
            compare_accounts(api.request("/meta"), compiled, report)
        except APIError as error:
            report.errors.append(str(error))
        try:
            sample_live(api, args.repository, compiled, cap, observed, report)
        except APIError as error:
            report.errors.append(str(error))
    except (SourceError, APIError) as error:
        report.errors.append(str(error))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    return report.emit(Path(summary) if summary else None)


if __name__ == "__main__":
    raise SystemExit(main())
