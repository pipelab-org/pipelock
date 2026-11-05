# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Fixture contracts for the read-only Actions results grant canary."""

import contextlib
import copy
from datetime import datetime, timedelta
from email.message import Message
import io
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request
import urllib.response

import yaml

from scripts import actions_results_grant_canary as canary
from scripts.yaml_contracts import WorkflowLoader

FIXTURE = json.loads((Path(__file__).parent / "fixtures/actions_results_grant_canary/sample.json").read_text())
HOST = "productionresultssa17.blob.core.windows.net"
SECRET = "fixture-signature-never-output"
SOURCE = '''var githubActionsResultsHosts = []string{
    "productionresultssa17.blob.core.windows.net",
}
// 605 seconds on every job-log and artifact redirect sampled 2026-11-05.
const actionsResultsSASMaxLifetime = attestationBundleSASMaxLifetime
'''
SHARED = "const attestationBundleSASMaxLifetime = 24 * time.Hour\n"


def altered_url(**changes):
    url = urllib.parse.urlsplit(FIXTURE["job_location"])
    query = urllib.parse.parse_qs(url.query)
    for key, value in changes.items():
        if value is None:
            query.pop(key, None)
        else:
            query[key] = value if isinstance(value, list) else [value]
    return url._replace(query=urllib.parse.urlencode(query, doseq=True)).geturl()


def sample_api():
    api = mock.Mock()
    def request(endpoint, **kwargs):
        return copy.deepcopy({
            "/meta": FIXTURE["meta"],
            "/repos/pipelab-org/pipelock/actions/runs?status=completed&per_page=10": FIXTURE["runs"],
            "/repos/pipelab-org/pipelock/actions/runs/100/jobs?per_page=100": FIXTURE["jobs"],
            "/repos/pipelab-org/pipelock/actions/jobs/200/logs": FIXTURE["job_location"],
            "/repos/pipelab-org/pipelock/actions/runs/100/logs": FIXTURE["run_location"],
        }[endpoint])
    api.request.side_effect = request
    return api


class ContractTest(unittest.TestCase):
    def read(self, source=SOURCE, shared=SHARED):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "credential_audience_actions_results.go").write_text(source)
            (directory / "credential_audience.go").write_text(shared)
            return canary.read_contract(directory)

    def test_reads_literal_hosts_alias_cap_and_comment(self):
        self.assertEqual(self.read(), ({HOST}, 86400, 605))
        for unit, seconds in (("Second", 1), ("Minute", 60), ("Hour", 3600)):
            with self.subTest(unit=unit):
                source = SOURCE.replace("= attestationBundleSASMaxLifetime", f"= 2 * time.{unit}")
                self.assertEqual(self.read(source)[1], 2 * seconds)

    def test_unparseable_contracts_fail_with_fixed_source_error(self):
        for source in ("", SOURCE.replace("[]string{", "func() []string {"),
                       SOURCE.replace(f'"{HOST}",', f'"{HOST}", "{HOST}",'),
                       SOURCE.replace(HOST, SECRET), SOURCE.replace("605 seconds", "unknown seconds"),
                       SOURCE.replace(f'"{HOST}",', 'computed(),'),
                       SOURCE.replace("attestationBundleSASMaxLifetime", "unknown")):
            with self.subTest(source=source):
                with self.assertRaises(canary.SourceError) as raised:
                    self.read(source)
                self.assertNotIn(SECRET, str(raised.exception))
        with self.assertRaises(canary.SourceError):
            self.read(shared="const attestationBundleSASMaxLifetime = 0 * time.Hour\n")
        with self.assertRaises(canary.SourceError):
            canary.read_contract(Path("/absent-canary-contract"))


class DriftTest(unittest.TestCase):
    def test_accounts_match_add_remove_and_ignore_unrelated(self):
        report = canary.Report()
        canary.compare_accounts(FIXTURE["meta"], {HOST}, report)
        self.assertFalse(report.drift)
        for published, compiled, label in (({HOST}, set(), "Added"), ({HOST}, {HOST, "productionresultssa1.blob.core.windows.net"}, "Removed")):
            with self.subTest(label=label):
                report = canary.Report()
                canary.compare_accounts({"domains": {"actions": list(published)}}, compiled, report)
                self.assertTrue(any(label in entry for entry in report.drift))
                for changed in published ^ compiled:
                    self.assertIn(changed, report.render())

    def test_bad_meta_is_evidence_failure(self):
        for meta in (None, {}, {"domains": {"actions": "bad"}}, {"domains": {"actions": [None]}}):
            with self.subTest(meta=meta), self.assertRaises(canary.APIError):
                canary.compare_accounts(meta, {HOST}, canary.Report())

    def test_all_accounts_removed_and_new_account_spelling_are_drift(self):
        for hosts in ([], ["api.vendor.example"], ["productionresultssanew.blob.core.windows.net"]):
            with self.subTest(hosts=hosts):
                report = canary.Report()
                canary.compare_accounts({"domains": {"actions": hosts}}, {HOST}, report)
                self.assertTrue(report.drift)
                self.assertFalse(report.errors)

    def test_valid_job_sas_and_lifetime_boundaries(self):
        start = datetime.fromisoformat("2026-11-05T09:59:55+00:00")
        for seconds, drift, warning in ((605, False, False), (606, False, True),
                                        (86400, False, True), (86401, True, False),
                                        (0, True, False), (-1, True, False)):
            with self.subTest(seconds=seconds):
                expiry = (start + timedelta(seconds=seconds)).isoformat()
                report = canary.Report()
                canary.check_sample(altered_url(se=expiry), {HOST}, 86400, 605, report)
                self.assertEqual(bool(report.drift), drift)
                self.assertEqual(bool(report.warnings), warning)

    def test_signed_field_shape_drift_and_no_secret_output(self):
        for changes in ({"sp": "w"}, {"sr": "c"}, {"spr": "http"}, {"sig": ""},
                        {"sig": [SECRET, SECRET]}, {"st": None}, {"se": SECRET},
                        {"st": "2026-11-05T09:59:55"}, {"rscd": "attachment"},
                        {SECRET: SECRET}, {"rsct": None}):
            with self.subTest(changes=changes):
                report = canary.Report()
                location = altered_url(**changes)
                canary.check_sample(location, {HOST}, 86400, 605, report)
                self.assertTrue(report.drift)
                self.assertNotIn(SECRET, report.render())
                self.assertNotIn(urllib.parse.urlsplit(location).query, report.render())

    def test_destination_and_malformed_url_drift(self):
        original = FIXTURE["job_location"]
        for location in (original.replace("https:", "http:"), original.replace(HOST, "api.vendor.example"),
                         original.replace(HOST, HOST + ".evil.example"), original.replace(HOST, HOST + ":444"),
                         original.replace(HOST, "user@" + HOST), original + "#fragment",
                         original.replace("/actions-results/", "/other/"),
                         "https://[invalid?sig=" + SECRET, original + "&bare"):
            with self.subTest(location=location):
                report = canary.Report()
                canary.check_sample(location, {HOST}, 86400, 605, report)
                self.assertTrue(report.drift)
                self.assertNotIn(SECRET, report.render())


class APITest(unittest.TestCase):
    def test_transport_returns_redirect_without_opening_destination(self):
        api = canary.GitHubAPI("fixture-token")
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                error = urllib.error.HTTPError("https://api.github.com/logs", status, "redirect",
                                               {"Location": FIXTURE["job_location"]}, io.BytesIO())
                with mock.patch.object(api.opener, "open", side_effect=error) as opened:
                    self.assertEqual(api.request("/logs", redirect=True), FIXTURE["job_location"])
                    opened.assert_called_once()
                    self.assertEqual(opened.call_args.args[0].full_url, "https://api.github.com/logs")
        self.assertIsNone(canary.NoRedirect().redirect_request(None, None, 302, "", {}, FIXTURE["job_location"]))

        # Exercise urllib's redirect machinery too: a second open would send
        # the request to the signed destination and fail this contract.
        opened_urls = []
        class RedirectTransport(urllib.request.HTTPSHandler):
            def https_open(self, request):
                opened_urls.append(request.full_url)
                headers = Message()
                headers["Location"] = FIXTURE["job_location"]
                response = urllib.response.addinfourl(io.BytesIO(), headers, request.full_url, 302)
                response.msg = "Found"
                return response
        api.opener = urllib.request.build_opener(canary.NoRedirect(), RedirectTransport())
        self.assertEqual(api.request("/logs", redirect=True), FIXTURE["job_location"])
        self.assertEqual(opened_urls, ["https://api.github.com/logs"])

    def test_error_bodies_and_exception_urls_never_escape(self):
        api = canary.GitHubAPI("fixture-token")
        for failure in (urllib.error.HTTPError(FIXTURE["job_location"], 403, SECRET, {}, io.BytesIO(SECRET.encode())),
                        urllib.error.HTTPError(FIXTURE["job_location"], 302, SECRET, {}, io.BytesIO()),
                        urllib.error.URLError(FIXTURE["job_location"]), OSError(SECRET),
                        http.client.BadStatusLine(SECRET), http.client.IncompleteRead(SECRET.encode())):
            with self.subTest(failure=type(failure)), mock.patch.object(api.opener, "open", side_effect=failure):
                with self.assertRaises(canary.APIError) as raised:
                    api.request("/logs", redirect=True)
                self.assertNotIn(SECRET, str(raised.exception))
                self.assertNotIn("sig=", str(raised.exception))

    def test_json_and_unexpected_success(self):
        api = canary.GitHubAPI("fixture-token")
        for body, redirect, valid in ((b'{"ok":true}', False, True), (b'invalid', False, False),
                                      (b'{}', True, False)):
            with self.subTest(body=body, redirect=redirect):
                with mock.patch.object(api.opener, "open", return_value=io.BytesIO(body)):
                    if valid:
                        self.assertEqual(api.request("/meta"), {"ok": True})
                    else:
                        with self.assertRaises(canary.APIError):
                            api.request("/logs", redirect=redirect)

    def test_fixture_sampling_and_run_log_scope(self):
        api = sample_api()
        report = canary.Report()
        canary.sample_live(api, "pipelab-org/pipelock", {HOST}, 86400, 605, report)
        self.assertFalse(report.drift or report.errors or report.warnings)
        self.assertIn("605 s", report.render())
        for call in api.request.call_args_list:
            if call.args[0].endswith("/logs"):
                self.assertTrue(call.kwargs["redirect"])
        for location in ("https://api.vendor.example/?sig=" + SECRET, "https://[invalid"):
            api = sample_api()
            original = api.request.side_effect
            api.request.side_effect = lambda endpoint, **kw: location if "/runs/100/logs" in endpoint else original(endpoint, **kw)
            report = canary.Report()
            canary.sample_live(api, "pipelab-org/pipelock", {HOST}, 86400, 605, report)
            self.assertTrue(report.warnings)
            self.assertNotIn(SECRET, report.render())

    def test_unsampleable_and_malformed_api_evidence(self):
        for runs in ({"workflow_runs": []}, {}, {"workflow_runs": [{"id": SECRET}]}):
            api = mock.Mock()
            api.request.return_value = runs
            with self.subTest(runs=runs), self.assertRaises(canary.APIError):
                canary.sample_live(api, "pipelab-org/pipelock", {HOST}, 86400, 605, canary.Report())
        for jobs in ({"jobs": []}, {"jobs": [{"status": "queued"}]},
                     {"jobs": [{"status": "completed", "conclusion": "skipped"}]},
                     {"jobs": [{"status": "completed", "conclusion": "success", "steps": [1], "id": SECRET}]}):
            api = sample_api()
            original = api.request.side_effect
            api.request.side_effect = lambda endpoint, **kw: jobs if "/jobs?" in endpoint else original(endpoint, **kw)
            with self.subTest(jobs=jobs), self.assertRaises(canary.APIError):
                canary.sample_live(api, "pipelab-org/pipelock", {HOST}, 86400, 605, canary.Report())


class MainTest(unittest.TestCase):
    def invoke(self, api=None, source_error=False, token="fixture-token", repository="pipelab-org/pipelock"):
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary.md"
            stdout = io.StringIO()
            with mock.patch.dict(os.environ, {"GH_TOKEN": token, "GITHUB_TOKEN": "", "GITHUB_STEP_SUMMARY": str(summary)}), \
                    mock.patch.object(canary, "read_contract", side_effect=canary.SourceError("Source unavailable") if source_error else None,
                                      return_value=({HOST}, 86400, 605)), \
                    mock.patch.object(canary, "GitHubAPI", return_value=api or sample_api()), \
                    contextlib.redirect_stdout(stdout):
                status = canary.main(["--repository", repository])
            return status, stdout.getvalue(), summary.read_text()

    def test_every_outcome_writes_summary_and_redacts_signature(self):
        changed = sample_api()
        original = changed.request.side_effect
        changed.request.side_effect = lambda endpoint, **kw: altered_url(sp="w", **{SECRET: SECRET}) if endpoint.endswith("/jobs/200/logs") else original(endpoint, **kw)
        failed = mock.Mock()
        failed.request.side_effect = canary.APIError("GitHub API: HTTP 403; evidence unavailable")
        for options, expected in (({}, 0), ({"api": changed}, 1), ({"api": failed}, 2),
                                  ({"source_error": True}, 2), ({"token": ""}, 2),
                                  ({"repository": SECRET + "?"}, 2)):
            with self.subTest(options=options):
                status, stdout, summary = self.invoke(**options)
                self.assertEqual(status, expected)
                self.assertIn("## Actions results grant canary", summary)
                self.assertIn(summary, stdout)
                for output in (stdout, summary):
                    self.assertNotIn(SECRET, output)
                    self.assertNotIn("sig=", output)
                    self.assertNotIn(FIXTURE["job_location"], output)
                if expected:
                    self.assertIn("::error", stdout)
                if expected == 2:
                    self.assertIn("Canary evidence error", stdout)

    def test_account_error_does_not_skip_sample_or_hide_drift(self):
        api = sample_api()
        original = api.request.side_effect
        api.request.side_effect = lambda endpoint, **kw: {} if endpoint == "/meta" else original(endpoint, **kw)
        status, stdout, _ = self.invoke(api=api)
        self.assertEqual(status, 2)
        self.assertIn("605 s", stdout)
        self.assertIn("Meta API", stdout)

    def test_lifetime_warning_is_success_and_is_emitted(self):
        api = sample_api()
        original = api.request.side_effect
        api.request.side_effect = lambda endpoint, **kw: altered_url(se="2026-11-05T10:10:01Z") if endpoint.endswith("/jobs/200/logs") else original(endpoint, **kw)
        status, stdout, summary = self.invoke(api=api)
        self.assertEqual(status, 0)
        self.assertIn("::warning", stdout)
        self.assertNotIn("::error", stdout)
        self.assertIn("606 s", summary)
        self.assertNotIn(SECRET, stdout + summary)

    def test_stdout_without_summary_and_summary_write_failure(self):
        for path, expected in ((None, 0), (Path("/absent-canary-parent/summary.md"), 2)):
            with self.subTest(path=path), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(canary.Report().emit(path), expected)

    def test_workflow_is_read_only_pinned_and_always_publishes_summary(self):
        workflow = yaml.load((canary.ROOT / ".github/workflows/actions-results-grant-canary.yaml").read_text(), Loader=WorkflowLoader)
        self.assertEqual(set(workflow["on"]), {"schedule", "workflow_dispatch"})
        self.assertEqual(workflow["permissions"], {"contents": "read", "actions": "read"})
        self.assertEqual(len(workflow["on"]["schedule"]), 1)
        cron = workflow["on"]["schedule"][0]["cron"].split()
        self.assertEqual(cron[2:4], ["*", "*"])
        self.assertRegex(cron[4], r"^[0-6]$")
        job = workflow["jobs"]["canary"]
        self.assertNotIn("permissions", job)
        for step in job["steps"]:
            if "uses" in step:
                self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
                if step["uses"].startswith("actions/checkout@"):
                    self.assertIs(step["with"]["persist-credentials"], False)
        sample = job["steps"][1]
        self.assertEqual(sample["env"]["GH_TOKEN"], "${{ github.token }}")
        self.assertEqual(sample["run"], "python3 scripts/actions_results_grant_canary.py")
        final = job["steps"][-1]
        self.assertEqual(final["if"], "always()")
        # Execute both final-step branches; GitHub gives each step a new summary file.
        for content in (None, "## Safe fixture summary\n"):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                summary = root / "step-summary.md"
                if content:
                    (root / "actions-results-summary.md").write_text(content)
                subprocess.run(["bash", "-euc", final["run"]], check=True,
                               env={**os.environ, "RUNNER_TEMP": directory, "GITHUB_STEP_SUMMARY": str(summary)})
                self.assertIn(content or "Check did not finish", summary.read_text())


if __name__ == "__main__":
    unittest.main()
