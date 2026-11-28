# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Require complete producer evidence for the scheduled timing refresh."""

import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import ci_test_durations as durations
from scripts.ci_test_durations import ci_artifact_inputs
from scripts.ci_test_packages import ROOT, SHARDS


class ShardDriftTest(unittest.TestCase):
    def write_artifact(self, root, lane, shard, *events):
        path = root / f"go-test-json-{lane}-go126-{shard}" / f"go-test-{lane}.json"
        path.parent.mkdir()
        path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        return path

    def test_recovers_only_complete_artifacts_without_lowering_weights(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proxy = "example.test/internal/proxy"
            slow, fast = "example.test/rest/slow", "example.test/rest/fast"
            self.write_artifact(root, "oss", "proxy-0",
                                {"ImportPath": proxy, "Action": "build-output", "Output": "build note\n"},
                                {"Package": proxy, "Action": "start"},
                                {"Package": proxy, "Action": "run", "Test": "TestExisting"},
                                {"Package": proxy, "Action": "pass", "Test": "TestExisting", "Elapsed": 4},
                                {"Package": proxy, "Action": "pass", "Elapsed": 4})
            self.write_artifact(root, "oss", "rest-0",
                                {"Package": slow, "Action": "pass", "Elapsed": 12},
                                {"Package": fast, "Action": "pass", "Elapsed": 2})
            self.write_artifact(root, "enterprise", "rest-0",
                                {"Package": slow, "Action": "pass", "Elapsed": 90},
                                {"Package": "example.test/rest/failed", "Action": "fail", "Elapsed": 90})
            malformed = self.write_artifact(root, "enterprise", "rest-1",
                                            {"Package": slow, "Action": "pass", "Elapsed": 95})
            malformed.write_text(malformed.read_text(encoding="utf-8") + '{"Action":', encoding="utf-8")
            self.write_artifact(root, "enterprise", "rest-2",
                                {"Package": slow, "Action": "pass", "Elapsed": 99},
                                {"Package": slow, "Action": "start"})
            self.write_artifact(root, "enterprise", "rest-3",
                                {"Package": slow, "Action": "pass", "Elapsed": float("nan")})

            args = ["ci_test_durations.py", "--recover-ci-artifacts", directory]
            stdout, stderr = StringIO(), StringIO()
            with patch("sys.argv", args), redirect_stdout(stdout), redirect_stderr(stderr), \
                 patch.object(durations, "load_durations", return_value={"proxy": {"TestExisting": 10, "TestUnseen": 8}}), \
                 patch.object(durations, "load_package_durations", return_value={slow: 6, fast: 7}), \
                 patch.object(durations, "tree_test_names", return_value=["TestExisting", "TestUnseen"]):
                self.assertEqual(durations.main(), 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result, {"trees": {"proxy": {"TestExisting": 10, "TestUnseen": 8}},
                                      "packages": {slow: 12, fast: 7}})
            diagnostics = stderr.getvalue()
            self.assertIn(f"2 of {2 * len(SHARDS)}", diagnostics)
            self.assertIn("missing or empty CI timing artifact", diagnostics)
            for shard in ("rest-0", "rest-1", "rest-2", "rest-3"):
                self.assertRegex(diagnostics, f"incomplete or failed CI timing artifact: .*enterprise-go126-{shard}/")

    def test_recovery_refuses_empty_input_and_incompatible_options(self):
        with tempfile.TemporaryDirectory() as directory:
            args = ["ci_test_durations.py", "--recover-ci-artifacts", directory]
            stdout, stderr = StringIO(), StringIO()
            with patch("sys.argv", args), redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(durations.main(), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("no usable CI timing artifacts", stderr.getvalue())
            for extra in (["--write"], ["--partial"], ["input.json"], ["--ci-artifacts", directory]):
                with self.subTest(extra=extra), patch("sys.argv", args + extra), redirect_stderr(StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        durations.main()
                    self.assertEqual(raised.exception.code, 2)

    def test_requires_every_nonempty_measured_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "missing or empty"):
                ci_artifact_inputs(root)
            paths = []
            for lane in ("oss", "enterprise"):
                for shard in SHARDS:
                    path = root / f"go-test-json-{lane}-go126-{shard}" / f"go-test-{lane}.json"
                    path.parent.mkdir()
                    path.write_text(json.dumps({"Action": "pass", "Package": "example.test/rest",
                                                "Elapsed": 1.0}) + "\n", encoding="utf-8")
                    paths.append(path)
            self.assertEqual(ci_artifact_inputs(root), paths)
            for path in paths:
                body = path.read_text(encoding="utf-8")
                for invalid in ("", "not JSON\n", '{"Action":"start"}\n',
                                # Unfinished top-level test; the package itself passed.
                                ('{"Action":"run","Package":"example.test/internal/proxy","Test":"TestPartial"}\n'
                                 '{"Action":"pass","Package":"example.test/internal/proxy","Test":"TestPartial/child","Elapsed":12}\n'
                                 '{"Action":"pass","Package":"example.test/internal/proxy","Elapsed":12}\n'),
                                '{"Action":"fail","Package":"example.test/rest","Elapsed":1}\n'):
                    with self.subTest(path=path.name, invalid=invalid):
                        path.write_text(invalid, encoding="utf-8")
                        with self.assertRaises(ValueError):
                            ci_artifact_inputs(root)
                path.write_text(body, encoding="utf-8")
                path.unlink()
                with self.assertRaisesRegex(ValueError, "missing or empty"):
                    ci_artifact_inputs(root)
                path.write_text(body, encoding="utf-8")

    def test_workflow_requires_complete_evidence_before_writing(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci-shard-drift.yaml").read_text(encoding="utf-8"))
        step = next(step for step in workflow["jobs"]["drift"]["steps"]
                    if step.get("name") == "Refresh weights and check the budget")
        self.assertIn('--write --ci-artifacts "$RUNNER_TEMP/timing" || exit $?', step["run"])


if __name__ == "__main__":
    unittest.main()
