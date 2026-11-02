# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import yaml

from scripts.release_doc_versions import (
    DISCOVER_VERSION, REGISTRY, _canonical_stats, check as check_inventory,
    check_document_versions as check, check_registry,
)
from scripts.yaml_contracts import WorkflowLoader


ROOT = Path(__file__).resolve().parents[1]


CURRENT = """\
git clone --branch v3.6.0 --depth 1 https://github.com/pipelab-org/pipelock.git
docker pull ghcr.io/luckypipewrench/pipelock:3.6.0
helm install pipelock oci://ghcr.io/luckypipewrench/charts/pipelock --version 3.6.0
RUN curl -fsSL https://github.com/luckyPipewrench/pipelock/releases/download/v3.6.0/pipelock_3.6.0_linux_amd64.tar.gz
- uses: luckyPipewrench/pipelock@0123456789abcdef0123456789abcdef01234567 # v3.6.0
"""


def write_tree(root: Path, *, current: str = CURRENT, health: str = '  "version": "v3.6.0",\n') -> None:
    (root / "README.md").write_text(current, encoding="utf-8")
    health_path = root / "docs" / "guides" / "health.md"
    health_path.parent.mkdir(parents=True, exist_ok=True)
    health_path.write_text(health, encoding="utf-8")
    (root / "release").mkdir(exist_ok=True)
    (root / "release/version.txt").write_text("3.6.0")
    registry = minimal_registry()
    registry["surfaces"] = [
        {"id": path, "path": path, "pattern": r"(?P<value>" + DISCOVER_VERSION.pattern + r")",
         "expected": "source:product", "format": "version", "count": count,
         "reason": "Current operator instructions."}
        for path, count in (("README.md", 6), ("docs/guides/health.md", 1))
    ]
    (root / REGISTRY).write_text(json.dumps(registry))



def minimal_registry() -> dict:
    return {
        "schema_version": 1,
        "sources": {"product": {"path": "release/version.txt", "pattern": r"^(?P<value>[^\n]+)$"}},
        "scan": {"roots": ["README.md", "docs"], "suffixes": [".md"], "exclude": []},
        "surfaces": [],
        "external": [{"id": "site", "owner": "example/site", "url": "https://site.example/",
                      "reason": "The site owns homepage numbers."}],
    }

class ReleaseDocVersionTests(unittest.TestCase):
    def test_repository_matches_chart_app_version(self) -> None:
        """Exercise the release gate on the shipped tree, not only fixtures."""
        chart = yaml.load(
            (ROOT / "charts/pipelock/Chart.yaml").read_text(encoding="utf-8"),
            Loader=WorkflowLoader,
        )
        self.assertEqual(check_inventory(ROOT, f"v{chart['appVersion']}"), [])

    def test_known_current_pins_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(root)
            self.assertEqual(check(root, "v3.6.0"), [])

    def test_each_supported_stale_pin_fails(self) -> None:
        stale_cases = (
            ("git clone branch", "git clone --branch v3.5.0 --depth 1 https://github.com/pipelab-org/pipelock.git"),
            ("Docker tag", "docker pull ghcr.io/luckypipewrench/pipelock:3.5.0"),
            ("Helm version", "helm install pipelock oci://ghcr.io/luckypipewrench/charts/pipelock --version 3.5.0"),
            (
                "archive tag and filename",
                "RUN curl https://github.com/luckyPipewrench/pipelock/releases/download/v3.5.0/pipelock_3.5.0_linux_amd64.tar.gz",
            ),
            (
                "Action version comment",
                "- uses: luckyPipewrench/pipelock@0123456789abcdef0123456789abcdef01234567 # v3.5.0",
            ),
        )
        for label, line in stale_cases:
            with self.subTest(surface=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_tree(root, current=CURRENT.replace(
                    "git clone --branch v3.6.0 --depth 1 https://github.com/pipelab-org/pipelock.git",
                    line,
                    1,
                ))
                findings = check(root, "v3.6.0")
                self.assertTrue(any("expected" in finding and "README.md" in finding for finding in findings), findings)

    def test_clone_pins_from_both_repository_owners_are_checked(self) -> None:
        for owner in ("pipelab-org", "luckyPipewrench"):
            with self.subTest(owner=owner), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_tree(root, current=CURRENT + (
                    f"git clone --branch v3.5.0 --depth 1 https://github.com/{owner}/pipelock.git\n"
                ))
                self.assertTrue(any("git clone release branch" in finding and "3.5.0" in finding
                                    for finding in check(root, "v3.6.0")))

    def test_near_miss_repository_name_is_not_a_clone_pin(self) -> None:
        for url in (
            "https://github.com/pipelab-org/pipelock-fork.git",
            "https://github.com/luckyPipewrench/pipelock-fork.git",
            "https://github.com/pipelab-org/pipelock.git.backup",
        ):
            with self.subTest(url=url), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_tree(root, current=CURRENT + (
                    f"git clone --branch v3.5.0 --depth 1 {url}\n"
                ))
                findings = check(root, "v3.6.0")
                self.assertFalse(any("3.5.0" in finding for finding in findings), findings)

    def test_quoted_stale_pins_cannot_hide_behind_current_pins(self) -> None:
        for quote in ("'", '"', "`"):
            for line in (
                f"git clone --branch {quote}v3.5.0{quote} https://github.com/luckyPipewrench/pipelock.git",
                f"- uses: luckyPipewrench/pipelock@0123456789abcdef0123456789abcdef01234567 # {quote}v3.5.0{quote}",
            ):
                with self.subTest(line=line), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    write_tree(root, current=CURRENT + line + "\n")
                    self.assertTrue(any("3.5.0" in finding for finding in check(root, "v3.6.0")))

    def test_unprefixed_action_tag_cannot_hide_behind_current_comment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(root, current=CURRENT + "- uses: luckyPipewrench/pipelock@3.5.0\n")
            self.assertTrue(any("incorrect v prefix" in finding for finding in check(root, "v3.6.0")))

    def test_download_options_and_folded_yaml_stale_pins_fail(self) -> None:
        cases = (
            "gh release download --repo luckyPipewrench/pipelock v3.5.0",
            "gh release download -R luckyPipewrench/pipelock --dir ./out v3.5.0",
            "gh release download --repo=luckyPipewrench/pipelock v3.5.0",
            "run: >-\n  gh release download\n  --repo luckyPipewrench/pipelock\n  v3.5.0\n",
        )
        for source in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_tree(root)
                (root / "examples").mkdir()
                (root / "examples" / "install.yaml").write_text(source)
                self.assertTrue(any("3.5.0" in finding for finding in check(root, "v3.6.0")))

    def test_folded_and_download_option_positive_controls(self) -> None:
        cases = (
            "gh release download --repo luckyPipewrench/pipelock --clobber v3.6.0",
            "gh release download --dir 3.5.0 --pattern '*.tar.gz' v3.6.0",
            "run: >+\n  gh release download\n  --repo luckyPipewrench/pipelock\n  v3.6.0\n",
            "run: >-\n  gh release download\n\n  v3.5.0\n",
            "run: >-\n  gh release download\n    v3.5.0\n",
        )
        for source in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_tree(root)
                (root / "examples").mkdir()
                (root / "examples" / "install.yaml").write_text(source)
                self.assertEqual(check(root, "v3.6.0"), [])

    def test_stale_health_output_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(root, health='  "version": "v3.5.0",\n')
            self.assertTrue(any("health response version" in finding for finding in check(root, "v3.6.0")))

    def test_malformed_candidate_and_supported_reference_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(root)
            findings = check(root, "v3.6")
            self.assertTrue(any("malformed release tag" in finding for finding in findings), findings)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            malformed = CURRENT.replace(
                "ghcr.io/luckypipewrench/pipelock:3.6.0",
                "ghcr.io/luckypipewrench/pipelock:3.6",
            )
            write_tree(root, current=malformed)
            findings = check(root, "v3.6.0")
            self.assertTrue(any("malformed version '3.6'" in finding for finding in findings), findings)

    def test_historical_and_frozen_comparisons_are_positive_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(root)
            (root / "docs" / "cli").mkdir(parents=True)
            (root / "docs" / "cli" / "update.md").write_text(
                "pipelock update --version v3.1.0   # install a specific release tag\n",
                encoding="utf-8",
            )
            (root / "docs" / "contain-cli.md").write_text(
                "sudo pipelock contain upgrade --version v3.2.0  # pin to a specific tag\n",
                encoding="utf-8",
            )
            (root / "docs" / "benchmarks").mkdir(parents=True)
            (root / "docs" / "benchmarks" / "history.md").write_text(
                "docker pull ghcr.io/luckypipewrench/pipelock:3.2.0\n",
                encoding="utf-8",
            )
            (root / "CHANGELOG.md").write_text(
                "git clone --branch v3.4.0 https://github.com/luckyPipewrench/pipelock.git\n",
                encoding="utf-8",
            )
            self.assertEqual(check(root, "v3.6.0"), [])

    def test_prefixes_follow_published_artifact_names(self) -> None:
        for before, after in (
            ("--branch v3.6.0", "--branch 3.6.0"),
            ("pipelock:3.6.0", "pipelock:v3.6.0"),
            ("--version 3.6.0", "--version v3.6.0"),
        ):
            with self.subTest(reference=after), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_tree(root, current=CURRENT.replace(before, after))
                self.assertTrue(any("incorrect v prefix" in item for item in check(root, "v3.6.0")))

    def test_continuations_punctuation_and_tag_refs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(root, current=CURRENT + "\nSee (ghcr.io/luckypipewrench/pipelock:3.6.0).\n")
            self.assertEqual(check(root, "v3.6.0"), [])
            with (root / "README.md").open("a") as target:
                target.write("\nhelm pull oci://ghcr.io/luckypipewrench/charts/pipelock \\\n --version 3.5.0\n- uses: luckyPipewrench/pipelock@v3.5.0\ngh release download v3.5.0 --repo luckyPipewrench/pipelock\n")
            findings = check(root, "v3.6.0")
            for surface in ("Helm chart version", "GitHub Action tag", "release download command"):
                self.assertTrue(any(surface in item for item in findings), findings)

    def test_cli_and_shell_consumer_deny_stale_and_allow_current(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        script = source_root / "scripts/release_doc_versions.py"
        consumer = (source_root / "scripts/check-release-ready.sh").read_text()
        start = consumer.index('if ! python3 "$REPO_ROOT/scripts/release_doc_versions.py"')
        block = consumer[start:consumer.index("\nfi", start) + 3]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "scripts/release_doc_versions.py").write_text(script.read_text())
            for version, expected in (("3.6.0", 0), ("3.5.0", 1)):
                write_tree(root, current=CURRENT.replace("3.6.0", version))
                result = subprocess.run([sys.executable, str(script), str(root), "v3.6.0"], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)
                result = subprocess.run(["bash", "-c", 'REPO_ROOT="$1"; VERSION=v3.6.0; fail=0; ' + block + '; exit "$fail"', "consumer", str(root)], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_archive_tag_and_filename_fail_independently(self) -> None:
        for before, after in (("/v3.6.0/", "/v3.5.0/"), ("pipelock_3.6.0_", "pipelock_3.5.0_")):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_tree(root, current=CURRENT.replace(before, after))
                self.assertTrue(any("release archive URL" in item for item in check(root, "v3.6.0")))

    def test_archive_consumers_and_init_image_stay_on_the_release(self) -> None:
        commands = (
            "gh release download v3.6.0 --pattern pipelock_3.5.0_linux_amd64.tar.gz",
            "gh release download --pattern=pipelock_3.5.0_linux_amd64.tar.gz v3.6.0",
            "gh attestation verify pipelock_3.5.0_linux_amd64.tar.gz --owner luckyPipewrench",
            "tar xzf pipelock_3.5.0_linux_amd64.tar.gz",
            "tar xzf pipelock-verifier_3.5.0_linux_amd64.tar.gz",
            "image: ghcr.io/luckypipewrench/pipelock-init:3.5.0",
        )
        for source in commands:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_tree(root, current=CURRENT + source + "\n")
                self.assertTrue(any("3.5.0" in issue for issue in check(root, "v3.6.0")))
                write_tree(root, current=CURRENT + source.replace("3.5.0", "3.6.0") + "\n")
                self.assertEqual(check(root, "v3.6.0"), [])

    def test_missing_required_surface_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(
                root,
                current="\n".join(
                    line for line in CURRENT.splitlines() if "helm install" not in line
                )
                + "\n",
            )
            findings = check(root, "v3.6.0")
            self.assertTrue(any("missing required current-release surface: Helm" in finding for finding in findings), findings)

class ReleaseSurfaceRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        write_tree(self.root)
        self.registry = json.loads((self.root / REGISTRY).read_text())

    def save(self) -> None:
        (self.root / REGISTRY).write_text(json.dumps(self.registry))

    def add_surface(self, *, text="Release package 3.6.0\n", pattern=None, expected="source:product", fmt="version") -> Path:
        path = self.root / "docs/current.md"
        path.write_text(text)
        self.registry["surfaces"].append({
            "id": "additional-release-surface", "path": "docs/current.md",
            "pattern": pattern or r"Release package (?P<value>[^\s]+)",
            "expected": expected, "count": 1, "reason": "Current package instructions.", "format": fmt,
        })
        self.save()
        return path

    def test_registered_drift_and_missing_surface_fail(self) -> None:
        path = self.add_surface()
        self.assertEqual(check_inventory(self.root), [])
        path.write_text("Release package 3.5.0\n")
        issues = check_inventory(self.root)
        self.assertTrue(any("additional-release-surface has '3.5.0', expected '3.6.0'" in issue for issue in issues), issues)
        path.write_text("Package instructions without a version\n")
        self.assertTrue(any("matched 0 times, expected 1" in issue for issue in check_inventory(self.root)))
        path.unlink()
        self.assertTrue(any("unreadable" in issue for issue in check_inventory(self.root)))

    def test_quickstart_historical_pin_requires_legacy_namespace(self) -> None:
        relative = "examples/quickstart/README.md"
        registry = minimal_registry()
        shipped = json.loads((ROOT / REGISTRY).read_text(encoding="utf-8"))
        registry["surfaces"] = [entry for entry in shipped["surfaces"] if entry["path"] == relative]
        registry["scan"]["roots"] = [relative]
        chart = yaml.load((ROOT / "charts/pipelock/Chart.yaml").read_text(), Loader=WorkflowLoader)
        values = {"product": str(chart["appVersion"])}
        path = self.root / relative
        path.parent.mkdir(parents=True)
        original = (ROOT / relative).read_text(encoding="utf-8")
        path.write_text(original)
        self.assertEqual(check_registry(self.root, registry, values), [])

        legacy = "PIPELOCK_IMAGE_NAMESPACE=luckypipewrench"
        self.assertEqual(original.count(legacy), 1)
        path.write_text(original.replace(legacy, "PIPELOCK_IMAGE_NAMESPACE=pipelab-org"))
        issues = check_registry(self.root, registry, values)
        self.assertTrue(any("quickstart-legacy-example matched 0 times" in issue for issue in issues), issues)

    def test_new_surface_requires_registration_even_when_current(self) -> None:
        (self.root / "docs/new-install.md").write_text("Release package v3.6.0\n")
        issues = check_inventory(self.root)
        self.assertTrue(any("new-install.md:1: unregistered" in issue for issue in issues), issues)

    def test_new_public_test_count_requires_registration(self) -> None:
        (self.root / "docs/new-count.md").write_text("12,000 tests\n")
        self.assertTrue(any("unregistered" in issue and "12,000" in issue for issue in check_inventory(self.root)))

    def test_added_and_removed_occurrences_are_not_silent(self) -> None:
        path = self.add_surface()
        path.write_text(path.read_text() * 2)
        self.assertTrue(any("matched 2 times, expected 1" in issue for issue in check_inventory(self.root)))

    def test_source_driven_figure_tracks_stats_and_denies_drift(self) -> None:
        path = self.add_surface(text="65 built-in patterns\n", pattern=r"(?P<value>\d+) built-in patterns", expected="stats:DLP patterns", fmt="number")
        with mock.patch("scripts.release_doc_versions._canonical_stats", return_value={"stats:DLP patterns": "65"}):
            self.assertEqual(check_inventory(self.root), [])
            path.write_text("64 built-in patterns\n")
            self.assertTrue(any("expected '65'" in issue for issue in check_inventory(self.root)))
        path.write_text("66 built-in patterns\n")
        with mock.patch("scripts.release_doc_versions._canonical_stats", return_value={"stats:DLP patterns": "66"}):
            self.assertEqual(check_inventory(self.root), [])

    def test_historical_snapshot_is_bound_to_its_numbers(self) -> None:
        text = "Measured 1,000 requests on v3.5.0\n"
        path = self.add_surface(text=text, pattern=r"\A(?P<value>[\s\S]+)\Z", expected=hashlib.sha256(text.encode()).hexdigest(), fmt="sha256")
        self.assertEqual(check_inventory(self.root), [])
        path.write_text(text.replace("1,000", "2,000"))
        self.assertTrue(any("additional-release-surface has" in issue for issue in check_inventory(self.root)))

    def test_source_versions_can_advance_without_changing_selectors(self) -> None:
        path = self.add_surface()
        for relative in ("README.md", "docs/guides/health.md", "docs/current.md", "release/version.txt"):
            target = self.root / relative
            target.write_text(target.read_text().replace("3.6.0", "4.0.0-beta.1"))
        self.assertEqual(check_inventory(self.root), [])
        self.assertEqual(check_inventory(self.root, "v4.0.0-beta.1"), [])
        path.write_text("Release package 3.6.0\n")
        self.assertTrue(check_inventory(self.root, "v4.0.0-beta.1"))

    def test_registry_and_source_errors_fail_closed(self) -> None:
        bad_registries = []
        for key, value in (("schema_version", 2), ("sources", {}), ("surfaces", []), ("external", [])):
            bad = copy.deepcopy(self.registry)
            bad[key] = value
            bad_registries.append(bad)
        for key, value in (("pattern", "("), ("pattern", "no capture"), ("count", 0), ("count", True), ("expected", "source:missing"), ("reason", ""), ("path", "../outside.md")):
            bad = copy.deepcopy(self.registry)
            bad["surfaces"][0][key] = value
            bad_registries.append(bad)
        bad = copy.deepcopy(self.registry)
        bad["surfaces"].append(bad["surfaces"][0])
        bad_registries.append(bad)
        bad = copy.deepcopy(self.registry)
        bad["scan"]["roots"].append("absent")
        bad_registries.append(bad)
        bad = copy.deepcopy(self.registry)
        bad["external"][0].pop("owner")
        bad_registries.append(bad)
        for bad in bad_registries:
            with self.subTest(registry=bad):
                (self.root / REGISTRY).write_text(json.dumps(bad))
                self.assertTrue(any("invalid or unreadable" in issue for issue in check_inventory(self.root)))
        for text in ('{', '{"schema_version":1,"schema_version":1}'):
            (self.root / REGISTRY).write_text(text)
            self.assertTrue(check_inventory(self.root))
        self.save()
        (self.root / "release/version.txt").write_text("invalid")
        self.assertTrue(any("malformed version" in issue for issue in check_inventory(self.root)))
        (self.root / REGISTRY).unlink()
        self.assertTrue(check_inventory(self.root))

    def test_independent_json_and_toml_versions_and_source_cardinality(self) -> None:
        for kind, body in (("json", '{"package":{"version":"0.7.0"}}'), ("toml", '[package]\nversion="0.7.0"\n')):
            with self.subTest(kind=kind):
                (self.root / "release/package.txt").write_text(body)
                self.registry["sources"]["independent"] = {"path": "release/package.txt", kind: ["package", "version"]}
                path = self.add_surface(text="Release package 0.7.0\n", expected="source:independent")
                self.assertEqual(check_inventory(self.root), [])
                path.write_text("Release package 3.6.0\n")
                self.assertTrue(any("expected '0.7.0'" in issue for issue in check_inventory(self.root)))
                self.registry["surfaces"].pop()
        self.registry["sources"]["product"]["pattern"] = "no match"
        self.save()
        self.assertTrue(any("exactly once" in issue for issue in check_inventory(self.root)))

    def test_stats_requires_pass_and_each_canonical_metric(self) -> None:
        output = "--- PASS: TestCanonicalStats (0.00s)\n" + "\n".join(f"{name}: 1" for name in ("DLP patterns", "Response patterns", "Chain patterns", "Preset files", "Direct deps"))
        for status, text, succeeds in ((0, output, True), (1, output, False), (0, "PASS", False), (0, output.replace("Direct deps: 1", ""), False), (0, output + "\nDirect deps: 1", False)):
            with self.subTest(status=status, output=text), mock.patch("scripts.release_doc_versions.subprocess.run", return_value=subprocess.CompletedProcess([], status, stdout=text, stderr="")):
                if succeeds:
                    self.assertEqual(_canonical_stats(self.root)["stats:DLP patterns"], "1")
                else:
                    with self.assertRaises(ValueError):
                        _canonical_stats(self.root)

    def test_shipped_registry_leaves_renovate_owned_pins_alone(self) -> None:
        # Renovate rewrites action and toolchain pins in workflows and action.yml
        # weekly and cannot edit this registry, so inventorying them would fail
        # every dependency PR. Product references in the reusable workflow are
        # registered separately from third-party action pins.
        registry = json.loads((ROOT / REGISTRY).read_text(encoding="utf-8"))
        roots = registry["scan"]["roots"]
        self.assertNotIn(".github/workflows", roots)
        self.assertNotIn("action.yml", roots)
        self.assertNotIn(".github/workflows/reusable-scan.yml", roots)
        stray = [entry["id"] for entry in registry["surfaces"]
                 if (entry["path"].startswith(".github/workflows/") and entry["path"] != ".github/workflows/reusable-scan.yml")
                 or entry["path"] == "action.yml"]
        self.assertEqual(stray, [])

    def test_reusable_workflow_dependency_bump_preserves_product_checks(self) -> None:
        registry = json.loads((ROOT / REGISTRY).read_text(encoding="utf-8"))
        relative = ".github/workflows/reusable-scan.yml"
        workflow = self.root / relative
        workflow.parent.mkdir(parents=True, exist_ok=True)
        original = (ROOT / relative).read_text(encoding="utf-8")
        self.registry["surfaces"].extend(entry for entry in registry["surfaces"] if entry["path"] == relative)
        current = str(yaml.load((ROOT / "charts/pipelock/Chart.yaml").read_text(), Loader=WorkflowLoader)["appVersion"])
        (self.root / "release/version.txt").write_text(current)
        for path in (self.root / "README.md", self.root / "docs/guides/health.md"):
            path.write_text(path.read_text().replace("3.6.0", current))
        self.save()
        bumped, count = re.subn(r"(uses: actions/checkout@[^\n]+# v)[0-9.]+", r"\g<1>99.98.97", original)
        self.assertEqual(count, 1)
        workflow.write_text(bumped)
        self.assertEqual(check_inventory(self.root), [])
        for line in original.splitlines():
            if current not in line:
                continue
            for invalid in ("3.5.0", current + ".1"):
                with self.subTest(line=line, invalid=invalid):
                    workflow.write_text(bumped.replace(line, line.replace(current, invalid)))
                    issues = check_inventory(self.root)
                    self.assertTrue(any(relative in issue for issue in issues), issues)

    def test_shipped_exclusions_do_not_hide_documentation_directories(self) -> None:
        registry = json.loads((ROOT / REGISTRY).read_text(encoding="utf-8"))
        self.registry["scan"]["exclude"] = registry["scan"]["exclude"]
        self.save()
        for relative in ("docs/guides/tests/a.md", "docs/testdata/a.md", "docs/dist/a.md", "docs/node_modules/a.md"):
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Release package v3.5.0\n")
                self.assertTrue(any(f"{relative}:1: unregistered" in issue for issue in check_inventory(self.root)))
                path.unlink()

    def test_workflow_binary_version_is_bound_to_its_own_step(self) -> None:
        docs = (ROOT / "scripts/docs-check.sh").read_text()
        start = docs.index("check_pipelock_workflow_version()")
        function = docs[start:docs.index("check_conductor_serve_scope()", start)]
        for owner in ("luckyPipewrench", "pipelab-org"):
            for version, status in (("3.6.0", 0), ("3.5.0", 1), ("3 .6.0", 1)):
                with self.subTest(owner=owner, version=version):
                    path = self.root / "workflow.yaml"
                    path.write_text("      - name: Scan\n        uses: " + owner + "/pipelock@main\n        with:\n          version: '" + version + "'\n      - run: echo 3.6.0\n")
                    result = subprocess.run(["bash", "-c", function + '\ncheck_pipelock_workflow_version "$1" "$2"', "workflow-check", str(path), "3.6.0"], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, status, result.stderr)

    def test_doc_check_and_preflight_use_the_same_checker(self) -> None:
        docs = (ROOT / "scripts/docs-check.sh").read_text()
        preflight = (ROOT / "scripts/check-release-ready.sh").read_text()
        self.assertIn('python3 "$repo_root/scripts/release_doc_versions.py" "$repo_root"', docs)
        self.assertIn('python3 "$REPO_ROOT/scripts/release_doc_versions.py" "$REPO_ROOT" "$VERSION"', preflight)
        self.assertIn('check_pipelock_workflow_version "$workflow" "$current_version"', docs)
        self.assertNotIn("3\\.7\\.0", docs)

    def test_both_current_and_historical_repository_names_remain_checked(self) -> None:
        for owner in ("luckyPipewrench", "pipelab-org"):
            with self.subTest(owner=owner):
                current = CURRENT.replace("luckyPipewrench", owner).replace("luckypipewrench", owner.lower())
                write_tree(self.root, current=current)
                self.assertEqual(check(self.root, "v3.6.0"), [])
                write_tree(self.root, current=current.replace("3.6.0", "3.5.0"))
                self.assertTrue(check(self.root, "v3.6.0"))


if __name__ == "__main__":
    unittest.main()
