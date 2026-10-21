#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Regression contract for native CI target evidence."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

import yaml

if __package__:
    from .test_ci_workflow_topology import DOCS_SKIP_CONDITION
else:
    from test_ci_workflow_topology import DOCS_SKIP_CONDITION


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yaml"
NATIVE_TARGETS = {
    "test-macos": ("macos-latest", "ARM64", "darwin/arm64", "bash"),
    "test-macos-intel": ("macos-26-intel", "X64", "darwin/amd64", "bash"),
    "test-windows": ("windows-latest", "X64", "windows/amd64", "pwsh"),
    "test-windows-arm64": ("windows-11-arm", "ARM64", "windows/arm64", "pwsh"),
    "test-linux-arm64": ("ubuntu-26.04-arm", "ARM64", "linux/arm64", "bash"),
}

# Existing native-job prerequisites in .github/workflows/ci.yaml. Keep the
# immutable action revisions aligned when updating those dependencies.
NATIVE_SETUP_ACTIONS = [
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
]


def workflow_model() -> dict:
    """Load the full workflow, including inherited environment."""
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def executable_lines(proof: str) -> list[str]:
    """Return non-comment shell lines with indentation removed."""
    return [
        stripped
        for line in proof.splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]


def expected_proof_lines(shell: str, runner_arch: str, go_target: str) -> list[str]:
    """Return the exact straight-line proof required for one native lane."""
    if shell == "pwsh":
        return [
            'Write-Output "runner architecture: $env:RUNNER_ARCH"',
            '$goTarget = "$(go env GOOS)/$(go env GOARCH)"',
            'Write-Output "Go target: $goTarget"',
            (
                f'if ($env:RUNNER_ARCH -ne "{runner_arch}") '
                f'{{ throw "expected {runner_arch} runner, got $env:RUNNER_ARCH" }}'
            ),
            (
                f'if ($goTarget -ne "{go_target}") '
                f'{{ throw "expected {go_target} Go target, got $goTarget" }}'
            ),
        ]
    return [
        "set -euo pipefail",
        'echo "runner architecture: $RUNNER_ARCH"',
        'go_target="$(go env GOOS)/$(go env GOARCH)"',
        'echo "Go target: $go_target"',
        f'test "$RUNNER_ARCH" = "{runner_arch}"',
        f'test "$go_target" = "{go_target}"',
    ]


def native_target_errors(workflow: dict) -> list[str]:
    """Return violations of the native target and architecture contract."""
    errors = []
    jobs = workflow["jobs"]
    # GitHub workflow syntax: workflow and job env are inherited by steps.
    # https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#env
    # Reject overrides of the values used by the native proof, including the
    # case-insensitive spellings accepted by the Windows environment.
    # `go help environment`: GOENV selects defaults for GOOS and GOARCH.
    def check_environment(scope: dict, name: str) -> None:
        environment = scope.get("env", {})
        if not isinstance(environment, dict) or any(
            str(key).upper() in {"GOOS", "GOARCH", "GOENV", "RUNNER_ARCH"}
            for key in environment
        ):
            errors.append(f"{name} overrides or obscures native proof environment")

    missing = object()

    # GitHub workflow syntax: the most specific defaults.run.shell wins.
    # https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#defaultsrun
    def default_shell(scope: dict) -> object:
        defaults = scope.get("defaults", {})
        if not isinstance(defaults, dict):
            return None
        run = defaults.get("run", {})
        if not isinstance(run, dict):
            return None
        return run.get("shell", missing)

    check_environment(workflow, "workflow")
    for job_name, (runner, runner_arch, go_target, shell) in NATIVE_TARGETS.items():
        job = jobs.get(job_name)
        if job is None:
            errors.append(f"missing {job_name}")
            continue
        if job.get("runs-on") != runner:
            errors.append(f"{job_name} does not use {runner}")
        if job.get("continue-on-error") is not None:
            errors.append(f"{job_name} allows its native proof to fail")
        # Join the topology check's existing docs-only skip contract. A job
        # condition must not silently bypass the required native evidence.
        condition = job.get("if")
        if not isinstance(condition, str) or " ".join(condition.split()) != " ".join(
            DOCS_SKIP_CONDITION.split()
        ):
            errors.append(f"{job_name} changes the docs-only skip condition")
        needs = job.get("needs")
        if not isinstance(needs, list) or set(needs) != {"security-scan", "changed-files"}:
            errors.append(f"{job_name} changes native proof dependencies")
        check_environment(job, job_name)
        steps = job.get("steps", [])
        proof_steps = [
            step
            for step in steps
            if step.get("name") == f"Verify native target is {go_target}"
        ]
        if len(proof_steps) != 1:
            errors.append(f"{job_name} does not have one architecture proof step")
            continue
        # Preserve the existing workflow order: checkout/setup actions, then
        # native proof before run commands can write GITHUB_ENV or go env -w.
        setup_steps = steps[:steps.index(proof_steps[0])]
        if any("run" in step for step in setup_steps):
            errors.append(f"{job_name} runs commands before its native proof")
        if [step.get("uses") for step in setup_steps] != NATIVE_SETUP_ACTIONS:
            errors.append(f"{job_name} changes native proof setup actions")
        if any(key in proof_steps[0] for key in ("if", "continue-on-error", "env")):
            errors.append(f"{job_name} does not require unmodified architecture proof")
        effective_shell = proof_steps[0].get("shell", missing)
        for inherited in (job, workflow):
            if effective_shell is missing:
                effective_shell = default_shell(inherited)
        if effective_shell is missing:
            effective_shell = shell
        if effective_shell != shell:
            errors.append(f"{job_name} overrides the architecture proof shell")
        proof = proof_steps[0].get("run", "")
        actual_lines = executable_lines(proof)
        expected_lines = expected_proof_lines(shell, runner_arch, go_target)
        if shell == "pwsh":
            runner_predicate = f'if ($env:RUNNER_ARCH -ne "{runner_arch}")'
            target_predicate = f'if ($goTarget -ne "{go_target}")'
            target_source = '$goTarget = "$(go env GOOS)/$(go env GOARCH)"'
        else:
            runner_predicate = f'test "$RUNNER_ARCH" = "{runner_arch}"'
            target_predicate = f'test "$go_target" = "{go_target}"'
            target_source = 'go_target="$(go env GOOS)/$(go env GOARCH)"'
        if not any(line.startswith(runner_predicate) for line in actual_lines):
            errors.append(f"{job_name} does not verify runner architecture {runner_arch}")
        if target_source not in actual_lines or not any(
            line.startswith(target_predicate) for line in actual_lines
        ):
            errors.append(f"{job_name} does not verify native Go target {go_target}")
        if actual_lines != expected_lines:
            errors.append(f"{job_name} does not use the straight-line architecture proof")
    return errors


class NativeTargetWorkflowTest(unittest.TestCase):
    """Protect native job labels and their runtime architecture assertions."""

    def setUp(self):
        """Load a fresh workflow model for each mutation test."""
        self.workflow = workflow_model()

    def test_native_targets_have_pinned_architecture_evidence(self):
        """Accept the checked-in native target contract."""
        self.assertEqual(native_target_errors(self.workflow), [])

    def test_runner_label_drift_fails_the_contract(self):
        """Reject a runner label that no longer proves the claimed pair."""
        for job_name, wrong_runner, expected_runner in (
            ("test-macos-intel", "macos-latest", "macos-26-intel"),
            ("test-macos-intel", "macos-15-intel", "macos-26-intel"),
            ("test-linux-arm64", "ubuntu-24.04-arm", "ubuntu-26.04-arm"),
            ("test-linux-arm64", "ubuntu-26.04", "ubuntu-26.04-arm"),
        ):
            with self.subTest(job=job_name, runner=wrong_runner):
                broken = copy.deepcopy(self.workflow)
                broken["jobs"][job_name]["runs-on"] = wrong_runner
                self.assertIn(
                    f"{job_name} does not use {expected_runner}",
                    native_target_errors(broken),
                )

    def test_missing_runtime_architecture_check_fails_the_contract(self):
        """Reject a proof step replaced with inert output."""
        broken = copy.deepcopy(self.workflow)
        proof = next(
            step
            for step in broken["jobs"]["test-windows-arm64"]["steps"]
            if step.get("name") == "Verify native target is windows/arm64"
        )
        proof["run"] = 'Write-Output "windows/arm64"'
        self.assertIn(
            "test-windows-arm64 does not verify runner architecture ARM64",
            native_target_errors(broken),
        )

    def test_skipped_or_nonfatal_proof_fails_the_contract(self):
        """Reject proof that CI may skip, ignore, or run with supplied target values."""
        for job_name, (_, _, go_target, _) in NATIVE_TARGETS.items():
            for field, value in (
                ("if", False),
                ("continue-on-error", True),
                ("env", {"GOOS": "darwin", "GOARCH": "amd64"}),
            ):
                with self.subTest(job=job_name, field=field):
                    broken = copy.deepcopy(self.workflow)
                    proof = next(
                        step for step in broken["jobs"][job_name]["steps"]
                        if step.get("name") == f"Verify native target is {go_target}"
                    )
                    proof[field] = value
                    self.assertIn(
                        f"{job_name} does not require unmodified architecture proof",
                        native_target_errors(broken),
                    )
            broken = copy.deepcopy(self.workflow)
            broken["jobs"][job_name]["continue-on-error"] = True
            self.assertIn(
                f"{job_name} allows its native proof to fail",
                native_target_errors(broken),
            )

    def test_job_skip_conditions_fail_the_contract(self):
        """Allow only the existing topology docs carve-out for every native job."""
        for job_name in NATIVE_TARGETS:
            for condition in (False, None, "false", "${{ false }}",
                              DOCS_SKIP_CONDITION.replace("!cancelled()", "false")):
                with self.subTest(job=job_name, condition=condition):
                    broken = copy.deepcopy(self.workflow)
                    broken["jobs"][job_name]["if"] = condition
                    self.assertIn(
                        f"{job_name} changes the docs-only skip condition",
                        native_target_errors(broken),
                    )
            broken = copy.deepcopy(self.workflow)
            broken["jobs"][job_name]["needs"] = ["security-scan"]
            self.assertIn(
                f"{job_name} changes native proof dependencies",
                native_target_errors(broken),
            )

    def test_inherited_target_environment_fails_the_contract(self):
        """Reject forged target values at both inherited environment scopes."""
        for scope in ("workflow", *NATIVE_TARGETS):
            for environment in (
                {"GOOS": "darwin"}, {"GOARCH": "amd64"},
                {"GOENV": "forged.env"}, {"goenv": "forged.env"},
                {"RUNNER_ARCH": "X64"}, {"goarch": "amd64"},
                "${{ inputs.environment }}", None,
            ):
                with self.subTest(scope=scope, environment=environment):
                    broken = copy.deepcopy(self.workflow)
                    target = broken if scope == "workflow" else broken["jobs"][scope]
                    target["env"] = environment
                    self.assertIn(
                        f"{scope} overrides or obscures native proof environment",
                        native_target_errors(broken),
                    )

    def test_native_setup_action_changes_fail_the_contract(self):
        """Preserve the pinned setup sequence before every native proof."""
        for job_name in NATIVE_TARGETS:
            for mutation in ("extra", "reordered", "missing", "changed", "duplicate"):
                with self.subTest(job=job_name, mutation=mutation):
                    workflow = copy.deepcopy(self.workflow)
                    steps = workflow["jobs"][job_name]["steps"]
                    if mutation == "extra":
                        steps.insert(2, {"uses": "./.github/actions/target-override"})
                    elif mutation == "reordered":
                        steps[0], steps[1] = steps[1], steps[0]
                    elif mutation == "missing":
                        steps.pop(1)
                    elif mutation == "changed":
                        steps[1]["uses"] = "actions/setup-go@main"
                    else:
                        steps.insert(2, copy.deepcopy(steps[1]))
                    self.assertIn(
                        f"{job_name} changes native proof setup actions",
                        native_target_errors(workflow),
                    )
            workflow = copy.deepcopy(self.workflow)
            workflow["jobs"][job_name]["steps"].append(
                {"uses": "./.github/actions/after-proof"}
            )
            self.assertEqual(native_target_errors(workflow), [])

    def test_commands_before_native_proof_fail_the_contract(self):
        """Keep target-mutating commands behind the native proof in every lane."""
        for job_name, (_, _, target, _) in NATIVE_TARGETS.items():
            for command in (
                'go env -w GOARCH=amd64',
                'echo "GOARCH=amd64" >> "$GITHUB_ENV"',
                '"GOARCH=amd64" >> $env:GITHUB_ENV',
            ):
                with self.subTest(job=job_name, command=command):
                    workflow = copy.deepcopy(self.workflow)
                    steps = workflow["jobs"][job_name]["steps"]
                    index = next(i for i, step in enumerate(steps)
                                 if step.get("name") == f"Verify native target is {target}")
                    steps.insert(index, {"run": command})
                    self.assertIn(
                        f"{job_name} runs commands before its native proof",
                        native_target_errors(workflow),
                    )
                    steps.insert(index + 2, steps.pop(index))
                    self.assertEqual(native_target_errors(workflow), [])

    def test_unrelated_environment_and_condition_whitespace_are_allowed(self):
        """Keep harmless env settings and the existing docs exception valid."""
        workflow = copy.deepcopy(self.workflow)
        workflow["env"] = {"CI": "true"}
        for job_name in NATIVE_TARGETS:
            workflow["jobs"][job_name]["env"] = {"EXAMPLE_SETTING": "value"}
            workflow["jobs"][job_name]["if"] = DOCS_SKIP_CONDITION.replace(" && ", "  &&  ")
        self.assertEqual(native_target_errors(workflow), [])

    def test_effective_shell_overrides_fail_the_contract(self):
        """Reject inert, incompatible and malformed shells at every scope."""
        for job_name, (_, _, go_target, shell) in NATIVE_TARGETS.items():
            for scope in ("workflow", "job", "step"):
                for value in ("cat {0}", "python", "", None, False, [], {}):
                    with self.subTest(job=job_name, scope=scope, value=value):
                        workflow = copy.deepcopy(self.workflow)
                        job = workflow["jobs"][job_name]
                        proof = next(step for step in job["steps"]
                                     if step.get("name") == f"Verify native target is {go_target}")
                        proof.pop("shell", None)
                        if scope == "step":
                            proof["shell"] = value
                        else:
                            target = job if scope == "job" else workflow
                            target["defaults"] = {"run": {"shell": value}}
                        self.assertIn(
                            f"{job_name} overrides the architecture proof shell",
                            native_target_errors(workflow),
                        )

    def test_shell_precedence_and_defaults(self):
        """Accept the expected shell and harmless inherited settings."""
        for job_name, (_, _, go_target, shell) in NATIVE_TARGETS.items():
            for scope in ("workflow", "job", "step"):
                with self.subTest(job=job_name, scope=scope):
                    workflow = copy.deepcopy(self.workflow)
                    # Other lanes explicitly retain their required shells.
                    for name, (_, _, target, expected) in NATIVE_TARGETS.items():
                        proof = next(step for step in workflow["jobs"][name]["steps"]
                                     if step.get("name") == f"Verify native target is {target}")
                        proof["shell"] = expected
                    job = workflow["jobs"][job_name]
                    proof = next(step for step in job["steps"]
                                 if step.get("name") == f"Verify native target is {go_target}")
                    workflow["defaults"] = {"run": {"shell": "cat {0}"}}
                    if scope == "workflow":
                        proof.pop("shell")
                        workflow["defaults"]["run"]["shell"] = shell
                    elif scope == "job":
                        proof.pop("shell")
                        job["defaults"] = {"run": {"shell": shell}}
                    else:
                        job["defaults"] = {"run": {"shell": "cat {0}"}}
                    self.assertEqual(native_target_errors(workflow), [])
        workflow = copy.deepcopy(self.workflow)
        workflow["defaults"] = {"run": {"working-directory": "."}}
        self.assertEqual(native_target_errors(workflow), [])

    def test_malformed_shell_defaults_fail_the_contract(self):
        """Malformed inherited settings must not become an absent shell."""
        for scope in ("workflow", "job"):
            for value in (None, False, [], {"run": None}, {"run": []}):
                with self.subTest(scope=scope, value=value):
                    workflow = copy.deepcopy(self.workflow)
                    job = workflow["jobs"]["test-macos-intel"]
                    target = workflow if scope == "workflow" else job
                    target["defaults"] = value
                    self.assertIn(
                        "test-macos-intel overrides the architecture proof shell",
                        native_target_errors(workflow),
                    )

    def test_inverted_predicates_fail_the_contract(self):
        """Reject success predicates whose direction is reversed."""
        broken = copy.deepcopy(self.workflow)
        mac_proof = next(
            step
            for step in broken["jobs"]["test-macos-intel"]["steps"]
            if step.get("name") == "Verify native target is darwin/amd64"
        )
        mac_proof["run"] = mac_proof["run"].replace(
            'test "$RUNNER_ARCH" = "X64"',
            'test "$RUNNER_ARCH" != "X64"',
        )
        windows_proof = next(
            step
            for step in broken["jobs"]["test-windows-arm64"]["steps"]
            if step.get("name") == "Verify native target is windows/arm64"
        )
        windows_proof["run"] = windows_proof["run"].replace(
            'if ($goTarget -ne "windows/arm64")',
            'if ($goTarget -eq "windows/arm64")',
        )
        errors = native_target_errors(broken)
        self.assertIn(
            "test-macos-intel does not verify runner architecture X64",
            errors,
        )
        self.assertIn(
            "test-windows-arm64 does not verify native Go target windows/arm64",
            errors,
        )

    def test_commented_and_echoed_predicates_fail_the_contract(self):
        """Reject predicates that exist only as comments or log text."""
        broken = copy.deepcopy(self.workflow)
        mac_proof = next(
            step
            for step in broken["jobs"]["test-macos-intel"]["steps"]
            if step.get("name") == "Verify native target is darwin/amd64"
        )
        mac_proof["run"] = mac_proof["run"].replace(
            'test "$RUNNER_ARCH" = "X64"',
            '# test "$RUNNER_ARCH" = "X64"',
        )
        windows_proof = next(
            step
            for step in broken["jobs"]["test-windows-arm64"]["steps"]
            if step.get("name") == "Verify native target is windows/arm64"
        )
        windows_proof["run"] = windows_proof["run"].replace(
            'if ($goTarget -ne "windows/arm64")',
            'Write-Output \'if ($goTarget -ne "windows/arm64")\'; if ($false)',
        )
        errors = native_target_errors(broken)
        self.assertIn(
            "test-macos-intel does not verify runner architecture X64",
            errors,
        )
        self.assertIn(
            "test-windows-arm64 does not use the straight-line architecture proof",
            errors,
        )

    def test_dead_control_flow_fails_the_contract(self):
        """Reject valid predicates wrapped in unreachable shell control flow."""
        broken = copy.deepcopy(self.workflow)
        proof = next(
            step
            for step in broken["jobs"]["test-linux-arm64"]["steps"]
            if step.get("name") == "Verify native target is linux/arm64"
        )
        proof["run"] = f"if false; then\n{proof['run']}fi\n"
        self.assertIn(
            "test-linux-arm64 does not use the straight-line architecture proof",
            native_target_errors(broken),
        )


if __name__ == "__main__":
    unittest.main()
