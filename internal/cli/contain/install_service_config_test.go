// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/serviceenv"
)

func TestInstallServiceConfigOptionsAndOrdering(t *testing.T) {
	env, runner, _ := newPreflightInstallEnv(t)
	seedManagedConfig(t, env)
	var observed []serviceenv.CheckOptions
	env.checkServiceConfig = func(_ context.Context, opts serviceenv.CheckOptions) error {
		observed = append(observed, opts)
		if !opts.AllowMissing {
			if len(runner.calls) == 0 || argvFor(runner.calls[len(runner.calls)-1].name, runner.calls[len(runner.calls)-1].args...) != argvFor("systemctl", "daemon-reload") {
				t.Fatal("prospective check did not immediately follow reload")
			}
		}
		return nil
	}
	if err := preflightPipelockConfig(t.Context(), env, installOpts{}, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.pipelockTarget, []byte("fake pipelock binary"), 0o600); err != nil {
		t.Fatal(err)
	} //nolint:gosec // executable fixture.
	if _, err := stepEnableSystemUnit().apply(t.Context(), env); err != nil {
		t.Fatal(err)
	}
	if len(observed) != 2 {
		t.Fatal("both validation phases did not run")
	}
	early, prospective := observed[0], observed[1]
	if !early.AllowMissing || early.PlannedUser != env.proxyUserName || early.Binary != env.pipelockBinary || !early.RequireBuildCompatibility {
		t.Fatal("incorrect early check options")
	}
	if prospective.AllowMissing || prospective.ExpectedFragmentPath != env.systemUnitPath || prospective.Binary != env.pipelockTarget || prospective.ConfigFile != managedPipelockConfigPath(env) || !prospective.RequireBuildCompatibility {
		t.Fatal("incorrect prospective check options")
	}
}

func TestInstallProspectiveRejectionRollsBackWithoutRestartingPriorService(t *testing.T) {
	env, runner, _ := newPreflightInstallEnv(t)
	target := seedManagedConfig(t, env)
	oldConfig, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		t.Fatal(err)
	}
	oldUnit := []byte("[Service]\nUser=pipelock-proxy\nExecStart=/usr/local/bin/pipelock run\n")
	oldBinary := []byte("previous binary")
	for path, body := range map[string][]byte{env.systemUnitPath: oldUnit, env.pipelockTarget: oldBinary} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Explicitly establish a previously running service. The failing attempt
	// must never reach any service start/stop/restart/enable operation.
	runner.on(argvFor("systemctl", "is-active", "pipelock"), "active\n", 0, nil)
	runner.on(argvFor("systemctl", "is-enabled", "pipelock"), "enabled\n", 0, nil)
	env.checkServiceConfig = func(_ context.Context, opts serviceenv.CheckOptions) error {
		if !opts.AllowMissing {
			return errors.New("prospective environment rejected")
		}
		return nil
	}
	src := writePreflightConfig(t, "candidate.yaml", "mode: strict\nforward_proxy:\n  enabled: true\nmetrics_listen: 127.0.0.1:9091\n")
	err = runInstall(t.Context(), env, installOpts{configSource: src})
	if err == nil || !strings.Contains(err.Error(), "prospective environment rejected") {
		t.Fatalf("unexpected install outcome: %v", err)
	}
	for path, want := range map[string][]byte{target: oldConfig, env.systemUnitPath: oldUnit, env.pipelockTarget: oldBinary} {
		got, err := os.ReadFile(filepath.Clean(path))
		if err != nil || string(got) != string(want) {
			t.Fatalf("rollback did not restore %s", path)
		}
	}
	for _, call := range runner.calls {
		argv := argvFor(call.name, call.args...)
		for _, action := range []string{"stop", "start", "restart", "enable", "disable"} {
			if argv == argvFor("systemctl", action, "pipelock") || argv == argvFor("systemctl", action, "--now", "pipelock") {
				t.Fatalf("prior service changed: %s", argv)
			}
		}
	}
}

func TestInstallServiceConfigRefusesMissingValidatorAndBinaryChanges(t *testing.T) {
	for _, phase := range []string{"missing early", "missing prospective", "before", "after"} {
		t.Run(phase, func(t *testing.T) {
			env, _, _ := newPreflightInstallEnv(t)
			seedManagedConfig(t, env)
			if err := os.WriteFile(env.pipelockTarget, []byte("fake pipelock binary"), 0o600); err != nil {
				t.Fatal(err)
			} //nolint:gosec // executable fixture.
			env.preflightBinaryHash = mustHashFile(t, env, env.pipelockTarget)
			switch phase {
			case "missing early":
				env.checkServiceConfig = nil
				if preflightPipelockConfig(t.Context(), env, installOpts{}, false) == nil {
					t.Fatal("missing early validator accepted")
				}
				return
			case "missing prospective":
				env.checkServiceConfig = nil
			case "before":
				env.preflightBinaryHash = "different"
			case "after":
				env.checkServiceConfig = func(context.Context, serviceenv.CheckOptions) error {
					return os.WriteFile(env.pipelockTarget, []byte("changed"), 0o600)
				}
			}
			if validateProspectivePipelockConfig(t.Context(), env) == nil {
				t.Fatal("unsafe prospective validation accepted")
			}
		})
	}
}

func TestInstallServiceConfigResolvesRelativeSelections(t *testing.T) {
	env, _, _ := newPreflightInstallEnv(t)
	src := writePreflightConfig(t, "candidate.yaml", "forward_proxy:\n  enabled: true\n")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	absBinary := env.pipelockBinary
	env.pipelockBinary, err = filepath.Rel(cwd, absBinary)
	if err != nil {
		t.Fatal(err)
	}
	relSource, err := filepath.Rel(cwd, src)
	if err != nil {
		t.Fatal(err)
	}
	env.checkServiceConfig = func(_ context.Context, opts serviceenv.CheckOptions) error {
		if opts.Binary != absBinary || opts.ConfigFile != src {
			t.Fatal("relative selection did not resolve to absolute validator inputs")
		}
		return nil
	}
	if err := preflightPipelockConfig(t.Context(), env, installOpts{configSource: relSource}, true); err != nil {
		t.Fatal(err)
	}
}

// The validator refuses a leaf symlink, while install hashes and copies
// through one, so the early check must receive the resolved regular file.
func TestInstallServiceConfigResolvesSymlinkedValidator(t *testing.T) {
	env, _, _ := newPreflightInstallEnv(t)
	src := writePreflightConfig(t, "candidate.yaml", "forward_proxy:\n  enabled: true\n")
	resolved, err := filepath.EvalSymlinks(env.pipelockBinary)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "pipelock-link")
	if err := os.Symlink(resolved, link); err != nil {
		t.Fatal(err)
	}
	env.pipelockBinary = link
	var got string
	env.checkServiceConfig = func(_ context.Context, opts serviceenv.CheckOptions) error {
		got = opts.Binary
		return nil
	}
	if err := preflightPipelockConfig(t.Context(), env, installOpts{configSource: src}, true); err != nil {
		t.Fatal(err)
	}
	if got != resolved {
		t.Fatalf("validator received %q, want resolved regular file %q", got, resolved)
	}
}
