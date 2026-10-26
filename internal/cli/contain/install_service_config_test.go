// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
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
	}
	if _, err := stepEnableSystemUnit().apply(t.Context(), env); err != nil {
		t.Fatal(err)
	}
	if len(observed) != 2 {
		t.Fatal("both validation phases did not run")
	}
	early, prospective := observed[0], observed[1]
	// Independent contracts: config/containment.go defines the managed marker,
	// TestRenderSystemUnit_StateHomeIsWritable owns writable state placement,
	// and scripts/e2e/browser_repro/managed.py checks the exact managed argv.
	wantEnvironment := []string{"PIPELOCK_CONTAINMENT_MANAGED=1", "XDG_STATE_HOME=" + filepath.Join(env.dataDir, "state")}
	wantArgv := []string{env.pipelockTarget, "run", "--config", filepath.Join(env.configDir, "pipelock.yaml"), "--capture-output", filepath.Join(env.dataDir, "captures")}
	if !slices.Equal(early.PlannedEnvironment, wantEnvironment) {
		t.Fatal("planned environment differs from the managed service contract")
	}
	if !slices.Equal(prospective.ExpectedExecStart, wantArgv) {
		t.Fatal("prospective command differs from the managed service contract")
	}
	unit := renderSystemUnit(env)
	for _, assignment := range wantEnvironment {
		if !strings.Contains(unit, "Environment="+assignment+"\n") {
			t.Fatal("planned environment missing from rendered unit")
		}
	}
	if !strings.Contains(unit, "ExecStart="+strings.Join(wantArgv, " ")+"\n") {
		t.Fatal("expected command missing from rendered unit")
	}
	if !early.AllowMissing || early.PlannedUser != env.proxyUserName || early.Binary != env.pipelockBinary || !early.RequireBuildCompatibility {
		t.Fatal("incorrect early check options")
	}
	if prospective.AllowMissing || prospective.ExpectedFragmentPath != env.systemUnitPath || prospective.Binary != env.pipelockTarget || prospective.ConfigFile != managedPipelockConfigPath(env) || !prospective.RequireBuildCompatibility {
		t.Fatal("incorrect prospective check options")
	}
}

func TestInstallStagedRelativeCompanionUsesManagedDirectory(t *testing.T) {
	for _, companionPresent := range []bool{true, false} {
		name := "managed companion missing"
		if companionPresent {
			name = "managed companion present"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv(config.EnvLicenseKey, "")
			env, _, _ := newPreflightInstallEnv(t)
			src := writePreflightConfig(t, "candidate.yaml", "mode: balanced\nforward_proxy:\n  enabled: true\nmetrics_listen: 127.0.0.1:9091\nlicense_file: license.txt\n")
			// A different token beside the source detects accidental use of
			// the operator's source directory instead of the managed directory.
			if err := os.WriteFile(filepath.Join(filepath.Dir(src), "license.txt"), []byte("source-token"), 0o600); err != nil {
				t.Fatal(err)
			}
			if companionPresent {
				if err := os.WriteFile(filepath.Join(env.configDir, "license.txt"), []byte("managed-token"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			opts := installOpts{configSource: src}
			if _, err := stepStagePipelockConfig(opts).apply(t.Context(), env); err != nil {
				t.Fatal(err)
			}
			target, err := pipelockConfigPreflightTargetFor(env, opts, false)
			if err != nil {
				t.Fatal(err)
			}
			if target.checkPath != filepath.Join(env.configDir, "pipelock.yaml.staged") || filepath.Dir(target.checkPath) != filepath.Dir(target.unitPath) {
				t.Fatal("staged candidate does not share the managed configuration directory")
			}
			env.checkServiceConfig = func(_ context.Context, o serviceenv.CheckOptions) error {
				cfg, err := config.Load(o.ConfigFile)
				if err == nil && (cfg.LicenseFile != "license.txt" || cfg.LicenseKey != "managed-token") {
					t.Fatal("staged loader did not resolve the managed relative companion")
				}
				return err
			}
			err = preflightPipelockConfig(t.Context(), env, opts, false)
			if !companionPresent {
				if err == nil {
					t.Fatal("source-only companion passed managed preflight")
				}
				if _, err := os.Stat(target.unitPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed preflight promoted the candidate")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stepPromotePipelockConfig(opts).apply(t.Context(), env); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(target.unitPath)
			if err != nil || cfg.LicenseFile != "license.txt" || cfg.LicenseKey != "managed-token" {
				t.Fatal("promotion changed relative companion resolution")
			}
		})
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
			}
			env.preflightBinaryHash = mustHashFile(t, env, env.pipelockTarget)
			var called, wantCalled bool
			var want string
			switch phase {
			case "missing early":
				env.checkServiceConfig = nil
				if err := preflightPipelockConfig(t.Context(), env, installOpts{}, false); err == nil || !strings.Contains(err.Error(), "requires service configuration validation") {
					t.Fatalf("missing early validator did not refuse: %v", err)
				}
				return
			case "missing prospective":
				env.checkServiceConfig = nil
				want = "validator is unavailable"
			case "before":
				env.preflightBinaryHash = "different"
				env.checkServiceConfig = func(context.Context, serviceenv.CheckOptions) error {
					called = true
					return nil
				}
				want = "differs from config-preflight binary"
			case "after":
				env.checkServiceConfig = func(context.Context, serviceenv.CheckOptions) error {
					called = true
					return os.WriteFile(env.pipelockTarget, []byte("changed"), 0o600)
				}
				want = "changed during prospective config validation"
				wantCalled = true
			}
			if err := validateProspectivePipelockConfig(t.Context(), env); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("wrong prospective refusal: got %v, want %q", err, want)
			}
			if called != wantCalled {
				t.Fatalf("prospective validator called=%v, want %v", called, wantCalled)
			}
		})
	}
}

func TestInstallProspectiveRequiresPreflightHash(t *testing.T) {
	env, _, _ := newPreflightInstallEnv(t)
	called := false
	env.checkServiceConfig = func(context.Context, serviceenv.CheckOptions) error {
		called = true
		return nil
	}
	err := validateProspectivePipelockConfig(t.Context(), env)
	if err == nil || !strings.Contains(err.Error(), "preflight binary identity") {
		t.Fatalf("missing preflight identity did not refuse service start: %v", err)
	}
	if called {
		t.Fatal("prospective validator ran without preflight binary identity")
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

func TestInstallDryRunDefersUnavailableServiceEnvironment(t *testing.T) {
	env, runner, out := newPreflightInstallEnv(t)
	src := writePreflightConfig(t, "candidate.yaml", "forward_proxy:\n  enabled: true\n")
	env.checkServiceConfig = func(context.Context, serviceenv.CheckOptions) error { return serviceenv.ErrUnavailable }
	if err := runInstall(t.Context(), env, installOpts{dryRun: true, configSource: src}); err != nil {
		t.Fatalf("plan inspection refused unavailable environment: %v", err)
	}
	if !strings.Contains(out.String(), "[DEFERRED]") || !strings.Contains(out.String(), "not validated") {
		t.Fatal("deferred validation was not disclosed")
	}
	if env.preflightBinaryHash != "" {
		t.Fatal("deferred validation recorded an assurance hash")
	}
	assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
}

func TestInstallDryRunUnavailableValidationBoundary(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		wantRefuse bool
		needsToken bool
	}{
		{name: "malformed YAML", body: "forward_proxy:\n  enabled: true\nbroken: [\n", wantRefuse: true},
		{name: "invalid field type", body: "forward_proxy:\n  enabled: true\nmode: []\n", wantRefuse: true},
		{name: "unknown schema field", body: "forward_proxy:\n  enabled: true\nunknown_option: true\n"},
		{name: "invalid semantic value", body: "forward_proxy:\n  enabled: true\nmode: invalid\n"},
		{name: "service environment dependency", body: "forward_proxy:\n  enabled: true\nkill_switch:\n  api_listen: 127.0.0.1:9090\n", needsToken: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.EnvKillSwitchAPIToken, "")
			env, runner, out := newPreflightInstallEnv(t)
			src := writePreflightConfig(t, "candidate.yaml", tc.body)
			if _, err := config.Load(src); err == nil {
				t.Fatal("actual config loader accepted the invalid caller-context fixture")
			}
			if tc.needsToken {
				t.Setenv(config.EnvKillSwitchAPIToken, "service-fixture-token")
				if _, err := config.Load(src); err != nil {
					t.Fatal("environment-dependent fixture did not pass with its required input")
				}
				t.Setenv(config.EnvKillSwitchAPIToken, "")
			}
			checks := 0
			env.checkServiceConfig = func(context.Context, serviceenv.CheckOptions) error {
				checks++
				return serviceenv.ErrUnavailable
			}
			err := preflightPipelockConfig(t.Context(), env, installOpts{configSource: src}, true)
			if (err != nil) != tc.wantRefuse || checks != 1 {
				t.Fatal("dry-run did not preserve the parse-refusal/service-validation boundary")
			}
			if !strings.Contains(out.String(), "[DEFERRED]") || !strings.Contains(out.String(), "configuration not validated") || env.preflightBinaryHash != "" {
				t.Fatal("dry-run incorrectly claimed service validation")
			}
			// A caller-context fallback would reject the environment-dependent
			// fixture even though the actual service input makes it valid.
			if len(runner.calls) != 0 {
				t.Fatal("unavailable service validation invoked a caller-context fallback")
			}
			assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
		})
	}
}

func TestInstallUnavailableEnvironmentStillRefusesRealMutation(t *testing.T) {
	env, runner, _ := newPreflightInstallEnv(t)
	seedManagedConfig(t, env)
	env.checkServiceConfig = func(context.Context, serviceenv.CheckOptions) error { return serviceenv.ErrUnavailable }
	if err := preflightPipelockConfig(t.Context(), env, installOpts{}, false); !errors.Is(err, serviceenv.ErrUnavailable) {
		t.Fatalf("real preflight accepted unavailable environment: %v", err)
	}
	if env.preflightBinaryHash != "" {
		t.Fatal("unavailable environment recorded assurance hash")
	}
	assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
}

func TestInstallFreshIdentityExistsBeforeServiceValidation(t *testing.T) {
	env, runner, _ := newPreflightInstallEnv(t)
	src := writePreflightConfig(t, "candidate.yaml", "forward_proxy:\n  enabled: true\n")
	created := false
	lookup := env.lookupUser
	env.lookupUser = func(name string) (*user.User, error) {
		if name == env.proxyUserName && !created {
			return nil, user.UnknownUserError(name)
		}
		return lookup(name)
	}
	run := env.runCmd
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		if name == "useradd" && slices.Contains(args, env.proxyUserName) {
			created = true
		}
		return run(ctx, name, args...)
	}
	checks := 0
	env.checkServiceConfig = func(context.Context, serviceenv.CheckOptions) error {
		if !created {
			t.Fatal("service validation preceded planned identity creation")
		}
		checks++
		return errors.New("stop before config promotion")
	}
	if err := runInstall(t.Context(), env, installOpts{configSource: src}); err == nil || checks != 1 || !created {
		t.Fatal("fresh identity sequence did not reach service validation")
	}
	for _, call := range runner.calls {
		for _, action := range []string{"start", "restart", "enable"} {
			if call.name == "systemctl" && len(call.args) > 0 && call.args[0] == action {
				t.Fatal("service activated before validation")
			}
		}
	}
}

func TestInstallNativeCredentialRefusalPreservesServiceInputs(t *testing.T) {
	for _, phase := range []string{"early", "prospective"} {
		t.Run(phase, func(t *testing.T) {
			env, runner, _ := newPreflightInstallEnv(t)
			target := seedManagedConfig(t, env)
			preserved := map[string][]byte{}
			body, err := os.ReadFile(filepath.Clean(target))
			if err != nil {
				t.Fatal(err)
			}
			preserved[target] = body
			credential := filepath.Join(env.configDir, "admin-token.encrypted")
			dropin := filepath.Join(env.configDir, "credentials.conf")
			for path, body := range map[string][]byte{
				credential:         []byte("opaque-encrypted-fixture"),
				dropin:             []byte("[Service]\nLoadCredentialEncrypted=admin-token:" + credential + "\nExecStartPre=/bin/false\n"),
				env.systemUnitPath: []byte("[Service]\nUser=pipelock-proxy\nExecStart=/usr/local/bin/pipelock run\n"),
				env.pipelockTarget: []byte("prior-binary"),
			} {
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
				preserved[path] = body
			}
			runner.on(argvFor("systemctl", "is-active", "pipelock"), "active\n", 0, nil)
			runner.on(argvFor("systemctl", "is-enabled", "pipelock"), "enabled\n", 0, nil)
			env.checkServiceConfig = func(_ context.Context, opts serviceenv.CheckOptions) error {
				if phase == "early" || !opts.AllowMissing {
					return errors.New("service configuration validation does not support ExecStartPre; migrate to kill_switch.api_token_file")
				}
				return nil
			}
			src := writePreflightConfig(t, "candidate.yaml", "mode: balanced\nforward_proxy:\n  enabled: true\nkill_switch:\n  api_token_file: $CREDENTIALS_DIRECTORY/admin-token\n")
			if err := runInstall(t.Context(), env, installOpts{configSource: src}); err == nil || !strings.Contains(err.Error(), "api_token_file") {
				t.Fatalf("credential refusal lost: %v", err)
			}
			if phase == "early" {
				assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
			}
			for path, want := range preserved {
				got, err := os.ReadFile(filepath.Clean(path))
				if err != nil || string(got) != string(want) {
					t.Fatalf("credential refusal changed %s", path)
				}
			}
			for _, call := range runner.calls {
				for _, action := range []string{"start", "stop", "restart"} {
					if argvFor(call.name, call.args...) == argvFor("systemctl", action, "pipelock") {
						t.Fatal("rejected native credential changed the active service")
					}
				}
			}
		})
	}
}
