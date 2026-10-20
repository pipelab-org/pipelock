// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const candidatePath = "/etc/pipelock/pipelock.yaml"

func typed(signature string, value any) []byte {
	body, _ := json.Marshal(struct {
		Type string `json:"type"`
		Data any    `json:"data"`
	}{signature, value})
	return body
}

type fixture struct {
	properties  map[string][]byte
	files       map[string][]byte
	show        string
	executions  int
	environment []string
	b           backend
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		properties: make(map[string][]byte),
		files:      map[string][]byte{candidatePath: []byte("mode: balanced\n")},
		show:       "Id=pipelock.service\nLoadState=loaded\nNeedDaemonReload=no\nTransient=no\n",
	}
	for _, name := range []string{"Environment", "UnsetEnvironment", "SupplementaryGroups", "PassEnvironment", "ImportCredential", "DropInPaths"} {
		f.properties[name] = typed("as", []string{})
	}
	for _, name := range []string{"Group", "PAMName", "RootDirectory", "RootImage", "WorkingDirectory"} {
		f.properties[name] = typed("s", "")
	}
	for _, name := range []string{"LoadCredential", "LoadCredentialEncrypted"} {
		f.properties[name] = typed("a(ss)", []any{})
	}
	for _, name := range []string{"SetCredential", "SetCredentialEncrypted"} {
		f.properties[name] = typed("a(say)", []any{})
	}
	for _, name := range []string{"ExecStartPre", "ExecCondition"} {
		f.properties[name] = typed("a(sasbttttuii)", []any{})
	}
	f.properties["EnvironmentFiles"] = typed("a(sb)", []any{})
	f.properties["DynamicUser"] = typed("b", false)
	f.properties["SetLoginEnvironment"] = typed("b", true)
	f.properties["User"] = typed("s", "pipelock-proxy")
	f.properties["FragmentPath"] = typed("s", "/etc/systemd/system/pipelock.service")
	f.properties["manager:Environment"] = typed("as", []string{})
	f.properties["manager:Version"] = typed("s", "262 (262.1)")
	f.b.command = func(_ context.Context, binary string, args ...string) ([]byte, int, error) {
		if binary == "/usr/bin/systemctl" {
			return []byte(f.show), 0, nil
		}
		if binary != "/usr/bin/busctl" {
			return nil, -1, errors.New("unexpected helper")
		}
		if slices.Contains(args, "introspect") {
			var out strings.Builder
			for name, body := range f.properties {
				if strings.HasPrefix(name, "manager:") || name == "FragmentPath" || name == "DropInPaths" {
					continue
				}
				var envelope struct {
					Type string `json:"type"`
				}
				_ = json.Unmarshal(body, &envelope)
				_, _ = fmt.Fprintf(&out, ".%s property %s - const\n", name, envelope.Type)
			}
			return []byte(out.String()), 0, nil
		}
		name := args[len(args)-1]
		if args[len(args)-2] == managerInterface {
			name = "manager:" + name
		}
		value, ok := f.properties[name]
		if !ok {
			return nil, 1, nil
		}
		return value, 0, nil
	}
	f.b.readFile = func(path string) (fileImage, error) {
		body, ok := f.files[path]
		if !ok {
			return fileImage{}, errMissingFile
		}
		return fileImage{Data: slices.Clone(body), Stamp: contentStamp(body, "fixture")}, nil
	}
	f.b.identity = func(string, string, []string) (identity, error) {
		return identity{UID: 1000, GID: 1000, Groups: []uint32{1000, 1001}, Home: "/var/lib/pipelock-proxy"}, nil
	}
	f.b.execute = func(_ context.Context, _ CheckOptions, env []string, _ identity, _ []byte) error {
		f.executions++
		f.environment = slices.Clone(env)
		return nil
	}
	return f
}

func fixtureOptions() CheckOptions {
	return CheckOptions{Binary: "/usr/local/bin/pipelock", ConfigFile: candidatePath, Service: Unit, RequireBuildCompatibility: true}
}

func TestConfigurationEnvironmentPrecedence(t *testing.T) {
	f := newFixture(t)
	f.properties["manager:Environment"] = typed("as", []string{config.EnvKillSwitchAPIToken + "=manager", config.EnvLicenseKey + "=manager-license", "LD_PRELOAD=/untrusted"})
	f.properties["Environment"] = typed("as", []string{config.EnvKillSwitchAPIToken + "=unit", "PIPELOCK_HOME=/service/home%literal"})
	f.properties["EnvironmentFiles"] = typed("a(sb)", []any{[]any{"/run/env-one", false}, []any{"/run/env-two", false}})
	f.files["/run/env-one"] = []byte(config.EnvKillSwitchAPIToken + "=first\n" + config.EnvLicenseCRLFile + "=/first\n")
	f.files["/run/env-two"] = []byte(config.EnvKillSwitchAPIToken + "=second\n" + config.EnvLicenseCRLFile + "=\n")
	f.properties["UnsetEnvironment"] = typed("as", []string{config.EnvLicenseKey, config.EnvKillSwitchAPIToken + "=different"})
	if err := check(t.Context(), fixtureOptions(), f.b); err != nil {
		t.Fatal(err)
	}
	want := []string{"HOME=/var/lib/pipelock-proxy", "PIPELOCK_HOME=/service/home%literal", config.EnvKillSwitchAPIToken + "=second", config.EnvLicenseCRLFile + "="}
	slices.Sort(want)
	if !slices.Equal(f.environment, want) {
		t.Fatalf("environment precedence mismatch: got %q", f.environment)
	}
	if f.executions != 1 {
		t.Fatal("validator did not run exactly once")
	}
}

func TestCandidateUsesItsOwnReader(t *testing.T) {
	f := newFixture(t)
	var delivered []byte
	f.b.readCandidate = func(path string) (fileImage, error) {
		if path != candidatePath {
			t.Fatalf("candidate reader got %s", path)
		}
		return fileImage{Data: []byte("candidate-bytes"), Stamp: "candidate"}, nil
	}
	f.b.execute = func(_ context.Context, _ CheckOptions, _ []string, _ identity, candidate []byte) error {
		delivered = slices.Clone(candidate)
		return nil
	}
	if err := check(t.Context(), fixtureOptions(), f.b); err != nil {
		t.Fatal(err)
	}
	if string(delivered) != "candidate-bytes" {
		t.Fatal("validator did not receive the candidate reader's bytes")
	}
}

func TestConfigurationEnvironmentUnsetMatchesExactAssignment(t *testing.T) {
	for _, unset := range []string{config.EnvKillSwitchAPIToken, config.EnvKillSwitchAPIToken + "=token"} {
		f := newFixture(t)
		f.properties["Environment"] = typed("as", []string{config.EnvKillSwitchAPIToken + "=token"})
		f.properties["UnsetEnvironment"] = typed("as", []string{unset})
		if err := check(t.Context(), fixtureOptions(), f.b); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(f.environment, config.EnvKillSwitchAPIToken+"=token") {
			t.Fatal("unset assignment survived")
		}
	}
}

func TestServiceRefusesUnsupportedContexts(t *testing.T) {
	for name, value := range map[string][]byte{
		"PassEnvironment": typed("as", []string{"SECRET"}), "PAMName": typed("s", "login"), "DynamicUser": typed("b", true),
		"RootDirectory": typed("s", "/rootfs"), "RootImage": typed("s", "/root.img"), "WorkingDirectory": typed("s", "/custom"),
		"LoadCredential": typed("a(ss)", []any{[]string{"key", "/key"}}), "LoadCredentialEncrypted": typed("a(ss)", []any{[]string{"key", "/key"}}),
		"SetCredential": typed("a(say)", []any{[]any{"key", []int{1}}}), "SetCredentialEncrypted": typed("a(say)", []any{[]any{"key", []int{1}}}),
		"ImportCredential": typed("as", []string{"key"}), "ExecStartPre": typed("a(sasbttttuii)", []any{[]any{"command"}}), "ExecCondition": typed("a(sasbttttuii)", []any{[]any{"command"}}),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.properties[name] = value
			if err := check(t.Context(), fixtureOptions(), f.b); err == nil || f.executions != 0 {
				t.Fatal("unsupported context reached validator")
			}
		})
	}
}

func TestServiceIdentityAndObservationFailures(t *testing.T) {
	for name, show := range map[string]string{
		"wrong unit":     "Id=other.service\nLoadState=loaded\nNeedDaemonReload=no\nTransient=no\n",
		"missing":        "Id=pipelock.service\nLoadState=not-found\nNeedDaemonReload=no\nTransient=no\n",
		"masked":         "Id=pipelock.service\nLoadState=masked\nNeedDaemonReload=no\nTransient=no\n",
		"stale":          "Id=pipelock.service\nLoadState=loaded\nNeedDaemonReload=yes\nTransient=no\n",
		"transient":      "Id=pipelock.service\nLoadState=loaded\nNeedDaemonReload=no\nTransient=yes\n",
		"duplicate":      "Id=pipelock.service\nLoadState=loaded\nNeedDaemonReload=no\nTransient=no\nId=pipelock.service\n",
		"missing fields": "Id=pipelock.service\nLoadState=loaded\n",
		"unknown field":  "Id=pipelock.service\nLoadState=loaded\nNeedDaemonReload=no\nTransient=no\nUnknown=x\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.show = show
			if check(t.Context(), fixtureOptions(), f.b) == nil || f.executions != 0 {
				t.Fatal("invalid service identity reached validator")
			}
		})
	}
	for _, fail := range []string{"timeout", "command error", "nonzero", "oversize", "identity lookup", "typed malformed", "login null", "missing property"} {
		t.Run(fail, func(t *testing.T) {
			f := newFixture(t)
			switch fail {
			case "timeout", "command error":
				f.b.command = func(context.Context, string, ...string) ([]byte, int, error) {
					return nil, -1, context.DeadlineExceeded
				}
			case "nonzero":
				f.b.command = func(context.Context, string, ...string) ([]byte, int, error) { return []byte(f.show), 1, nil }
			case "oversize":
				f.show = strings.Repeat("x", maxObservationBytes+1)
			case "identity lookup":
				f.b.identity = func(string, string, []string) (identity, error) { return identity{}, errors.New("secret-sentinel") }
			case "typed malformed":
				f.properties["Environment"] = []byte(`{"type":"as","data":["secret-sentinel",]}`)
			case "login null":
				f.properties["SetLoginEnvironment"] = typed("b", nil)
			case "missing property":
				delete(f.properties, "EnvironmentFiles")
			}
			err := check(t.Context(), fixtureOptions(), f.b)
			if err == nil || f.executions != 0 || strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatal("observation failure did not fail safely")
			}
		})
	}
}

func TestServiceFilesFailClosed(t *testing.T) {
	for _, name := range []string{"required missing", "optional missing", "unreadable optional", "malformed optional", "glob", "relative", "noncanonical", "candidate missing"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			path := "/run/env"
			optional := false
			wantSuccess := false
			switch name {
			case "optional missing":
				optional = true
				wantSuccess = true
			case "unreadable optional":
				optional = true
				f.b.readFile = func(string) (fileImage, error) { return fileImage{}, errors.New("denied secret-sentinel") }
			case "malformed optional":
				optional = true
				f.files[path] = []byte("TOKEN='secret-sentinel")
			case "glob":
				path = "/run/*.env"
			case "relative":
				path = "run/env"
			case "noncanonical":
				path = "/run/../run/env"
			case "candidate missing":
				delete(f.files, candidatePath)
				f.files[path] = []byte("A=value\n")
			}
			f.properties["EnvironmentFiles"] = typed("a(sb)", []any{[]any{path, optional}})
			err := check(t.Context(), fixtureOptions(), f.b)
			if (err == nil) != wantSuccess {
				t.Fatal("unexpected service-file validation result")
			}
			if err != nil && strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatal("file error exposed a value")
			}
		})
	}
}

func TestServiceSnapshotChanges(t *testing.T) {
	for _, change := range []string{"manager", "unit", "environment file", "candidate", "identity"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			identityChanged := false
			originalIdentity := f.b.identity
			f.b.identity = func(name, group string, additional []string) (identity, error) {
				if identityChanged {
					return identity{UID: 2000, Home: "/different"}, nil
				}
				return originalIdentity(name, group, additional)
			}
			f.properties["EnvironmentFiles"] = typed("a(sb)", []any{[]any{"/run/env", false}})
			f.files["/run/env"] = []byte("A=before\n")
			f.b.execute = func(context.Context, CheckOptions, []string, identity, []byte) error {
				switch change {
				case "manager":
					f.properties["manager:Environment"] = typed("as", []string{"A=after"})
				case "unit":
					f.properties["Environment"] = typed("as", []string{"A=after"})
				case "environment file":
					f.files["/run/env"] = []byte("A=after\n")
				case "candidate":
					f.files[candidatePath] = []byte("mode: strict\n")
				case "identity":
					identityChanged = true
				}
				return nil
			}
			if err := check(t.Context(), fixtureOptions(), f.b); err == nil || !strings.Contains(err.Error(), "changed") {
				t.Fatal("changed snapshot was accepted")
			}
		})
	}
}

func TestServiceOptionsAndMissingUnit(t *testing.T) {
	for _, alter := range []func(*CheckOptions){func(o *CheckOptions) { o.Service = "other.service" }, func(o *CheckOptions) { o.ConfigFile = "-" }, func(o *CheckOptions) { o.ConfigFile = "relative" }, func(o *CheckOptions) { o.Binary = "relative" }} {
		f := newFixture(t)
		opts := fixtureOptions()
		alter(&opts)
		if check(t.Context(), opts, f.b) == nil {
			t.Fatal("invalid check options accepted")
		}
	}
	f := newFixture(t)
	f.show = "Id=pipelock.service\nLoadState=not-found\nNeedDaemonReload=no\nTransient=no\n"
	opts := fixtureOptions()
	opts.AllowMissing = true
	if check(t.Context(), opts, f.b) == nil {
		t.Fatal("missing planned identity accepted")
	}
	opts.PlannedUser = "pipelock-proxy"
	opts.PlannedEnvironment = []string{config.EnvKillSwitchAPIToken + "=planned"}
	if err := check(t.Context(), opts, f.b); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.environment, config.EnvKillSwitchAPIToken+"=planned") {
		t.Fatal("planned environment missing")
	}
	opts.ExpectedFragmentPath = "/etc/systemd/system/pipelock.service"
	if check(t.Context(), opts, f.b) == nil {
		t.Fatal("provisional missing unit accepted as prospective unit")
	}
	f = newFixture(t)
	opts = fixtureOptions()
	opts.ExpectedFragmentPath = "/wrong/path"
	if check(t.Context(), opts, f.b) == nil {
		t.Fatal("wrong prospective fragment accepted")
	}
}

func TestChildErrorDoesNotExposeValues(t *testing.T) {
	f := newFixture(t)
	f.b.execute = func(context.Context, CheckOptions, []string, identity, []byte) error {
		return errors.New("secret-sentinel")
	}
	err := check(t.Context(), fixtureOptions(), f.b)
	if err == nil || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatal("child error was not withheld")
	}
}

func TestConfigurationProjectionIgnoresCallerAndLoader(t *testing.T) {
	t.Setenv(config.EnvKillSwitchAPIToken, "caller-secret")
	got := configurationEnvironment(map[string]string{"LD_PRELOAD": "/untrusted", "GODEBUG": "untrusted", "PATH": "/untrusted", config.EnvLicenseKey: "service-license"})
	if !slices.Equal(got, []string{config.EnvLicenseKey + "=service-license"}) {
		t.Fatal("unrelated or caller environment reached validator")
	}
	for _, assignments := range [][]string{{"NO_EQUALS"}, {"1BAD=x"}, {"A=x\x00y"}} {
		if applyAssignments(map[string]string{}, assignments) == nil {
			t.Fatal("invalid environment assignment accepted")
		}
	}
}

func TestMalformedConfigurationInputsRefuse(t *testing.T) {
	for name, body := range map[string][]byte{
		"manager:Environment": typed("as", []string{"missing-equals"}),
		"User":                typed("s", true), "SupplementaryGroups": typed("as", []any{nil}),
		"SetLoginEnvironment": typed("b", "false"), "Environment": typed("as", []string{"bad assignment"}),
		"EnvironmentFiles": typed("a(sb)", []any{[]any{"/run/env", nil}}),
		"UnsetEnvironment": typed("as", []string{"1BAD"}), "FragmentPath": typed("s", true), "DropInPaths": typed("as", []any{nil}),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.properties[name] = body
			if check(t.Context(), fixtureOptions(), f.b) == nil || f.executions != 0 {
				t.Fatal("malformed configuration input accepted")
			}
		})
	}
	for _, phase := range []string{"planned identity", "planned assignments", "after observation", "manager typed", "missing fragment"} {
		t.Run(phase, func(t *testing.T) {
			f := newFixture(t)
			opts := fixtureOptions()
			switch phase {
			case "planned identity", "planned assignments":
				f.show = "Id=pipelock.service\nLoadState=not-found\nNeedDaemonReload=no\nTransient=no\n"
				opts.AllowMissing = true
				opts.PlannedUser = "proxy"
				if phase == "planned identity" {
					f.b.identity = func(string, string, []string) (identity, error) { return identity{}, errors.New("secret-sentinel") }
				} else {
					opts.PlannedEnvironment = []string{"invalid"}
				}
			case "after observation":
				f.b.execute = func(context.Context, CheckOptions, []string, identity, []byte) error {
					delete(f.files, candidatePath)
					return nil
				}
			case "manager typed":
				f.properties["manager:Environment"] = typed("as", []any{nil})
			case "missing fragment":
				delete(f.properties, "FragmentPath")
			}
			if err := check(t.Context(), opts, f.b); err == nil || strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatal("uncertain observation accepted or exposed")
			}
		})
	}
}
