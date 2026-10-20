// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
			out.WriteString(`<node><interface name="` + serviceInterface + `">`)
			for name, body := range f.properties {
				if strings.HasPrefix(name, "manager:") || name == "FragmentPath" || name == "DropInPaths" {
					continue
				}
				var envelope struct {
					Type string `json:"type"`
				}
				_ = json.Unmarshal(body, &envelope)
				_, _ = fmt.Fprintf(&out, `<property name="%s" type="%s" access="read"/>`, name, envelope.Type)
			}
			out.WriteString(`</interface></node>`)
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

func TestEnvironmentFileCommentUsesRunningManagerVersion(t *testing.T) {
	// NEWS v254 records the EnvironmentFile comment-escape change. This is
	// env-file.c COMMENT_ESCAPE, not systemd.syntax(7)'s unit-file continuation.
	// https://github.com/systemd/systemd/blob/v254/NEWS
	// https://github.com/systemd/systemd/blob/v254/man/systemd.syntax.xml
	for _, version := range []int{252, 253, 254, 257} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			f := newFixture(t)
			f.properties["manager:Version"] = typed("s", fmt.Sprintf("%d (vendor build)", version))
			f.properties["Environment"] = typed("as", []string{config.EnvKillSwitchAPIToken + "=unit-token"})
			f.properties["EnvironmentFiles"] = typed("a(sb)", []any{[]any{"/run/comment.env", false}})
			// The systemd 257 VM received an empty token from these exact file
			// bytes, overriding the nonempty unit assignment. Validation must
			// reject a configured kill-switch API with that empty token.
			f.files["/run/comment.env"] = []byte("# ignored\\\n" + config.EnvKillSwitchAPIToken + "=\nCONTROL=kept\n")
			t.Setenv(config.EnvKillSwitchAPIToken, "")
			f.b.execute = func(_ context.Context, _ CheckOptions, env []string, _ identity, _ []byte) error {
				f.executions++
				f.environment = slices.Clone(env)
				for _, assignment := range env {
					if name, value, ok := strings.Cut(assignment, "="); ok && name == config.EnvKillSwitchAPIToken {
						t.Setenv(name, value)
					}
				}
				cfg := config.Defaults()
				cfg.KillSwitch.APIListen = "127.0.0.1:9090"
				return cfg.Validate()
			}
			err := check(t.Context(), fixtureOptions(), f.b)
			want := config.EnvKillSwitchAPIToken + "="
			if version < 254 {
				want += "unit-token"
			}
			if f.executions != 1 || !slices.Contains(f.environment, want) || (err != nil) != (version >= 254) {
				t.Fatalf("manager %d: expected token override/validation mismatch, got environment %q, error %v", version, f.environment, err)
			}
		})
	}
}

func TestEnvironmentFileUnresolvedManagerRefusesValidation(t *testing.T) {
	for _, version := range []string{"", "unknown", "0"} {
		t.Run(version, func(t *testing.T) {
			f := newFixture(t)
			f.properties["manager:Version"] = typed("s", version)
			f.properties["EnvironmentFiles"] = typed("a(sb)", []any{[]any{"/run/comment.env", false}})
			f.files["/run/comment.env"] = []byte("# ignored\\\n" + config.EnvKillSwitchAPIToken + "=\n")
			if err := check(t.Context(), fixtureOptions(), f.b); err == nil || f.executions != 0 {
				t.Fatal("unknown manager semantics reached the validator")
			}
		})
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
	for _, change := range []string{"manager", "manager version", "unit", "environment file", "candidate", "identity"} {
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
				case "manager version":
					f.properties["manager:Version"] = typed("s", "252")
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

func TestMissingUnitHomeMatchesLoadedUnit(t *testing.T) {
	// USER_CREDS_CLEAN omits an account home of "/", leaving any manager
	// HOME intact. The provisional managed unit must use that same rule.
	// https://github.com/systemd/systemd/blob/v252/src/core/execute.c
	for _, tc := range []struct {
		name, home string
		baseline   []string
		want       []string
	}{
		{"root home omitted", "/", []string{}, nil},
		{"root home preserves manager", "/", []string{"HOME=/manager/home"}, []string{"HOME=/manager/home"}},
		{"ordinary home replaces manager", "/var/lib/pipelock-proxy", []string{"HOME=/manager/home"}, []string{"HOME=/var/lib/pipelock-proxy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.b.identity = func(string, string, []string) (identity, error) {
				return identity{Home: tc.home}, nil
			}
			f.properties["manager:Environment"] = typed("as", tc.baseline)
			opts := fixtureOptions()
			if err := check(t.Context(), opts, f.b); err != nil {
				t.Fatal(err)
			}
			loaded := slices.Clone(f.environment)
			f.show = "Id=pipelock.service\nLoadState=not-found\nNeedDaemonReload=no\nTransient=no\n"
			opts.AllowMissing, opts.PlannedUser = true, "pipelock-proxy"
			if err := check(t.Context(), opts, f.b); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(loaded, tc.want) || !slices.Equal(f.environment, loaded) {
				t.Fatalf("loaded %q, provisional %q; want %q", loaded, f.environment, tc.want)
			}
		})
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

func TestProspectiveInvocationBinding(t *testing.T) {
	expected := []string{"/usr/local/bin/pipelock", "run", "--config", candidatePath, "--capture-output", "/var/lib/pipelock/captures"}
	for _, variant := range []string{"executable", "candidate", "argv0", "flags", "multiple"} {
		t.Run(variant, func(t *testing.T) {
			f := newFixture(t)
			opts := fixtureOptions()
			opts.ExpectedExecStart = expected
			argv := slices.Clone(expected)
			path := expected[0]
			flags := []string{}
			switch variant {
			case "executable":
				path = "/bin/other"
			case "candidate":
				argv[3] = "/other.yaml"
			case "argv0":
				argv[0] = "/other"
			case "flags":
				flags = []string{"privileged"}
			}
			row := []any{path, argv, false, 0, 0, 0, 0, 0, 0, 0}
			rows := []any{row}
			if variant == "multiple" {
				rows = append(rows, row)
			}
			f.properties["ExecStart"] = typed("a(sasbttttuii)", rows)
			f.properties["ExecStartEx"] = typed("a(sasasttttuii)", []any{[]any{path, argv, flags, 0, 0, 0, 0, 0, 0, 0}})
			if err := check(t.Context(), opts, f.b); err == nil || f.executions != 0 {
				t.Fatal("mismatched loaded invocation reached validator")
			}
		})
	}
}

func TestOptionalUnreadableEnvironmentFile(t *testing.T) {
	f := newFixture(t)
	f.properties["EnvironmentFiles"] = typed("a(sb)", []any{[]any{"/run/optional", true}})
	read := f.b.readFile
	f.b.readFile = func(path string) (fileImage, error) {
		if path == "/run/optional" {
			return fileImage{}, os.ErrPermission
		}
		return read(path)
	}
	if err := check(t.Context(), fixtureOptions(), f.b); err != nil {
		t.Fatalf("optional unreadable file refused: %v", err)
	}
}

func prospectiveFixture(t *testing.T) (*fixture, CheckOptions) {
	t.Helper()
	f := newFixture(t)
	opts := fixtureOptions()
	opts.ExpectedExecStart = []string{opts.Binary, "run", "--config", candidatePath, "--capture-output", "/var/lib/pipelock/captures"}
	f.properties["ExecStart"] = typed("a(sasbttttuii)", []any{[]any{opts.Binary, opts.ExpectedExecStart, false, 0, 0, 0, 0, 0, 0, 0}})
	f.properties["ExecStartEx"] = typed("a(sasasttttuii)", []any{[]any{opts.Binary, opts.ExpectedExecStart, []string{}, 0, 0, 0, 0, 0, 0, 0}})
	return f, opts
}

func TestProspectiveInvocationSuccessAndReobservation(t *testing.T) {
	f, opts := prospectiveFixture(t)
	if err := check(t.Context(), opts, f.b); err != nil || f.executions != 1 {
		t.Fatalf("matching invocation refused: %v", err)
	}
	for _, changed := range []string{"ExecStart", "ExecStartEx"} {
		t.Run(changed, func(t *testing.T) {
			f, opts := prospectiveFixture(t)
			execute := f.b.execute
			f.b.execute = func(ctx context.Context, opts CheckOptions, env []string, id identity, candidate []byte) error {
				_ = execute(ctx, opts, env, id, candidate)
				// Runtime timestamps are part of the stable observation too.
				if changed == "ExecStart" {
					f.properties[changed] = typed("a(sasbttttuii)", []any{[]any{opts.Binary, opts.ExpectedExecStart, false, 1, 0, 0, 0, 0, 0, 0}})
				} else {
					f.properties[changed] = typed("a(sasasttttuii)", []any{[]any{opts.Binary, opts.ExpectedExecStart, []string{}, 1, 0, 0, 0, 0, 0, 0}})
				}
				return nil
			}
			if err := check(t.Context(), opts, f.b); err == nil || !strings.Contains(err.Error(), "changed during validation") {
				t.Fatal("changed invocation accepted")
			}
		})
	}
}

func TestProspectiveInvocationMalformedAndFlags(t *testing.T) {
	for _, body := range [][]byte{
		typed("a(sasasttttuii)", nil), typed("a(sasasttttuii)", []any{}),
		typed("a(sasasttttuii)", []any{[]any{"/usr/local/bin/pipelock"}}),
		typed("as", []string{}),
	} {
		f, opts := prospectiveFixture(t)
		f.properties["ExecStartEx"] = body
		if err := check(t.Context(), opts, f.b); err == nil || f.executions != 0 {
			t.Fatal("malformed invocation accepted")
		}
	}
	for _, flags := range []any{nil, []string{"ignore-failure"}, []string{"privileged"}, []string{"no-setuid"}, []string{"no-env-expand"}, []string{"ambient"}, []any{nil}} {
		f, opts := prospectiveFixture(t)
		f.properties["ExecStartEx"] = typed("a(sasasttttuii)", []any{[]any{opts.Binary, opts.ExpectedExecStart, flags, 0, 0, 0, 0, 0, 0, 0}})
		if err := check(t.Context(), opts, f.b); err == nil || f.executions != 0 {
			t.Fatal("nonempty or malformed command flags accepted")
		}
	}
	f, opts := prospectiveFixture(t)
	f.properties["ExecStart"] = typed("a(sasbttttuii)", []any{[]any{opts.Binary, opts.ExpectedExecStart, true, 0, 0, 0, 0, 0, 0, 0}})
	if check(t.Context(), opts, f.b) == nil || f.executions != 0 {
		t.Fatal("ignore-failure command accepted")
	}
}

func TestServiceUnavailableClassification(t *testing.T) {
	for _, phase := range []string{"manager", "planned identity", "static identity", "credential"} {
		t.Run(phase, func(t *testing.T) {
			f := newFixture(t)
			opts := fixtureOptions()
			switch phase {
			case "manager":
				f.b.command = func(context.Context, string, ...string) ([]byte, int, error) {
					return nil, -1, errors.New("secret-sentinel")
				}
			case "planned identity":
				f.show = "Id=pipelock.service\nLoadState=not-found\nNeedDaemonReload=no\nTransient=no\n"
				opts.AllowMissing = true
				opts.PlannedUser = "not-created"
				f.b.identity = func(string, string, []string) (identity, error) { return identity{}, ErrUnavailable }
			case "static identity":
				f.b.identity = func(string, string, []string) (identity, error) { return identity{}, ErrUnavailable }
			case "credential":
				f.b.execute = func(context.Context, CheckOptions, []string, identity, []byte) error { return ErrUnavailable }
			}
			err := check(t.Context(), opts, f.b)
			if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatal("unavailable environment lost its safe classification")
			}
		})
	}
}

func TestOptionalEnvironmentFileAvailabilityChanges(t *testing.T) {
	for _, initialReadable := range []bool{false, true} {
		f := newFixture(t)
		f.properties["EnvironmentFiles"] = typed("a(sb)", []any{[]any{"/run/optional", true}})
		read := f.b.readFile
		readable := initialReadable
		f.b.readFile = func(path string) (fileImage, error) {
			if path != "/run/optional" {
				return read(path)
			}
			if !readable {
				return fileImage{}, errUnreadableFile
			}
			return fileImage{Data: []byte("A=value\n"), Stamp: "readable"}, nil
		}
		f.b.execute = func(context.Context, CheckOptions, []string, identity, []byte) error {
			readable = !readable
			return nil
		}
		if err := check(t.Context(), fixtureOptions(), f.b); err == nil || !strings.Contains(err.Error(), "changed during validation") {
			t.Fatal("optional file availability change accepted")
		}
	}
}

func TestProspectiveInvocationObservationFailures(t *testing.T) {
	for _, failure := range []string{"expected binary", "missing extended", "denied getter", "runtime null", "runtime type"} {
		t.Run(failure, func(t *testing.T) {
			f, opts := prospectiveFixture(t)
			switch failure {
			case "expected binary":
				opts.ExpectedExecStart[0] = "/wrong/binary"
			case "missing extended":
				delete(f.properties, "ExecStartEx")
			case "denied getter":
				command := f.b.command
				f.b.command = func(ctx context.Context, binary string, args ...string) ([]byte, int, error) {
					if args[len(args)-1] == "ExecStartEx" {
						return nil, 1, nil
					}
					return command(ctx, binary, args...)
				}
			case "runtime null", "runtime type":
				var invalid any
				if failure == "runtime type" {
					invalid = "not-numeric"
				}
				f.properties["ExecStartEx"] = typed("a(sasasttttuii)", []any{[]any{opts.Binary, opts.ExpectedExecStart, []string{}, invalid, 0, 0, 0, 0, 0, 0}})
			}
			if err := check(t.Context(), opts, f.b); err == nil || f.executions != 0 {
				t.Fatal("uncertain invocation reached validator")
			}
		})
	}
}

func TestCanceledServiceCheckIsNotUnavailable(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := check(ctx, fixtureOptions(), f.b)
	if err == nil || errors.Is(err, ErrUnavailable) || f.executions != 0 {
		t.Fatal("canceled check could be deferred as unavailable")
	}
}

func TestOversizedTypedObservationIsNotUnavailable(t *testing.T) {
	f := newFixture(t)
	f.b.command = func(context.Context, string, ...string) ([]byte, int, error) {
		return []byte(strings.Repeat("x", maxObservationBytes+1)), 0, nil
	}
	if _, err := readProperty(t.Context(), f.b, unitObject, serviceInterface, "User"); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatal("oversized typed input could be deferred as unavailable")
	}
}

func TestHelperPolicyFailuresCannotBeDeferred(t *testing.T) {
	for _, phase := range []string{"identity overflow", "typed overflow", "identity policy", "typed policy", "identity canceled", "typed canceled", "child canceled"} {
		t.Run(phase, func(t *testing.T) {
			f := newFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			command := f.b.command
			if phase == "child canceled" {
				f.b.execute = func(context.Context, CheckOptions, []string, identity, []byte) error { cancel(); return ErrUnavailable }
			} else {
				f.b.command = func(ctx context.Context, binary string, args ...string) ([]byte, int, error) {
					fail := strings.HasPrefix(phase, "identity") && binary == "/usr/bin/systemctl" || strings.HasPrefix(phase, "typed") && slices.Contains(args, "get-property")
					if !fail {
						return command(ctx, binary, args...)
					}
					if strings.HasSuffix(phase, "canceled") {
						cancel()
						return nil, -1, context.Canceled
					}
					if strings.HasSuffix(phase, "policy") {
						return nil, -1, fmt.Errorf("secret-sentinel: %w", errObservationPolicy)
					}
					return nil, -1, errObservationOverflow
				}
			}
			err := check(ctx, fixtureOptions(), f.b)
			if err == nil || errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatal("policy/cancellation failure could be deferred")
			}
			if strings.HasSuffix(phase, "policy") && !errors.Is(err, errObservationPolicy) {
				t.Fatal("helper policy failure lost its classification")
			}
		})
	}
}
