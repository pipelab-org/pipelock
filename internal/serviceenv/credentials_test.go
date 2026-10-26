// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
	"context"
	"strings"
	"testing"
)

func TestNativeCredentialValidation(t *testing.T) {
	for _, property := range []string{"LoadCredential", "LoadCredentialEncrypted"} {
		t.Run(property, func(t *testing.T) {
			f := newFixture(t)
			f.files[candidatePath] = []byte("kill_switch:\n  api_token_file: $CREDENTIALS_DIRECTORY/admin-token\n")
			f.properties[property] = typed("a(ss)", [][]string{{"admin-token", "/etc/credstore.encrypted/admin-token"}})
			f.files["/etc/credstore.encrypted/admin-token"] = []byte("opaque-credential")
			f.b.execute = func(_ context.Context, opts CheckOptions, _ []string, _ identity, _ []byte) error {
				f.executions++
				if opts.credential == nil || opts.credential.Property != property {
					t.Fatal("credential not passed to fresh validator")
				}
				return nil
			}
			if err := check(t.Context(), fixtureOptions(), f.b); err != nil {
				t.Fatal(err)
			}
			if f.executions != 1 {
				t.Fatal("validator not executed")
			}
		})
	}
}

func TestNativeCredentialRefusals(t *testing.T) {
	for _, tt := range []struct {
		name, file, property, source, id string
		prestart                         bool
	}{
		{name: "unreferenced", property: "LoadCredentialEncrypted", source: "/source", id: "admin-token"},
		{name: "different id", file: "$CREDENTIALS_DIRECTORY/admin-token", property: "LoadCredentialEncrypted", source: "/source", id: "other"},
		{name: "relative source", file: "$CREDENTIALS_DIRECTORY/admin-token", property: "LoadCredentialEncrypted", source: "source", id: "admin-token"},
		{name: "missing source", file: "$CREDENTIALS_DIRECTORY/admin-token", property: "LoadCredentialEncrypted", source: "/missing", id: "admin-token"},
		{name: "prestart", file: "$CREDENTIALS_DIRECTORY/admin-token", property: "LoadCredentialEncrypted", source: "/source", id: "admin-token", prestart: true},
		{name: "missing directive", file: "$CREDENTIALS_DIRECTORY/admin-token"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.files[candidatePath] = []byte("kill_switch:\n  api_token_file: '" + tt.file + "'\n")
			f.files["/source"] = []byte("opaque")
			if tt.property != "" {
				f.properties[tt.property] = typed("a(ss)", [][]string{{tt.id, tt.source}})
			}
			if tt.prestart {
				f.properties["ExecStartPre"] = typed("a(sasbttttuii)", []any{[]any{"/bin/sh"}})
			}
			if err := check(t.Context(), fixtureOptions(), f.b); err == nil {
				t.Fatal("unsupported credential definition accepted")
			}
			if f.executions != 0 {
				t.Fatal("executed validator before acceptance")
			}
		})
	}
}

func TestNativeCredentialRotationDuringCheck(t *testing.T) {
	f := newFixture(t)
	f.files[candidatePath] = []byte("kill_switch:\n  api_token_file: $CREDENTIALS_DIRECTORY/admin-token\n")
	f.properties["LoadCredentialEncrypted"] = typed("a(ss)", [][]string{{"admin-token", "/source"}})
	f.files["/source"] = []byte("before")
	f.b.execute = func(context.Context, CheckOptions, []string, identity, []byte) error {
		f.files["/source"] = []byte("after")
		return nil
	}
	if err := check(t.Context(), fixtureOptions(), f.b); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("rotation was not detected: %v", err)
	}
}

func TestCredentialDefinitionErrors(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(*fixture)
	}{
		{"malformed yaml", func(f *fixture) {
			f.files[candidatePath] = []byte("kill_switch: [")
			f.properties["LoadCredentialEncrypted"] = typed("a(ss)", [][]string{})
		}},
		{"wrong field type", func(f *fixture) { f.files[candidatePath] = []byte("kill_switch: wrong") }},
		{"empty candidate", func(f *fixture) {
			f.files[candidatePath] = nil
			f.properties["LoadCredential"] = typed("a(ss)", [][]string{{"admin-token", "/source"}})
		}},
		{"invalid credential reference", func(f *fixture) {
			f.files[candidatePath] = []byte("kill_switch:\n  api_token_file: $CREDENTIALS_DIRECTORY/../token\n")
		}},
		{"malformed row", func(f *fixture) { f.properties["LoadCredential"] = typed("a(ss)", [][]string{{"admin-token"}}) }},
		{"duplicate source", func(f *fixture) { f.properties["LoadCredential"] = f.properties["LoadCredentialEncrypted"] }},
		{"old manager", func(f *fixture) { f.properties["manager:Version"] = typed("s", "253") }},
		{"directory override", func(f *fixture) { f.properties["Environment"] = typed("as", []string{"CREDENTIALS_DIRECTORY=/old"}) }},
		{"directory unset", func(f *fixture) { f.properties["UnsetEnvironment"] = typed("as", []string{"CREDENTIALS_DIRECTORY"}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.files[candidatePath] = []byte("kill_switch:\n  api_token_file: $CREDENTIALS_DIRECTORY/admin-token\n")
			f.files["/source"] = []byte("opaque")
			f.properties["LoadCredentialEncrypted"] = typed("a(ss)", [][]string{{"admin-token", "/source"}})
			tt.setup(f)
			if err := check(t.Context(), fixtureOptions(), f.b); err == nil || f.executions != 0 {
				t.Fatal("malformed definition reached validator", err)
			}
		})
	}
}
