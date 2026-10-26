// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serviceenv

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestCredentialValidatorArguments(t *testing.T) {
	opts := fixtureOptions()
	opts.credential = &credentialSource{Property: "LoadCredentialEncrypted", Name: "admin-token", Path: "/etc/credstore.encrypted/admin-token"}
	opts.credentialUnset = []string{"LD_PRELOAD", "GODEBUG"}
	env := []string{config.EnvKillSwitchAPIToken + "=private-token", "HOME=/service/home"}
	args, err := credentialValidatorArgs(opts, env, identity{UID: 1234, GID: 1234, Groups: []uint32{1234, 1235}}, 9)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	if strings.Contains(joined, "private-token") || strings.Contains(joined, "/service/home") {
		t.Fatal("environment value leaked into arguments")
	}
	for _, want := range []string{"--property=LoadCredentialEncrypted=admin-token:/etc/credstore.encrypted/admin-token", "--setenv=" + config.EnvKillSwitchAPIToken, "--setenv=HOME", "--property=User=1234", "--property=SupplementaryGroups=1234 1235", "--expand-environment=no", "--require-build-compatibility", "--property=LimitCORE=0"} {
		if !slices.Contains(args, want) {
			t.Fatalf("missing argument %s", want)
		}
	}
	if !strings.Contains(joined, "UnsetEnvironment=GODEBUG LD_PRELOAD") {
		t.Fatal("manager injection inputs not removed")
	}
	if !strings.Contains(joined, "BindReadOnlyPaths=/proc/") || !strings.Contains(joined, "/fd/9:"+opts.Binary) {
		t.Fatal("validator inode is not pinned")
	}
	for _, tt := range []struct {
		name   string
		mutate func(*CheckOptions)
		env    []string
	}{
		{name: "no credential", mutate: func(o *CheckOptions) { o.credential = nil }},
		{name: "wrong property", mutate: func(o *CheckOptions) { o.credential = &credentialSource{Property: "SetCredential", Path: "/source"} }},
		{name: "specifier binary", mutate: func(o *CheckOptions) { o.Binary = "/opt/%n/pipelock" }},
		{name: "manager directory override", mutate: func(o *CheckOptions) { o.credentialUnset = []string{"CREDENTIALS_DIRECTORY"} }},
		{name: "malformed environment", env: []string{"not-an-assignment"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			copyOpts := opts
			if tt.mutate != nil {
				tt.mutate(&copyOpts)
			}
			if _, err := credentialValidatorArgs(copyOpts, tt.env, identity{}, 9); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}

func TestCredentialValidationExecution(t *testing.T) {
	for _, name := range []string{"success", "failure", "changed binary", "bad paths", "canceled"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "pipelock")
			if err := os.WriteFile(path, []byte("executable-fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			var before unix.Stat_t
			if err := unix.Fstat(int(file.Fd()), &before); err != nil {
				t.Fatal(err)
			}
			opts := fixtureOptions()
			opts.Binary = path
			opts.ConfigFile = filepath.Join(dir, "config.yaml")
			opts.credential = &credentialSource{Property: "LoadCredentialEncrypted", Name: "admin-token", Path: "/credential-source"}
			v := credentialValidation{opts: opts, env: []string{"HOME=/service/home"}, id: currentIdentity(t), candidate: []byte("candidate-bytes"), binary: file, before: before}
			if name == "bad paths" {
				v.opts.Binary = "/bad%path"
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if name == "canceled" {
				cancel()
			}
			ran, stopped := false, false
			err = v.run(ctx, func(cmd *exec.Cmd) error {
				ran = true
				if cmd.Path != "/usr/bin/systemd-run" || cmd.WaitDelay <= 0 {
					t.Fatal("unbounded or unexpected validator")
				}
				if body, e := io.ReadAll(cmd.Stdin); e != nil || string(body) != "candidate-bytes" {
					t.Fatal("candidate was not supplied on stdin")
				}
				if !slices.Contains(cmd.Env, "HOME=/service/home") {
					t.Fatal("observed environment not supplied")
				}
				if strings.Contains(strings.Join(cmd.Args, " "), "/service/home") {
					t.Fatal("environment exposed in arguments")
				}
				if name == "failure" || name == "canceled" {
					return errors.New("private-output")
				}
				if name == "changed binary" {
					if e := os.WriteFile(path, []byte("changed"), 0o600); e != nil {
						t.Fatal(e)
					}
				}
				return nil
			}, func(ctx context.Context, unit string) {
				stopped = true
				if ctx.Err() != nil || !strings.HasPrefix(unit, "pipelock-config-check-") || !strings.HasSuffix(unit, ".service") {
					t.Fatal("cleanup lost its independent deadline or owned unit")
				}
			})
			if (err != nil) != (name != "success") {
				t.Fatalf("error=%v case=%s", err, name)
			}
			if err != nil && strings.Contains(err.Error(), "private-output") {
				t.Fatal("child error exposed")
			}
			if name == "bad paths" {
				if ran || stopped {
					t.Fatal("invalid input launched work")
				}
			} else if !ran || !stopped {
				t.Fatal("validator or cleanup not run")
			}
			if os.Geteuid() != 0 {
				if e := v.execute(t.Context()); !errors.Is(e, ErrUnavailable) {
					t.Fatalf("non-root credential validation: %v", e)
				}
			}
		})
	}
}
