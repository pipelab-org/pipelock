// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/serviceenv"
)

func TestCheckServiceUsesIsolatedValidator(t *testing.T) {
	var got serviceenv.CheckOptions
	cmd := checkCmdWithServiceValidator(func(_ context.Context, o serviceenv.CheckOptions) error { got = o; return nil }, func() (string, error) { return "/opt/pipelock", nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--config", "candidate.yaml", "--service", "pipelock", "--require-build-compatibility"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	wantPath, err := filepath.Abs("candidate.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got.Binary != "/opt/pipelock" || got.ConfigFile != wantPath || got.Service != "pipelock" || !got.RequireBuildCompatibility {
		t.Fatalf("wrong options: %+v", got)
	}
	if !strings.Contains(out.String(), "pipelock.service configuration environment") {
		t.Fatal("missing qualified success")
	}
}

func TestCheckServiceRejectsInvalidCombinations(t *testing.T) {
	for _, args := range [][]string{{"--service", "pipelock"}, {"--service", "pipelock", "--config", "-"}, {"--service", "pipelock", "--config", "candidate.yaml", "--url", "https://api.vendor.example"}} {
		called := false
		cmd := checkCmdWithServiceValidator(func(context.Context, serviceenv.CheckOptions) error { called = true; return nil }, func() (string, error) { return "/opt/pipelock", nil })
		cmd.SetArgs(args)
		if cmd.Execute() == nil || called {
			t.Fatal("invalid combination reached validator")
		}
	}
	for _, binaryFailure := range []bool{false, true} {
		cmd := checkCmdWithServiceValidator(func(context.Context, serviceenv.CheckOptions) error { return errors.New("service unavailable") }, func() (string, error) {
			if binaryFailure {
				return "", errors.New("cannot locate")
			}
			return "/opt/pipelock", nil
		})
		cmd.SetArgs([]string{"--service", "pipelock", "--config", "candidate.yaml"})
		if cmd.Execute() == nil {
			t.Fatal("service failure accepted")
		}
	}
}

func TestCheckServiceCredentialResolution(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("PIPELOCK_KILLSWITCH_API_TOKEN", "operator-token")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("kill_switch:\n  api_token_file: $CREDENTIALS_DIRECTORY/admin-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, resolve := range []bool{false, true} {
		cmd := CheckCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		args := []string{"--config", path}
		if resolve {
			args = append(args, "--resolve-runtime-credentials")
		}
		cmd.SetArgs(args)
		err := cmd.Execute()
		if resolve {
			if err == nil || !strings.Contains(err.Error(), "CREDENTIALS_DIRECTORY") || strings.Contains(out.String(), "Config validation: OK") {
				t.Fatalf("runtime validator did not fail closed: %v", err)
			}
		} else if err != nil || !strings.Contains(out.String(), "Runtime credential file not checked") {
			t.Fatalf("plain check did not qualify config validation: %v", err)
		}
	}
}
