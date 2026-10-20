// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"context"
	"errors"
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
