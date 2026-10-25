// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestRunCommand_ConfirmAccepted(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)
	out := &bytes.Buffer{}
	cmd := Cmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetIn(strings.NewReader("y\n"))

	if err := runCommand(context.Background(), cmd, opts, false); err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if !strings.Contains(string(readT(target)), "version 2.8.0") {
		t.Fatalf("accepted confirm did not update: %q", readT(target))
	}
	if !strings.Contains(out.String(), "Updated to") {
		t.Fatalf("expected success message, got %q", out.String())
	}
}

func TestRunCommand_DefaultAlreadyCurrent(t *testing.T) {
	assets, _ := standardAssets(t, testCurrent, testGOOS)
	rs := newReleaseServer(t, testCurrent, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)
	out := &bytes.Buffer{}
	cmd := Cmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetIn(strings.NewReader("")) // confirm path, but should short-circuit before prompt

	if err := runCommand(context.Background(), cmd, opts, false); err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if !strings.Contains(out.String(), "latest release") {
		t.Fatalf("expected nothing-to-do, got %q", out.String())
	}
	if string(readT(target)) != "OLD" {
		t.Fatalf("target mutated: %q", readT(target))
	}
}

func TestRunCommand_CheckError(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%t", jsonOutput), func(t *testing.T) {
			srv := newReleaseFetchErrorServer(t)
			opts := &Options{
				APIBase:        srv.URL,
				HTTPClient:     srv.Client(),
				TargetPath:     writeTargetBinary(t, "x"),
				CurrentVersion: testCurrent,
				CheckOnly:      true,
				JSON:           jsonOutput,
			}
			out := &bytes.Buffer{}
			cmd := Cmd()
			cmd.SetOut(out)
			cmd.SetErr(out)
			err := runCommand(context.Background(), cmd, opts, false)
			wantErr := fmt.Sprintf("fetching release metadata: HTTP GET %s/repos/%s/%s/releases/latest: status 503", srv.URL, repoOwner, repoName)
			if err == nil || err.Error() != wantErr {
				t.Fatalf("expected wrapped check error %q, got %v", wantErr, err)
			}
			if out.Len() != 0 {
				t.Fatalf("unexpected output on fetch failure: %q", out.String())
			}
			if got := string(readT(opts.TargetPath)); got != "x" {
				t.Fatalf("target mutated: %q", got)
			}
			if _, err := os.Stat(opts.TargetPath + backupSuffix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected backup after fetch failure: %v", err)
			}
		})
	}
}

func TestRunCommand_RollbackError(t *testing.T) {
	target := writeTargetBinary(t, "NEW") // no backup present
	opts := &Options{TargetPath: target, CurrentVersion: testCurrent, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	out := &bytes.Buffer{}
	cmd := Cmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	err := runCommand(context.Background(), cmd, opts, true)
	if !errors.Is(err, ErrNoBackup) {
		t.Fatalf("expected ErrNoBackup, got %v", err)
	}
}

func TestRunCommand_DefaultUpToDateAfterRun(t *testing.T) {
	// AssumeYes skips confirm; latest == current -> Run returns ErrUpToDate ->
	// the default branch converts it to a friendly message, no error.
	assets, _ := standardAssets(t, testCurrent, testGOOS)
	rs := newReleaseServer(t, testCurrent, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)
	opts.AssumeYes = true
	out := &bytes.Buffer{}
	cmd := Cmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	if err := runCommand(context.Background(), cmd, opts, false); err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if !strings.Contains(out.String(), "latest release") {
		t.Fatalf("expected nothing-to-do, got %q", out.String())
	}
}
