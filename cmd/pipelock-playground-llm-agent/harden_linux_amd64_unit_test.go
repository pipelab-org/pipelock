// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestHardenProcessWithOps(t *testing.T) {
	t.Parallel()

	var calls []string
	ops := hardenOps{
		setDumpable: func() error {
			calls = append(calls, "dumpable")
			return nil
		},
		applySeccomp: func() error {
			calls = append(calls, "seccomp")
			return nil
		},
	}

	if err := hardenProcessWithOps(ops); err != nil {
		t.Fatalf("hardenProcessWithOps: %v", err)
	}
	want := []string{"dumpable", "seccomp"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestHardenProcessWithOpsErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ops     hardenOps
		wantErr string
	}{
		{
			name: "dumpable",
			ops: hardenOps{
				setDumpable:  func() error { return errors.New("dumpable denied") },
				applySeccomp: func() error { return nil },
			},
			wantErr: "set non-dumpable",
		},
		{
			name: "seccomp",
			ops: hardenOps{
				setDumpable:  func() error { return nil },
				applySeccomp: func() error { return errors.New("seccomp denied") },
			},
			wantErr: "install seccomp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := hardenProcessWithOps(tt.ops)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
