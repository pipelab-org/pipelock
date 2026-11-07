// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"
	"time"
)

func TestReadyTimeoutFlag(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
		want  time.Duration
	}{
		{name: "default", want: 10 * time.Second},
		{name: "longer", value: "90s", want: 90 * time.Second},
		{name: "fractional", value: "200ms", want: 200 * time.Millisecond},
		{name: "smallest", value: "1ns", want: time.Nanosecond},
		{name: "zero", value: "0s"},
		{name: "negative", value: "-1s"},
		{name: "malformed", value: "later"},
		{name: "overflow", value: "999999999999h"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"--binary", os.Args[0], "--out", t.TempDir()}
			if tt.value != "" {
				args = append(args, "--ready-timeout", tt.value)
			}
			opt, _, _, err := parseFlags(args)
			if tt.want == 0 {
				if err == nil {
					t.Fatal("accepted invalid readiness timeout")
				}
				return
			}
			if err != nil || opt.readyTimeout != tt.want {
				t.Fatalf("readiness timeout = %s, error = %v; want %s", opt.readyTimeout, err, tt.want)
			}
		})
	}
}
