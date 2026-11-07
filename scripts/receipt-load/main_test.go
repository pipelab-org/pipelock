// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
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

func TestHarnessExitCodes(t *testing.T) {
	for _, scenario := range []string{"directory", "binary", "rules", "config", "sink-bind", "free-port", "proxy-start", "readiness-exit", "readiness-timeout", "sampler", "proc"} {
		t.Run(scenario, func(t *testing.T) {
			opt := smallOptions(t, newFakePipelock(t, "ok"))
			root := filepath.Join(opt.out, modeOff)
			savedListen, savedStat := listenTCP, readProcessStat
			t.Cleanup(func() { listenTCP, readProcessStat = savedListen, savedStat })
			calls := 0
			listenTCP = func(ctx context.Context) (net.Listener, error) {
				calls++
				if (scenario == "sink-bind" && calls == 1) || (scenario == "free-port" && calls == 2) {
					return nil, &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRNOTAVAIL}
				}
				if calls == 2 {
					switch scenario {
					case "proxy-start":
						if err := os.Chmod(filepath.Join(root, "bin", filepath.Base(opt.binary)), 0o600); err != nil {
							t.Fatal(err)
						}
					case "sampler":
						if err := os.Mkdir(filepath.Join(root, "samples.csv"), 0o750); err != nil {
							t.Fatal(err)
						}
					}
				}
				return savedListen(ctx)
			}
			switch scenario {
			case "directory":
				if err := os.Mkdir(root, 0o750); err != nil {
					t.Fatal(err)
				}
			case "binary":
				opt.binary = filepath.Join(t.TempDir(), "absent")
			case "rules":
				opt.rules = filepath.Join(t.TempDir(), "absent")
			case "config":
				opt.binary = newFakePipelock(t, "initfail")
			case "readiness-exit":
				opt.binary = newFakePipelock(t, "exitfast")
			case "readiness-timeout":
				opt.binary = newFakePipelock(t, "noready")
				opt.readyTimeout = time.Millisecond
			case "proc":
				readProcessStat = func(string) ([]byte, error) { return nil, os.ErrPermission }
			}
			if code := runModes(t.Context(), opt, []string{modeOff}); code != 4 {
				t.Fatalf("exit=%d, want harness error 4", code)
			}
			if scenario != "directory" {
				res := readResult(t, root)
				if res.Integrity.Verdict == verdictPass || res.Performance.Verdict == perfMeasured {
					t.Fatalf("setup failure reported a pass: %+v", res)
				}
			}
		})
	}
	t.Run("output-root", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		code := realMain([]string{"--binary", newFakePipelock(t, "ok"), "--out", filepath.Join(path, "child")})
		if code != 4 {
			t.Fatalf("output preparation exited %d, want harness error 4", code)
		}
	})
	// Unknown failures cannot acquire the setup exemption merely because they
	// returned no result. A result-write failure also loses that exemption.
	for _, err := range []error{nil, errors.New("unknown"), errors.Join(&setupError{os.ErrPermission}, errors.New("unknown")), errors.New("write result: " + (&setupError{os.ErrPermission}).Error())} {
		if code := modeExitCode(nil, err); code != 1 {
			t.Fatalf("unknown error %v exited %d, want integrity 1", err, code)
		}
	}
	t.Run("integrity-precedes-harness", func(t *testing.T) {
		for _, order := range [][]string{{modeOff, modeBest}, {modeBest, modeOff}} {
			opt := smallOptions(t, newFakePipelock(t, "ok"))
			if err := os.Mkdir(filepath.Join(opt.out, modeOff), 0o750); err != nil {
				t.Fatal(err)
			}
			// best mode has no receipts; off mode cannot create its run directory.
			if code := runModes(t.Context(), opt, order); code != 1 {
				t.Fatalf("mode order %v exited %d, want integrity 1", order, code)
			}
		}
	})
}
