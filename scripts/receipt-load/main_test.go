// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
			mode := modeOff
			if scenario == "sink-bind" || scenario == "free-port" || scenario == "proxy-start" {
				mode = modeRequired
			}
			root := filepath.Join(opt.out, mode)
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
			want := exitHarness
			if scenario == "readiness-exit" || scenario == "readiness-timeout" || scenario == "sampler" || scenario == "proc" {
				want = exitIntegrity
			}
			if code := runModes(t.Context(), opt, []string{mode}); code != want {
				t.Fatalf("exit=%d, want %d", code, want)
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
	for _, err := range []error{nil, errors.New("unknown"), fmt.Errorf("wrapped: %w", &setupError{os.ErrPermission}), errors.Join(&setupError{os.ErrPermission}, errors.New("unknown")), errors.New("write result: " + (&setupError{os.ErrPermission}).Error())} {
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

func TestHarnessBinaryAvailabilityThroughCLI(t *testing.T) {
	for _, kind := range []string{"missing", "directory", "non-executable"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "binary")
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatal(err)
				}
			case "non-executable":
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if code := realMain([]string{"--binary", path, "--out", t.TempDir()}); code != exitHarness {
				t.Fatalf("binary %s exited %d, want setup 4", kind, code)
			}
		})
	}
}

func TestHarnessRequiredStartupReceiptFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the real proxy")
	}
	// Inject a recorder failure at the production startup session_open seam.
	// The proxy must actually refuse required-mode startup before listening.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "internal", "cli", "runtime", "receipt_session_open.go")
	raw, err := os.ReadFile(filepath.Clean(source))
	if err != nil {
		t.Fatal(err)
	}
	patched := strings.Replace(string(raw), "var beforeStartupSessionOpenForTest func(*receipt.Emitter) error",
		`var beforeStartupSessionOpenForTest = func(*receipt.Emitter) error { return fmt.Errorf("injected recorder write failure") }`, 1)
	patched = strings.Replace(patched, `import "github.com/luckyPipewrench/pipelock/internal/receipt"`,
		`import ("fmt"; "github.com/luckyPipewrench/pipelock/internal/receipt")`, 1)
	dir := t.TempDir()
	replacement := filepath.Join(dir, "receipt_session_open.go")
	if err := os.WriteFile(replacement, []byte(patched), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{source: replacement}})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "pipelock")
	cmd := exec.CommandContext(t.Context(), "go", "build")
	cmd.Args = append(cmd.Args, "-overlay", overlayPath, "-o", binary)
	if realBuildTags != "" {
		cmd.Args = append(cmd.Args, "-tags", realBuildTags)
	}
	cmd.Args = append(cmd.Args, "./cmd/pipelock")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	opt := smallOptions(t, binary)
	res, err := runMode(t.Context(), opt, modeRequired)
	log, readErr := os.ReadFile(filepath.Join(opt.out, modeRequired, "proxy.log"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(log), "session_open receipt could not be emitted: injected recorder write failure") {
		t.Fatalf("did not exercise startup receipt refusal: %s", log)
	}
	if code := modeExitCode(res, err); code != exitIntegrity {
		t.Fatalf("startup receipt failure exited %d, want integrity 1: %v", code, err)
	}
}
