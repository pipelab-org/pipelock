// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/rules"
)

func TestRealReloadBundleWarningIsDetected(t *testing.T) {
	bin := realPipelock(t)
	root := filepath.Join(t.TempDir(), "run")
	dirs := newRunDirs(root)
	if err := dirs.create(); err != nil {
		t.Fatal(err)
	}
	env, _ := buildChildEnv(os.Environ(), dirs)
	configPath := filepath.Join(root, "pipelock.yaml")
	body := fmt.Sprintf("version: 1\nmode: balanced\nrules:\n  rules_dir: %s\n", dirs.rules)
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	port, err := freePort(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	addr := "127.0.0.1:" + strconv.Itoa(port)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p, err := startProxy(ctx, bin, dirs, env, configPath, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer p.cleanup()
	if err := awaitProxy(ctx, addr, p); err != nil {
		t.Fatal(err)
	}
	bundleDir := filepath.Join(dirs.rules, "reload-warning")
	if err := os.Mkdir(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}
	bundle := []byte("format_version: 1\nname: reload-warning\nversion: 2026.11.1\nauthor: Test\ndescription: Reload warning test\nmin_pipelock: 1.0.0\nrules:\n  - id: marker\n    type: dlp\n    status: stable\n    name: Reload marker\n    description: Reload marker\n    severity: high\n    confidence: high\n    pattern:\n      regex: receipt-load-reload-marker\n")
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bundle)
	if err := rules.WriteLockFile(filepath.Join(bundleDir, "bundle.lock"), &rules.LockFile{InstalledVersion: "2026.11.1", BundleSHA256: hex.EncodeToString(sum[:]), Unsigned: true}); err != nil {
		t.Fatal(err)
	}
	// Changing an unrelated setting makes the file watcher resolve bundles again.
	if err := os.WriteFile(configPath, []byte(body+"api_allowlist:\n  - api.vendor.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "proxy.log")
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, readErr := os.ReadFile(filepath.Clean(logPath))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.Contains(string(data), "WARNING: config reload: bundle ") {
			if shutdown := p.stop(5 * time.Second); !shutdown.Clean {
				t.Fatalf("proxy shutdown: %+v", shutdown)
			}
			data, readErr = os.ReadFile(filepath.Clean(logPath))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if strings.Contains(string(data), `"event":"rule_bundle_degraded"`) {
				t.Fatalf("warning-only fixture unexpectedly degraded: %s", data)
			}
			lines, scanErr := bundleLogLines(logPath)
			if scanErr != nil || len(lines) == 0 {
				t.Fatalf("reload bundle warning missed: lines=%v error=%v\n%s", lines, scanErr, data)
			}
			t.Logf("real producer: %s", strings.Join(lines, "\n"))
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("reload warning not emitted: %s", data)
		case <-ticker.C:
		}
	}
}
