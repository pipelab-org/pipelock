// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReloadSourceIdentity(t *testing.T) {
	for _, body := range []string{"mode: balanced\n", "mode: [broken\n"} {
		t.Run(body, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, hash, err := LoadReload(path)
			want := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
			if hash != want {
				t.Fatalf("hash=%s want=%s", hash, want)
			}
			if cfg != nil && cfg.Hash() != hash {
				t.Fatal("source identity differs from loaded config")
			}
			if (err != nil) != (body == "mode: [broken\n") {
				t.Fatalf("load=%v", err)
			}
		})
	}
	r := NewReloader(filepath.Join(t.TempDir(), "missing.yaml"))
	if r.WatchEstablished() {
		t.Fatal("unstarted watcher reported active")
	}
	_, hash, err := LoadReload(r.path)
	if err == nil || hash != "" {
		t.Fatalf("missing file hash=%q err=%v", hash, err)
	}
}

func TestReloadCoalesceNewestSourceStickySignal(t *testing.T) {
	next := ReloadEvent{Trigger: ReloadTriggerFile, SourceHash: "newest"}
	got := coalesceReloadEvents(ReloadEvent{Trigger: ReloadTriggerSignal, SourceHash: "older"}, next)
	if got.Trigger != ReloadTriggerSignal || got.SourceHash != "newest" {
		t.Fatalf("coalesced=%+v", got)
	}
}
