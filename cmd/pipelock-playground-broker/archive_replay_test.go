// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiveReplayOutputHelpersFailClosed(t *testing.T) {
	t.Run("kit output path must be new directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "already-a-file")
		if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
		f := &archiveReplayFlags{
			output:          filepath.Join(t.TempDir(), "bundle.tar.gz"),
			kitOutputDir:    path,
			linuxVerifier:   "unused",
			macOSVerifier:   "unused",
			windowsVerifier: "unused",
		}
		kits := []archiveKit{{name: "kit.zip", data: []byte("kit")}}
		if err := publishArchiveArtifacts(f, []byte("bundle"), kits); err == nil || !strings.Contains(err.Error(), "create kit output directory") {
			t.Fatalf("existing output file error = %v, want directory creation refusal", err)
		}
	})

	// A build failure must not reach the filesystem at all, because the build
	// runs before anything is published.
	t.Run("kit build stops before any output", func(t *testing.T) {
		kitDir := filepath.Join(t.TempDir(), "kits")
		f := &archiveReplayFlags{
			kitOutputDir:    kitDir,
			linuxVerifier:   filepath.Join(t.TempDir(), "missing-linux"),
			macOSVerifier:   filepath.Join(t.TempDir(), "missing-macos"),
			windowsVerifier: filepath.Join(t.TempDir(), "missing-windows"),
		}
		kits, err := buildArchiveVerifyKits(f, nil)
		if err == nil || !strings.Contains(err.Error(), "build linux verification kit") {
			t.Fatalf("missing verifier error = %v, want kit-build failure", err)
		}
		if kits != nil {
			t.Fatalf("a failed build returned kits: %v", kits)
		}
		if _, statErr := os.Stat(kitDir); !os.IsNotExist(statErr) {
			t.Fatalf("a failed kit build created the output directory: %v", statErr)
		}
	})

	// The finding this covers: a later write failure used to leave the bundle and
	// any earlier kits on disk, so a visitor could download a bundle whose kits
	// never arrived. Publication is now all-or-nothing.
	t.Run("a failed kit write removes every artifact this run created", func(t *testing.T) {
		dir := t.TempDir()
		bundlePath := filepath.Join(dir, "replay-bundle.tar.gz")
		kitDir := filepath.Join(dir, "kits")
		f := &archiveReplayFlags{output: bundlePath, kitOutputDir: kitDir}

		// The second kit collides with the first by name, so its O_EXCL create
		// fails after the bundle and the first kit are already written.
		kits := []archiveKit{
			{name: "same-name.zip", data: []byte("first")},
			{name: "same-name.zip", data: []byte("second")},
		}
		err := publishArchiveArtifacts(f, []byte("bundle"), kits)
		if err == nil || !strings.Contains(err.Error(), "create output") {
			t.Fatalf("error = %v, want the duplicate-name create refusal", err)
		}
		if _, statErr := os.Stat(bundlePath); !os.IsNotExist(statErr) {
			t.Fatal("the bundle survived a failed publication")
		}
		if _, statErr := os.Stat(filepath.Join(kitDir, "same-name.zip")); !os.IsNotExist(statErr) {
			t.Fatal("the first kit survived a failed publication")
		}
		if _, statErr := os.Stat(kitDir); !os.IsNotExist(statErr) {
			t.Fatal("the kit directory survived a failed publication")
		}
	})

	// Rollback must never touch an artifact it did not create. A pre-existing
	// output is refused before anything is written, so nothing is removed.
	t.Run("rollback never removes a pre-existing artifact", func(t *testing.T) {
		dir := t.TempDir()
		bundlePath := filepath.Join(dir, "replay-bundle.tar.gz")
		if err := os.WriteFile(bundlePath, []byte("serving-visitors"), 0o600); err != nil {
			t.Fatal(err)
		}
		f := &archiveReplayFlags{output: bundlePath, kitOutputDir: filepath.Join(dir, "kits")}
		kits := []archiveKit{{name: "kit.zip", data: []byte("kit")}}
		if err := publishArchiveArtifacts(f, []byte("bundle"), kits); err == nil {
			t.Fatal("publishing over an existing artifact must be refused")
		}
		data, err := os.ReadFile(filepath.Clean(bundlePath))
		if err != nil || string(data) != "serving-visitors" {
			t.Fatalf("the pre-existing artifact was removed or modified: %q, %v", data, err)
		}
	})

	// The writer reports CREATION separately from success, because rollback needs
	// both facts: a file it created must be removed even if the write failed, and
	// a path it did not create belongs to someone else and must never be touched.
	// Collapsing the two is what let a created-then-failed file survive rollback
	// and then block removal of the kit directory.
	t.Run("creation is reported separately from write success", func(t *testing.T) {
		dir := t.TempDir()

		fresh := filepath.Join(dir, "fresh.tar.gz")
		created, err := writeNewArchiveFile(fresh, []byte("bytes"))
		if err != nil {
			t.Fatalf("writeNewArchiveFile: %v", err)
		}
		if !created {
			t.Fatal("a file this call created was not reported as created, so rollback would leave it behind")
		}

		// A path that already exists was not created here. Reporting it as
		// created would make rollback delete an artifact serving visitors.
		created, err = writeNewArchiveFile(fresh, []byte("second"))
		if err == nil {
			t.Fatal("writing over an existing path must be refused")
		}
		if created {
			t.Fatal("an existing path was reported as created; rollback would delete an artifact this run did not write")
		}
	})

	t.Run("archive file writes exact bytes and never replaces directory", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "replay.tar.gz")
		want := []byte("replay-bytes")
		if _, err := writeNewArchiveFile(path, want); err != nil {
			t.Fatalf("writeNewArchiveFile: %v", err)
		}
		got, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read output: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("output = %q, want %q", got, want)
		}
		created, err := writeNewArchiveFile(dir, want)
		if err == nil || !strings.Contains(err.Error(), "create output") {
			t.Fatalf("directory output error = %v, want create-output refusal", err)
		}
		if created {
			t.Fatal("an existing directory was reported as created")
		}
	})
}
