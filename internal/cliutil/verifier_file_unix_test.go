// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cliutil

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const regularVerifierFileError = "input must be a regular file"

func TestReadVerifierFileNamedPipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	requireNonRegularVerifierInput(t, func() error {
		_, err := ReadVerifierFile(path)
		return err
	})
}

func TestReadVerifierFileRechecksOpenedInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkVerifierFileType(path); err != nil {
		t.Fatalf("check original input: %v", err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := unix.Mkfifo(replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	requireNonRegularVerifierInput(t, func() error {
		file, err := openCheckedVerifierFile(path, verifierOpenFlags)
		if file != nil {
			return file.Close()
		}
		return err
	})
}

func TestReadVerifierFileUnixInputTypes(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		_, err := ReadVerifierFile(t.TempDir())
		if err == nil || err.Error() != regularVerifierFileError {
			t.Fatalf("ReadVerifierFile error = %v, want %q", err, regularVerifierFileError)
		}
	})
	t.Run("socket", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "artifact")
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := listener.Close(); err != nil {
				t.Error(err)
			}
		})
		_, err = ReadVerifierFile(path)
		if err == nil || err.Error() != regularVerifierFileError {
			t.Fatalf("ReadVerifierFile error = %v, want %q", err, regularVerifierFileError)
		}
	})
	t.Run("symlink to regular file", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		const artifact = "receipt"
		if err := os.WriteFile(target, []byte(artifact), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink("target", link); err != nil {
			t.Fatal(err)
		}
		got, err := ReadVerifierFile(link)
		if err != nil || string(got) != artifact {
			t.Fatalf("ReadVerifierFile = %q, %v, want %q", got, err, artifact)
		}
	})
}

func requireNonRegularVerifierInput(t *testing.T, read func() error) {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- read() }()
	select {
	case err := <-result:
		if err == nil || err.Error() != regularVerifierFileError {
			t.Fatalf("verifier input error = %v, want %q", err, regularVerifierFileError)
		}
	case <-time.After(testwait.Deadline(500 * time.Millisecond)):
		t.Fatal("verifier input did not return before the deadline")
	}
}

func TestReadVerifierFilePathDisappears(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkVerifierFileType(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := checkVerifierFileType(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed input check error = %v, want %v", err, os.ErrNotExist)
	}
	file, err := openCheckedVerifierFile(path, verifierOpenFlags)
	if file != nil {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("opening removed input returned a file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed input open error = %v, want %v", err, os.ErrNotExist)
	}
}

func TestReadVerifierFileSearchableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permission bits do not restrict root")
	}
	dir := filepath.Join(t.TempDir(), "searchable")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	const artifact = "receipt"
	path := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(path, []byte(artifact), 0o600); err != nil {
		t.Fatal(err)
	}
	// Search permission without read permission: the name can be opened but
	// the directory cannot be listed.
	if err := unix.Chmod(dir, 0o100); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Chmod(dir, 0o750); err != nil {
			t.Error(err)
		}
	})
	if _, err := os.ReadDir(dir); err == nil {
		t.Fatal("test directory is still listable")
	}
	got, err := ReadVerifierFile(path)
	if err != nil || string(got) != artifact {
		t.Fatalf("ReadVerifierFile = %q, %v, want %q", got, err, artifact)
	}
}
