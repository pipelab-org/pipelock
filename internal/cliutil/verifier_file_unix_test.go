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
	const name = "artifact"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := checkVerifierFileType(root, name); err != nil {
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
		file, err := openCheckedVerifierFile(root, name, verifierOpenFlags)
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
	const name = "artifact"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := checkVerifierFileType(root, name); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := checkVerifierFileType(root, name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed input check error = %v, want %v", err, os.ErrNotExist)
	}
	file, err := openCheckedVerifierFile(root, name, verifierOpenFlags)
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
