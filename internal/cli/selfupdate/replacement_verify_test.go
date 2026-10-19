// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	releasetrust "github.com/luckyPipewrench/pipelock/internal/release"
)

func TestReplacementVerificationLeavesInstalledStateUnchanged(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(map[string][]byte, string)
		want   error
	}{
		{name: "tampered archive", mutate: func(assets map[string][]byte, asset string) { assets[asset] = []byte("tampered") }, want: ErrChecksumMismatch},
		{name: "tampered checksums", mutate: func(assets map[string][]byte, _ string) { assets[checksumsFile] = []byte("tampered") }, want: ErrSignatureVerify},
		{name: "tampered manifest", mutate: func(assets map[string][]byte, _ string) { assets[releasetrust.ManifestFile] = []byte("tampered") }, want: ErrSignatureVerify},
		{name: "missing signature", mutate: func(assets map[string][]byte, _ string) { delete(assets, releasetrust.ManifestSigFile) }, want: ErrSignatureVerify},
		{name: "wrong platform", want: ErrUnsupportedPlatform},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assets, asset := standardAssets(t, testLatest, "windows")
			if tt.mutate != nil {
				tt.mutate(assets, asset)
			}
			rs := newReleaseServer(t, testLatest, assets)
			target, _ := replacementFixture(t)
			writeReplacementFixture(t, target+backupSuffix, "prior rollback backup")
			opts := baseOptions(rs, target)
			opts.GOOS = "windows"
			if tt.name == "wrong platform" {
				opts.GOARCH = "unsupported"
			}
			st, err := opts.Run(context.Background())
			if !errors.Is(err, tt.want) {
				t.Fatalf("error=%v, want %v", err, tt.want)
			}
			if st != nil && st.Applied {
				t.Fatal("failed verification marked applied")
			}
			assertReplacementBytes(t, target, originalBytes)
			assertReplacementBytes(t, target+backupSuffix, "prior rollback backup")
			// Only the files created by the fixture remain; no recovery state appeared.
			assertDirEntries(t, filepath.Dir(target), "candidate.exe", "pipelock.exe", "pipelock.exe.bak")
		})
	}
}

func TestReplacementImplicitDowngradeLeavesBackupUnchanged(t *testing.T) {
	assets, _ := standardAssets(t, testCurrent, "windows")
	rs := newReleaseServer(t, testCurrent, assets)
	target, _ := replacementFixture(t)
	writeReplacementFixture(t, target+backupSuffix, "prior rollback backup")
	opts := baseOptions(rs, target)
	opts.GOOS = "windows"
	opts.CurrentVersion = strings.TrimPrefix(testLatest, "v")
	st, err := opts.Run(context.Background())
	if !errors.Is(err, ErrUpToDate) || st.Applied {
		t.Fatalf("status=%+v error=%v", st, err)
	}
	assertReplacementBytes(t, target, originalBytes)
	assertReplacementBytes(t, target+backupSuffix, "prior rollback backup")
}
