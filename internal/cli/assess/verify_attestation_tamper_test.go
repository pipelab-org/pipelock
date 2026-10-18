// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/report/attestation"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// resealAttestation applies edit to attestation.json, re-signs it with the
// run's own key, and re-seals the signed manifest over the new artifact
// hashes. The bundle-level integrity check therefore still passes, so the
// attestation-level checks behind it are the ones that must refuse.
func resealAttestation(t *testing.T, runDir, keystoreDir, agent string, edit func(t *testing.T, runDir string, att *attestation.Attestation)) {
	t.Helper()
	attPath := filepath.Join(runDir, "attestation.json")
	data, err := os.ReadFile(filepath.Clean(attPath))
	if err != nil {
		t.Fatal(err)
	}
	var att attestation.Attestation
	if err := json.Unmarshal(data, &att); err != nil {
		t.Fatal(err)
	}
	edit(t, runDir, &att)
	if err := writeAttestationJSON(attPath, &att); err != nil {
		t.Fatal(err)
	}
	priv, err := signing.NewKeystore(keystoreDir).LoadPrivateKey(agent)
	if err != nil {
		t.Fatal(err)
	}
	signAndSave(t, attPath, priv)
	resealManifest(t, runDir, priv)
}

func signAndSave(t *testing.T, path string, priv ed25519.PrivateKey) {
	t.Helper()
	sig, err := signing.SignFile(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.SaveSignature(sig, path+signing.SigExtension); err != nil {
		t.Fatal(err)
	}
}

// resealManifest recomputes the hash of every artifact still present and
// drops entries for removed ones, then re-signs manifest.json.
func resealManifest(t *testing.T, runDir string, priv ed25519.PrivateKey) {
	t.Helper()
	manifest := readTestManifest(t, runDir)
	for name := range manifest.Artifacts {
		if _, err := os.Stat(filepath.Join(runDir, name)); errors.Is(err, os.ErrNotExist) {
			delete(manifest.Artifacts, name)
			continue
		}
		if err := recordArtifactHash(runDir, name, manifest.Artifacts); err != nil {
			t.Fatal(err)
		}
	}
	manifestPath := filepath.Join(runDir, "manifest.json")
	if err := writeManifest(manifestPath, &manifest); err != nil {
		t.Fatal(err)
	}
	signAndSave(t, manifestPath, priv)
}

// flipLastHex returns h with only its final hex digit changed, so a
// comparison that stops short of the full digest still sees a match.
func flipLastHex(t *testing.T, h string) string {
	t.Helper()
	if len(h) != 64 {
		t.Fatalf("expected a 64-char hex digest, got %q", h)
	}
	last := byte('0')
	if h[63] == '0' {
		last = '1'
	}
	return h[:63] + string(last)
}

func runDirListing(t *testing.T, dir string) []string {
	t.Helper()
	// Open once so content reads stay inside this directory. A path swapped
	// for a symlink between the walk and the read must not escape the root.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	var out []string
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entry := rel + "|" + info.ModTime().String() + "|" + info.Mode().String()
		if info.Mode().IsRegular() {
			data, err := root.ReadFile(rel)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			entry += "|" + strconv.FormatInt(info.Size(), 10) + "|" + hex.EncodeToString(sum[:])
		}
		out = append(out, entry)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func TestAssessVerifyAttestationRefusesResealedTampering(t *testing.T) {
	type editFn func(t *testing.T, runDir string, att *attestation.Attestation)
	tests := []struct {
		name     string
		edit     editFn
		after    func(t *testing.T, runDir, keystoreDir, agent string) // post-seal tampering
		wantExit int
		want     string // empty means verification must pass
	}{
		{name: "resealed but unchanged verifies", edit: func(*testing.T, string, *attestation.Attestation) {}},
		{
			name: "schema version", edit: func(_ *testing.T, _ string, a *attestation.Attestation) { a.SchemaVersion = "0" },
			wantExit: verifyExitTamperedArtifact, want: "attestation schema version",
		},
		{
			name: "run id mismatch", edit: func(_ *testing.T, _ string, a *attestation.Attestation) { a.RunID = "other-run" },
			wantExit: verifyExitTamperedArtifact, want: "does not match manifest",
		},
		{
			name: "license tier", edit: func(_ *testing.T, _ string, a *attestation.Attestation) { a.LicenseTier = "free" },
			wantExit: verifyExitTamperedArtifact, want: "attestation license tier",
		},
		{name: "primary artifact traversal", edit: func(_ *testing.T, _ string, a *attestation.Attestation) {
			a.PrimaryArtifact = "../assessment.json"
		}, wantExit: verifyExitTamperedArtifact, want: "invalid primary artifact"},
		{
			name: "primary artifact hash empty", edit: func(_ *testing.T, _ string, a *attestation.Attestation) { a.PrimaryArtifactSHA256 = "" },
			wantExit: verifyExitTamperedArtifact, want: "invalid primary artifact",
		},
		{
			name: "expired", edit: func(_ *testing.T, _ string, a *attestation.Attestation) { a.ExpiresAt = time.Now().Add(-time.Hour) },
			wantExit: verifyExitTamperedArtifact, want: "attestation expired",
		},
		{name: "primary artifact hash mismatch", edit: func(t *testing.T, _ string, a *attestation.Attestation) {
			a.PrimaryArtifactSHA256 = flipLastHex(t, a.PrimaryArtifactSHA256)
		}, wantExit: verifyExitTamperedArtifact, want: "primary artifact hash mismatch"},
		{name: "signer fingerprint mismatch", edit: func(_ *testing.T, _ string, a *attestation.Attestation) {
			a.SignerKeyFingerprint = strings.Repeat("ab", 32)
		}, wantExit: verifyExitBadSignature, want: "key fingerprint mismatch"},
		{
			name: "badge hash mismatch", edit: func(t *testing.T, _ string, a *attestation.Attestation) {
				a.BadgeSHA256 = flipLastHex(t, a.BadgeSHA256)
			},
			wantExit: verifyExitTamperedArtifact, want: "badge.svg hash mismatch",
		},
		{name: "badge referenced but missing", edit: func(t *testing.T, runDir string, a *attestation.Attestation) {
			if a.BadgeSHA256 == "" {
				t.Fatal("fixture attestation must reference a badge")
			}
			if err := os.Remove(filepath.Join(runDir, "badge.svg")); err != nil {
				t.Fatal(err)
			}
		}, wantExit: verifyExitTamperedArtifact, want: "badge.svg referenced in attestation but"},
		{
			name: "attestation signature stripped", edit: func(*testing.T, string, *attestation.Attestation) {},
			after: func(t *testing.T, runDir, keystoreDir, agent string) {
				if err := os.Remove(filepath.Join(runDir, "attestation.json"+signing.SigExtension)); err != nil {
					t.Fatal(err)
				}
				priv, err := signing.NewKeystore(keystoreDir).LoadPrivateKey(agent)
				if err != nil {
					t.Fatal(err)
				}
				resealManifest(t, runDir, priv)
			}, wantExit: verifyExitBadSignature, want: "attestation signature file missing",
		},
		{
			name: "attestation signed by a different key", edit: func(*testing.T, string, *attestation.Attestation) {},
			after: func(t *testing.T, runDir, keystoreDir, agent string) {
				_, other, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signAndSave(t, filepath.Join(runDir, "attestation.json"), other)
				priv, err := signing.NewKeystore(keystoreDir).LoadPrivateKey(agent)
				if err != nil {
					t.Fatal(err)
				}
				resealManifest(t, runDir, priv)
			}, wantExit: verifyExitBadSignature, want: "attestation signature verification failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runDir, keystoreDir, agent := setupFinalizedRunWithAttestation(t)
			resealAttestation(t, runDir, keystoreDir, agent, tt.edit)
			if tt.after != nil {
				tt.after(t, runDir, keystoreDir, agent)
			}
			if code, err := runAssessVerify(runDir, agent, keystoreDir); code != 0 || err != nil {
				t.Fatalf("fixture must keep bundle verification green, got exit %d: %v", code, err)
			}
			before := runDirListing(t, runDir)
			code, err := runAssessVerifyAttestation(runDir, agent, keystoreDir)
			if tt.want == "" {
				if err != nil || code != 0 {
					t.Fatalf("verify = (%d, %v), want (0, nil)", code, err)
				}
			} else {
				if code != tt.wantExit {
					t.Fatalf("exit code = %d (%v), want %d", code, err, tt.wantExit)
				}
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("error = %v, want %q", err, tt.want)
				}
			}
			if after := runDirListing(t, runDir); strings.Join(after, "\n") != strings.Join(before, "\n") {
				t.Fatalf("verification modified the run directory:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

func TestAssessVerifyAttestationRejectsMalformedPayload(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		wantExit int
		check    func(error) bool
	}{
		{name: "valid payload control", payload: ""},
		{
			name: "truncated json", payload: `{"schema_version":`, wantExit: verifyExitTamperedArtifact,
			check: func(err error) bool { var se *json.SyntaxError; return errors.As(err, &se) },
		},
		{
			name: "wrong json type", payload: `{"run_id": 7}`, wantExit: verifyExitTamperedArtifact,
			check: func(err error) bool { var te *json.UnmarshalTypeError; return errors.As(err, &te) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runDir, keystoreDir, agent := setupFinalizedRunWithAttestation(t)
			if tt.payload != "" {
				attPath := filepath.Join(runDir, "attestation.json")
				if err := os.WriteFile(attPath, []byte(tt.payload), 0o600); err != nil {
					t.Fatal(err)
				}
				priv, err := signing.NewKeystore(keystoreDir).LoadPrivateKey(agent)
				if err != nil {
					t.Fatal(err)
				}
				signAndSave(t, attPath, priv)
				resealManifest(t, runDir, priv)
			}
			if code, err := runAssessVerify(runDir, agent, keystoreDir); code != 0 || err != nil {
				t.Fatalf("fixture must keep bundle verification green, got exit %d: %v", code, err)
			}
			before := runDirListing(t, runDir)
			code, err := runAssessVerifyAttestation(runDir, agent, keystoreDir)
			if after := runDirListing(t, runDir); strings.Join(after, "\n") != strings.Join(before, "\n") {
				t.Fatalf("verification modified the run directory:\nbefore %v\nafter  %v", before, after)
			}
			if tt.check == nil {
				if err != nil || code != 0 {
					t.Fatalf("verify = (%d, %v), want (0, nil)", code, err)
				}
				return
			}
			if code != tt.wantExit || err == nil || !strings.Contains(err.Error(), "parsing attestation") {
				t.Fatalf("verify = (%d, %v), want exit %d parsing error", code, err, tt.wantExit)
			}
			if !tt.check(err) {
				t.Fatalf("error %v does not carry the decoder cause", err)
			}
		})
	}
}
