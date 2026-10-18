// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// buildEvidenceOnlyRecorderJSONL writes a closed per-run recorder that holds
// EvidenceReceipt v2 entries and no action receipts.
func buildEvidenceOnlyRecorderJSONL(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{Recorder: rec, Signer: proxydecision.NewKeyedSigner(priv), Sanitize: proxydecision.SanitizeFromRedactor(rec.ReceiptRedactor()), Principal: "local", Actor: "pipelock", Session: session})
	for range 2 {
		if err := v2.Emit(proxydecision.Decision{ActionType: "http_request", Transport: "forward", Target: "https://api.vendor.example/a", Verdict: "allow", WinningSource: proxydecision.SourceScanner, PolicySources: []string{proxydecision.SourceScanner}, PolicyHash: strings.Repeat("b", 64)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("recorder files = %v, %v", files, err)
	}
	return files[0], pub
}

// --require-seal makes a missing seal invalid evidence (exit 1) whichever
// receipt chain the recorder holds, with or without --allow-prefix, in text
// and JSON output. Without it the same recorders are unproven prefixes.
func TestWholeRecorderRequireSealParity(t *testing.T) {
	evidencePath, evidenceKey := buildEvidenceOnlyRecorderJSONL(t)
	actionPath, actionKey := buildChainJSONL(t, 1)
	recorders := []struct{ name, path, key string }{
		{"evidence-only", evidencePath, hex.EncodeToString(evidenceKey)},
		{"action-chain", actionPath, hex.EncodeToString(actionKey)},
	}
	for _, tc := range []struct {
		name  string
		flags []string
		code  int
	}{
		{"unproven", nil, 3},
		{"allow-prefix", []string{"--allow-prefix"}, 0},
		{"require-seal", []string{"--require-seal"}, 1},
		{"require-seal-allow-prefix", []string{"--require-seal", "--allow-prefix"}, 1},
	} {
		for _, r := range recorders {
			for _, jsonMode := range []bool{false, true} {
				name := r.name + "/" + tc.name
				if jsonMode {
					name += "/json"
				}
				t.Run(name, func(t *testing.T) {
					cmd := VerifyReceiptCmd()
					var out bytes.Buffer
					cmd.SetOut(&out)
					cmd.SetErr(&out)
					cmd.SilenceUsage, cmd.SilenceErrors = true, true
					args := append([]string{r.path, "--whole-recorder", "--key", r.key}, tc.flags...)
					if jsonMode {
						args = append(args, "--json")
					}
					cmd.SetArgs(args)
					err := cmd.Execute()
					code := 0
					if err != nil {
						code = 1
						var ee *cliutil.ExitError
						if errors.As(err, &ee) {
							code = ee.Code
						}
					}
					if code != tc.code {
						t.Fatalf("exit=%d want=%d: %v\n%s", code, tc.code, err, out.String())
					}
					if tc.code == 1 && !errors.Is(err, errUnsealedRecorder) {
						t.Fatalf("err = %v, want the missing-seal error", err)
					}
					if tc.code == 1 {
						if strings.Contains(out.String(), "CHAIN VALID") || strings.Contains(out.String(), endproof.Prefix) {
							t.Fatalf("missing seal presented as success or an unproven prefix:\n%s", out.String())
						}
						if jsonMode {
							var report endproof.Report
							if err := json.Unmarshal(out.Bytes(), &report); err != nil {
								t.Fatal(err)
							}
							if report.Integrity != "invalid" || report.EndProof.Proven || report.Status != endproof.Invalid {
								t.Fatalf("json report=%+v", report)
							}
						} else if !strings.Contains(out.String(), "INCOMPLETE:") {
							t.Fatalf("missing incomplete verdict:\n%s", out.String())
						}
					}
				})
			}
		}
	}
}

// Under --require-seal an evidence-only recorder still checks --expect-head
// and --expect-seq: a pin that does not match fails as a pin mismatch before
// the seal is considered, and a matching pin leaves the missing seal as the
// failure.
func TestWholeRecorderRequireSealChecksPin(t *testing.T) {
	path, pub := buildEvidenceOnlyRecorderJSONL(t)
	key := hex.EncodeToString(pub)
	var head string
	var finalSeq uint64
	{
		cmd := VerifyReceiptCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{path, "--key", key, "--allow-prefix", "--json"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		var report struct {
			Chains []chainCLIReport `json:"chains"`
		}
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report.Chains) != 1 {
			t.Fatalf("report %q: %v", out.String(), err)
		}
		head, finalSeq = report.Chains[0].RootHash, report.Chains[0].FinalSeq
	}
	wrongHead := strings.Repeat("0", 64)
	seq := strconv.FormatUint(finalSeq, 10)
	wrongSeq := strconv.FormatUint(finalSeq+1, 10)
	for _, tc := range []struct {
		name    string
		flags   []string
		wantErr string
	}{
		{"head-mismatch", []string{"--expect-head", wrongHead}, "does not match expected head"},
		{"head-mismatch-allow-prefix", []string{"--expect-head", wrongHead, "--allow-prefix"}, "does not match expected head"},
		{"seq-mismatch", []string{"--expect-head", head, "--expect-seq", wrongSeq}, "does not match expected seq"},
		{"pin-matches", []string{"--expect-head", head, "--expect-seq", seq}, ""},
	} {
		for _, jsonMode := range []bool{false, true} {
			name := tc.name
			if jsonMode {
				name += "/json"
			}
			t.Run(name, func(t *testing.T) {
				cmd := VerifyReceiptCmd()
				var out bytes.Buffer
				cmd.SetOut(&out)
				cmd.SetErr(&out)
				cmd.SilenceUsage, cmd.SilenceErrors = true, true
				args := append([]string{path, "--whole-recorder", "--key", key, "--require-seal"}, tc.flags...)
				if jsonMode {
					args = append(args, "--json")
				}
				cmd.SetArgs(args)
				err := cmd.Execute()
				if code := cliutil.ExitCodeOf(err); code != 1 {
					t.Fatalf("exit=%d want=1: %v\n%s", code, err, out.String())
				}
				if tc.wantErr == "" {
					if !errors.Is(err, errUnsealedRecorder) {
						t.Fatalf("err = %v, want the missing-seal error", err)
					}
					if strings.Contains(out.String(), "CHAIN VALID") || strings.Contains(out.String(), endproof.Prefix) {
						t.Fatalf("matching pin presented the missing seal as success:\n%s", out.String())
					}
					return
				}
				if errors.Is(err, errUnsealedRecorder) || !strings.Contains(err.Error()+out.String(), tc.wantErr) {
					t.Fatalf("err = %v, want the pin mismatch %q\n%s", err, tc.wantErr, out.String())
				}
			})
		}
	}
}

// The in-memory whole-recorder oracle is the streaming verifier's expected
// verdict. Production sets CheckEnd, so a required seal on an evidence-only
// recorder has to deny on both, including when --allow-prefix is also set.
func TestWholeRecorderRequireSealMatchesLegacy(t *testing.T) {
	path, pub := buildEvidenceOnlyRecorderJSONL(t)
	key := hex.EncodeToString(pub)
	name := filepath.Base(path)
	for _, tc := range []struct {
		name string
		opts verifyReceiptOptions
		pin  bool
	}{
		{name: "require-seal", opts: verifyReceiptOptions{CheckEnd: true, RequireSeal: true}},
		{name: "require-seal-allow-prefix", opts: verifyReceiptOptions{CheckEnd: true, RequireSeal: true, AllowPrefix: true}},
		{name: "require-seal-pin", opts: verifyReceiptOptions{CheckEnd: true, RequireSeal: true, ExpectedHead: strings.Repeat("0", 64)}, pin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stream, legacy bytes.Buffer
			streamErr := verifyWholeRecorderFromFile(&stream, name, path, []string{key}, tc.opts)
			legacyErr := legacyVerifyWholeRecorderFromFile(&legacy, name, path, []string{key}, tc.opts)
			if verdictOf(&stream, streamErr) != verdictOf(&legacy, legacyErr) {
				t.Fatalf("streaming verdict differs\nstreaming: %v %s\nin-memory: %v %s", streamErr, stream.String(), legacyErr, legacy.String())
			}
			if tc.pin {
				if streamErr == nil || errors.Is(streamErr, errUnsealedRecorder) || !strings.Contains(streamErr.Error(), "does not match expected head") {
					t.Fatalf("pin err = %v", streamErr)
				}
				return
			}
			if !errors.Is(streamErr, errUnsealedRecorder) {
				t.Fatalf("err = %v, want the missing-seal error", streamErr)
			}
			if strings.Contains(stream.String(), "CHAIN VALID") || strings.Contains(stream.String(), endproof.Prefix) {
				t.Fatalf("missing seal presented as success or an unproven prefix:\n%s", stream.String())
			}
		})
	}
}
