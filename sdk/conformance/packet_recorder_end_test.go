// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// Regenerate only the packet recorder-end cases with:
//
//	go test ./sdk/conformance -run TestGeneratePacketRecorderEndCorpus -update-end-proof
func TestGeneratePacketRecorderEndCorpus(t *testing.T) {
	if !*updateEndProof {
		t.Skip("pass -update-end-proof")
	}
	generatePacketRecorderEndCorpus(t)
}

func generatePacketRecorderEndCorpus(t *testing.T) {
	t.Helper()
	pub, priv := keyFromSeed(seedEndProofSigner)
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000, SignCheckpoints: true}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	policy := strings.Repeat("c", 64)
	actions := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: policy, Principal: "local", Actor: "pipelock", Session: session})
	evidence := proxydecision.NewEmitter(proxydecision.EmitterConfig{Recorder: rec, Signer: proxydecision.NewKeyedSigner(priv), Principal: "local", Actor: "pipelock", Session: session})
	if actions == nil || evidence == nil {
		t.Fatal("emitter construction failed")
	}
	if err := actions.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := actions.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: "allow", Transport: "fetch", Target: "https://api.vendor.example/data"}); err != nil {
			t.Fatal(err)
		}
		if err := evidence.Emit(proxydecision.Decision{ActionType: "http_request", Transport: "fetch", Target: "https://api.vendor.example/data", Verdict: "allow", WinningSource: proxydecision.SourceScanner, PolicySources: []string{proxydecision.SourceScanner}, PolicyHash: policy}); err != nil {
			t.Fatal(err)
		}
	}
	if err := actions.EmitSessionClose("graceful_shutdown"); err != nil {
		t.Fatal(err)
	}
	if err := actions.EmitTranscriptRoot(session); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("recorder files: %v %v", files, err)
	}
	closed := readLines(t, files[0])
	root := lastIndexOfType(t, closed, "transcript_root")
	lastV2 := lastIndexOfType(t, closed, "evidence_receipt")
	cut := append([]string{}, closed[:lastV2]...)
	cut = append(cut, closed[lastV2+1:root]...)
	badSeal := append([]string{}, closed...)
	var rootEntry struct{ Detail receipt.TranscriptRoot }
	if err := json.Unmarshal([]byte(badSeal[root]), &rootEntry); err != nil {
		t.Fatal(err)
	}
	badSeal[root] = strings.Replace(badSeal[root], rootEntry.Detail.RootHash, strings.Repeat("0", 64), 1)
	badSeal = rehash(t, badSeal)
	checkpointIndex := lastIndexOfType(t, badSeal, "checkpoint")
	checkpoint, err := recorder.ParseEntryLine([]byte(badSeal[checkpointIndex]))
	if err != nil {
		t.Fatal(err)
	}
	var cp struct{ Detail recorder.CheckpointDetail }
	if err := json.Unmarshal([]byte(badSeal[checkpointIndex]), &cp); err != nil {
		t.Fatal(err)
	}
	// Keep the recorder authentically signed. Otherwise a missing root check
	// could hide behind the checkpoint signature failure in this fixture.
	signature := hex.EncodeToString(ed25519.Sign(priv, []byte(checkpoint.PrevHash)))
	badSeal[checkpointIndex] = strings.Replace(badSeal[checkpointIndex], cp.Detail.Signature, signature, 1)
	variants := map[string][]string{
		"v2-closed":        closed,
		"v2-tail-cut":      rehash(t, cut),
		"v2-no-checkpoint": closed[:len(closed)-1],
		"v2-bad-seal":      rehash(t, badSeal),
	}
	for name, lines := range variants {
		if err := os.WriteFile(filepath.Join(endProofDir, name+".jsonl"), joinLines(lines), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifestPath := filepath.Join(endProofDir, "expect.json")
	data, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Key         string                    `json:"key"`
		Cases       []endProofCase            `json:"cases"`
		AuditPacket []auditPacketEndProofCase `json:"audit_packet"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.Key != hex.EncodeToString(pub) {
		t.Fatalf("manifest key mismatch or invalid: %v", err)
	}
	retained := manifest.AuditPacket[:0]
	for _, c := range manifest.AuditPacket {
		if !strings.HasPrefix(c.Name, "v2-") {
			retained = append(retained, c)
		}
	}
	manifest.AuditPacket = append(retained,
		auditPacketEndProofCase{Name: "v2-closed", File: "v2-closed.jsonl", Exit: 0, Integrity: "valid", Status: "CHAIN VALID", Proven: true},
		auditPacketEndProofCase{Name: "v2-tail-cut", File: "v2-tail-cut.jsonl", Exit: 3, Integrity: "valid", Status: endProofPrefix},
		auditPacketEndProofCase{Name: "v2-no-checkpoint", File: "v2-no-checkpoint.jsonl", Exit: 3, Integrity: "valid", Status: endProofPrefix},
		auditPacketEndProofCase{Name: "v2-bad-seal", File: "v2-bad-seal.jsonl", Exit: 1, Integrity: "invalid", Status: "CHAIN BROKEN"},
	)
	data, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPacketRecorderEndCorpusShape(t *testing.T) {
	pub, _ := keyFromSeed(seedEndProofSigner)
	for name, wantV2 := range map[string]int{"v2-closed": 2, "v2-tail-cut": 1, "v2-no-checkpoint": 2, "v2-bad-seal": 2} {
		t.Run(name, func(t *testing.T) {
			entries, err := recorder.ReadHistoryEntries(filepath.Join(endProofDir, name+".jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			actions, evidence, _, err := receipt.RecorderFileChains(name+".jsonl", entries)
			if err != nil {
				t.Fatal(err)
			}
			if err := recorder.VerifyCheckpoints(entries, pub); err != nil {
				t.Fatalf("checkpoint signatures must remain valid even in the bad-seal case: %v", err)
			}
			chain := receipt.VerifyChain(actions, hex.EncodeToString(pub))
			if !chain.Valid || len(actions) != 4 || len(endproof.ActionEvidence(actions)) == 0 {
				t.Fatalf("action control must remain intact, closed, and unchanged: %+v", chain)
			}
			v2 := receipt.VerifyEvidenceChainTrusted(evidence, []string{hex.EncodeToString(pub)}, contractreceipt.ChainVerifyOptions{})
			if !v2.Valid || len(evidence) != wantV2 {
				t.Fatalf("v2 control: count=%d want=%d result=%+v", len(evidence), wantV2, v2)
			}
			var roots, checkpoints int
			for _, entry := range entries {
				switch entry.Type {
				case "transcript_root":
					roots++
				case "checkpoint":
					checkpoints++
				}
			}
			wantRoots, wantCheckpoints := 1, 1
			if name == "v2-tail-cut" {
				wantRoots, wantCheckpoints = 0, 0
			}
			if name == "v2-no-checkpoint" {
				wantCheckpoints = 0
			}
			if roots != wantRoots || checkpoints != wantCheckpoints {
				t.Fatalf("roots=%d checkpoints=%d, want %d %d", roots, checkpoints, wantRoots, wantCheckpoints)
			}
		})
	}
}
