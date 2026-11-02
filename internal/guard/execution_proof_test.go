// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package guard

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestExecutionProofBindsEffectiveInvocation(t *testing.T) {
	newValidProof := func() ExecutionProof {
		return NewExecutionProof(
			EnforcementRecord{State: EnforcementEnforced, Mechanism: "landlock", Coverage: CoverageFull},
			ExecControlOptions{Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool"},
			[]string{"tool", "arg"},
		)
	}
	t.Run("valid proof", func(t *testing.T) {
		if err := newValidProof().VerifyInvocation(ExecControlOptions{
			Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool",
		}, []string{"tool", "arg"}); err != nil {
			t.Fatalf("VerifyInvocation: %v", err)
		}
	})
	for _, testCase := range []struct {
		name     string
		expected ExecControlOptions
		command  []string
	}{
		{name: "wrong requested profile", expected: ExecControlOptions{Profile: "other", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool"}, command: []string{"tool", "arg"}},
		{name: "wrong requested workspace", expected: ExecControlOptions{Profile: "worker", PolicyHash: "config-hash", Workspace: "/other", TempDir: "/tmp/private", Binary: "/usr/bin/tool"}, command: []string{"tool", "arg"}},
		{name: "wrong requested temporary directory", expected: ExecControlOptions{Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/other", Binary: "/usr/bin/tool"}, command: []string{"tool", "arg"}},
		{name: "wrong requested binary", expected: ExecControlOptions{Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/other"}, command: []string{"tool", "arg"}},
		{name: "wrong requested argv", expected: ExecControlOptions{Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool"}, command: []string{"tool", "other"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := newValidProof().VerifyInvocation(testCase.expected, testCase.command); err == nil {
				t.Fatal("proof for a different requested invocation was accepted")
			}
		})
	}
	t.Run("wrong config binding", func(t *testing.T) {
		if err := newValidProof().VerifyInvocation(ExecControlOptions{
			Profile: "worker", PolicyHash: "other-config", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool",
		}, []string{"tool", "arg"}); err == nil {
			t.Fatal("proof with the wrong config binding was accepted")
		}
	})
	t.Run("tampered record through invocation verifier", func(t *testing.T) {
		proof := newValidProof()
		proof.Record.Coverage = CoveragePartial
		if err := proof.VerifyInvocation(ExecControlOptions{
			Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool",
		}, []string{"tool", "arg"}); err == nil {
			t.Fatal("invocation verifier accepted a tampered enforcement record")
		}
	})
	t.Run("execution failure", func(t *testing.T) {
		proof := newValidProof()
		proof.ExecError = "exec failed"
		if err := proof.Verify("config-hash"); err == nil {
			t.Fatal("proof carrying an exec failure was accepted")
		}
	})
	t.Run("tampered temporary directory", func(t *testing.T) {
		proof := newValidProof()
		proof.TempDir = "/tmp/other"
		if err := proof.Verify("config-hash"); err == nil {
			t.Fatal("tampered effective invocation was accepted")
		}
	})
	t.Run("tampered command", func(t *testing.T) {
		proof := newValidProof()
		proof.Command = []string{"other"}
		if err := proof.Verify("config-hash"); err == nil {
			t.Fatal("tampered command was accepted")
		}
	})
	t.Run("missing effective hash", func(t *testing.T) {
		proof := newValidProof()
		proof.EffectivePolicyHash = ""
		if err := proof.Verify("config-hash"); err == nil {
			t.Fatal("proof without an effective policy hash was accepted")
		}
	})

	// These are the remaining child-to-parent bindings. Each mutation keeps the
	// original digest, so a mixed or malformed helper record must fail closed
	// instead of being mistaken for proof about another invocation.
	for _, testCase := range []struct {
		name   string
		mutate func(*ExecutionProof)
	}{
		{name: "enforcement record", mutate: func(proof *ExecutionProof) { proof.Record.Coverage = CoveragePartial }},
		{name: "config hash", mutate: func(proof *ExecutionProof) { proof.ConfigPolicyHash = "other-config" }},
		{name: "profile", mutate: func(proof *ExecutionProof) { proof.Profile = "other-profile" }},
		{name: "workspace", mutate: func(proof *ExecutionProof) { proof.Workspace = "/other-workspace" }},
		{name: "binary", mutate: func(proof *ExecutionProof) { proof.Binary = "/usr/bin/other" }},
	} {
		t.Run("tampered "+testCase.name, func(t *testing.T) {
			proof := newValidProof()
			before := slices.Clone(proof.Command)
			testCase.mutate(&proof)
			if err := proof.Verify("config-hash"); err == nil {
				t.Fatalf("proof with tampered %s was accepted", testCase.name)
			}
			if !slices.Equal(proof.Command, before) {
				t.Fatal("proof verification mutated the command binding")
			}
		})
	}
}

// Thread retirement bookkeeping must not reach the hashed or encoded proof.
func TestExecutionProofOmitsThreadTaint(t *testing.T) {
	opts := ExecControlOptions{PolicyHash: "policy", Workspace: "/w", TempDir: "/t", Binary: "/bin/true"}
	record := EnforcementRecord{State: EnforcementEnforced, Mechanism: "landlock", Coverage: CoverageFull}
	clean := NewExecutionProof(record, opts, []string{"/bin/true"})
	record.threadTainted = true
	tainted := NewExecutionProof(record, opts, []string{"/bin/true"})
	if clean.EffectivePolicyHash != tainted.EffectivePolicyHash {
		t.Fatal("thread taint changed the execution proof hash")
	}
	cleanJSON, err := json.Marshal(clean)
	if err != nil {
		t.Fatal(err)
	}
	taintedJSON, err := json.Marshal(tainted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cleanJSON, taintedJSON) {
		t.Fatalf("thread taint changed the encoded proof:\n%s\n%s", cleanJSON, taintedJSON)
	}
}

// Captured on the pre-Withheld revision, not generated from the new schema.
func TestExecutionProofEmptyWithheldPreservesBytesAndHash(t *testing.T) {
	const before = `{"record":{"state":"enforced","mechanism":"landlock","required_abi":0,"observed_abi":null,"manifest_complete":false,"coverage":"full","outcomes":null},"config_policy_hash":"policy","effective_policy_hash":"e84859c0dbdcaff456d909eb9985ea47da031f92d5e6d0e991a099a8c22a4cae","workspace":"/w","temp_dir":"/t","binary":"/bin/true","command":["/bin/true"]}`
	for _, withheld := range [][]string{nil, {}} {
		record := EnforcementRecord{State: EnforcementEnforced, Mechanism: "landlock", Coverage: CoverageFull, Withheld: withheld}
		proof := NewExecutionProof(record, ExecControlOptions{PolicyHash: "policy", Workspace: "/w", TempDir: "/t", Binary: "/bin/true"}, []string{"/bin/true"})
		encoded, err := json.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != before {
			t.Fatalf("empty Withheld changed proof bytes:\n%s", encoded)
		}
		t.Logf("empty Withheld: byte-identical, hash %s", proof.EffectivePolicyHash)
	}
}

// This is the original typed record schema. Older Go decoders ignore Withheld,
// then reserialize this shape when checking the effective invocation digest.
type recordBeforeWithheld struct {
	State            EnforcementState `json:"state"`
	Mechanism        string           `json:"mechanism"`
	RequiredABI      int              `json:"required_abi"`
	ObservedABI      *int             `json:"observed_abi"`
	Reason           string           `json:"reason,omitempty"`
	ManifestComplete bool             `json:"manifest_complete"`
	Coverage         Coverage         `json:"coverage"`
	Unmediated       []string         `json:"unmediated,omitempty"`
	Unverified       []string         `json:"unverified,omitempty"`
	Outcomes         []PathOutcome    `json:"outcomes"`
}

func TestExecutionProofWithheldIsBoundAndOlderVerifierRejects(t *testing.T) {
	proof := NewExecutionProof(
		EnforcementRecord{State: EnforcementEnforced, Mechanism: "landlock", Coverage: CoverageFull, Withheld: []string{ReferWithheldReason}},
		ExecControlOptions{PolicyHash: "policy", Workspace: "/w", TempDir: "/t", Binary: "/bin/true"}, []string{"/bin/true"},
	)
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	// A round trip through one struct cannot catch a renamed JSON tag.
	if !bytes.Contains(encoded, []byte(`"withheld":`)) {
		t.Fatalf("encoded proof lacks the withheld key: %s", encoded)
	}
	var decoded ExecutionProof
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Verify("policy"); err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if !slices.Equal(decoded.Record.Withheld, []string{ReferWithheldReason}) {
		t.Fatal("proof lost withheld caveat")
	}

	for _, change := range []string{"remove", "alter"} {
		t.Run(change, func(t *testing.T) {
			tampered := decoded
			tampered.Record.Withheld = nil
			if change == "alter" {
				tampered.Record.Withheld = []string{"different caveat"}
			}
			if err := tampered.Verify("policy"); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
				t.Fatalf("tampered withheld accepted: %v", err)
			}
		})
	}
	// Decode the whole proof into the frozen old material schema. Unknown
	// fields are ignored exactly as by the old encoding/json consumer.
	legacyHashOf := func(encoded []byte) string {
		t.Helper()
		var legacy struct {
			Record           recordBeforeWithheld `json:"record"`
			ConfigPolicyHash string               `json:"config_policy_hash"`
			Profile          string               `json:"profile,omitempty"`
			Workspace        string               `json:"workspace"`
			TempDir          string               `json:"temp_dir"`
			Binary           string               `json:"binary"`
			Command          []string             `json:"command"`
		}
		if err := json.Unmarshal(encoded, &legacy); err != nil {
			t.Fatal(err)
		}
		material, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%x", sha256.Sum256(material))
	}
	// Control: the frozen schema must reproduce the hash of a proof without
	// Withheld, or the mismatch below could come from a wrong legacy model.
	control := proof
	control.Record.Withheld = nil
	control = NewExecutionProof(control.Record,
		ExecControlOptions{PolicyHash: "policy", Workspace: "/w", TempDir: "/t", Binary: "/bin/true"}, []string{"/bin/true"})
	controlEncoded, err := json.Marshal(control)
	if err != nil {
		t.Fatal(err)
	}
	if got := legacyHashOf(controlEncoded); got != control.EffectivePolicyHash {
		t.Fatalf("frozen schema does not model the older verifier: got %s, want %s", got, control.EffectivePolicyHash)
	}
	legacyHash := legacyHashOf(encoded)
	if legacyHash == decoded.EffectivePolicyHash {
		t.Fatal("older verifier silently accepted a withheld proof")
	}
	t.Logf("older verifier recomputes %s, rejects new hash %s", legacyHash, decoded.EffectivePolicyHash)
}
