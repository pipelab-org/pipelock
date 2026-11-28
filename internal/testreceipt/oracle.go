// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package testreceipt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var pathOperand = regexp.MustCompile(`(?i)(?:^|[ <\[|_-])(?:path|paths|file|files|[^ ]*dir(?:ectory)?|[^ ]+\.(?:jsonl?|ya?ml|tar|zip))(?:[ .>\]|]|$)`)

// VisitPathCommands discovers commands with a path-shaped operand or an
// evidence-shaped flag. The test must account for every candidate.
func VisitPathCommands(root *cobra.Command, visit func(*cobra.Command)) {
	for _, child := range root.Commands() {
		VisitPathCommands(child, visit)
	}
	if !root.Runnable() || root.Parent() == nil {
		return
	}
	_, operands, _ := strings.Cut(root.Use, " ")
	candidate := pathOperand.MatchString(operands)
	// Cobra merges parent persistent flags lazily.
	root.InheritedFlags()
	root.Flags().VisitAll(func(flag *pflag.Flag) {
		switch flag.Name {
		case "chain", "dir", "location", "input", "file", "receipt-out", "sessions", "log", "events", "config":
			candidate = true
		default:
			name := strings.ToLower(flag.Name)
			usage := strings.ToLower(flag.Usage)
			candidate = candidate || ((strings.Contains(name, "receipt") || strings.Contains(name, "evidence") ||
				strings.Contains(name, "recorder") || strings.Contains(name, "capture") ||
				strings.HasSuffix(name, "-dir")) && (strings.Contains(usage, "path") ||
				strings.Contains(usage, "file") || strings.Contains(usage, "directory")))
		}
	})
	if candidate {
		visit(root)
	}
}

// ReceiptProbe describes how to reach a candidate's evidence reader. Args
// start after the Cobra command name. Directory enables explicit-location
// tests for commands that support --location.
type ReceiptProbe struct {
	Args      []string
	Directory bool
}

// RunReceiptCommandOracle exercises the current command tree with writer
// fixtures. A new path-taking command has to provide a probe or an exclusion.
func RunReceiptCommandOracle(t *testing.T, root *cobra.Command, run func([]string, io.Writer) int, plans map[string][]ReceiptProbe, exclusions map[string]string) {
	t.Helper()
	fixtures := oracleFixtures(t)
	seen := make(map[string]bool)
	var tested, excluded, cases int
	VisitPathCommands(root, func(cmd *cobra.Command) {
		name := strings.TrimPrefix(cmd.CommandPath(), root.Name()+" ")
		seen[name] = true
		if reason := exclusions[name]; reason != "" {
			if _, planned := plans[name]; planned {
				t.Errorf("%s has both a probe and an exclusion", name)
			}
			t.Logf("excluded %s: %s", name, reason)
			excluded++
			return
		}
		probes := plans[name]
		if len(probes) == 0 {
			t.Errorf("classify path-taking command %s (%s)", name, cmd.Use)
			return
		}
		tested++
		for i, probe := range probes {
			for _, fixture := range fixtures {
				t.Run(fmt.Sprintf("%s/%d/%s", name, i, fixture.name), func(t *testing.T) {
					runReceiptProbe(t, run, name, probe, fixture, "")
				})
				cases++
				if probe.Directory && fixture.name == "nested" && cmd.Flags().Lookup("location") != nil {
					t.Run(fmt.Sprintf("%s/%d/explicit_location", name, i), func(t *testing.T) {
						runReceiptProbe(t, run, name, probe, fixture, "child")
					})
					cases++
				}
			}
		}
	})
	for name := range plans {
		if !seen[name] {
			t.Errorf("stale receipt oracle probe for %s", name)
		}
	}
	t.Logf("%s: %d commands tested in %d invocations; %d exclusions", root.Name(), tested, cases, excluded)
}

type oracleFixture struct {
	name, dir, file, key, keyFile string
}

func oracleFixtures(t *testing.T) []oracleFixture {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "signer.key")
	if err := signing.SavePrivateKey(v3FixtureKey(), keyFile); err != nil {
		t.Fatal(err)
	}
	captureSession := func() string {
		dir := filepath.Join(t.TempDir(), "example")
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	signed, damaged, renamed, nested, mixed := captureSession(), captureSession(), captureSession(), captureSession(), captureSession()
	signedFile, public := V3(t, signed, false)
	damagedFile, _ := V3(t, damaged, true)
	raw := oracleReadFile(t, signedFile)
	renamedFile := filepath.Join(renamed, "evidence-proxy-0.jsonl")
	oracleWriteFile(t, renamedFile, append([]byte("\n  "), raw...))
	child := filepath.Join(nested, "child")
	if err := os.Mkdir(child, 0o750); err != nil {
		t.Fatal(err)
	}
	nestedFile := filepath.Join(child, filepath.Base(signedFile))
	oracleWriteFile(t, nestedFile, raw)
	mixedFile := filepath.Join(mixed, filepath.Base(signedFile))
	legacy := oracleLegacyChain(t)
	oracleWriteFile(t, filepath.Join(nested, "evidence-proxy-0.jsonl"), legacy)
	oracleWriteFile(t, filepath.Join(mixed, "evidence-proxy-0.jsonl"), legacy)
	oracleWriteFile(t, mixedFile, raw)
	key := hex.EncodeToString(public)
	return []oracleFixture{
		{"signed", signed, signedFile, key, keyFile},
		{"damaged", damaged, damagedFile, key, keyFile},
		{"renamed", renamed, renamedFile, key, keyFile},
		{"nested", nested, nestedFile, key, keyFile},
		{"mixed", mixed, mixedFile, key, keyFile},
	}
}

func oracleLegacyChain(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	key := v3FixtureKey()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	emitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: "example", Principal: "example", Actor: "example"})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if err := emitter.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: "allow", Transport: "fetch", Method: "GET", Target: "https://example.com/"}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	return oracleReadFile(t, filepath.Join(dir, "evidence-proxy-0.jsonl"))
}

func runReceiptProbe(t *testing.T, run func([]string, io.Writer) int, name string, probe ReceiptProbe, fixture oracleFixture, location string) {
	t.Helper()
	side := t.TempDir()
	configPath := filepath.Join(side, "pipelock.yaml")
	config := "{}\n"
	if slices.Contains(probe.Args, "$config") {
		config = fmt.Sprintf("flight_recorder:\n  enabled: true\n  dir: %q\n  signing_key_path: %q\nlearn:\n  capture_dir: %q\nlogging:\n  output: file\n  file: %q\n",
			fixture.dir, fixture.keyFile, filepath.Dir(fixture.dir), fixture.file)
	}
	oracleWriteFile(t, configPath, []byte(config))
	replace := strings.NewReplacer("$dir", fixture.dir, "$file", fixture.file, "$pub", fixture.key,
		"$keyfile", fixture.keyFile, "$config", configPath, "$tmp", side)
	args := strings.Fields(name)
	for _, arg := range probe.Args {
		args = append(args, replace.Replace(arg))
	}
	if location != "" {
		args = append(args, "--location", location)
	}
	var out bytes.Buffer
	code := run(args, &out)
	var result struct {
		Kind     string `json:"kind"`
		Verdict  string `json:"verdict"`
		ExitCode *int   `json:"exit_code"`
	}
	// The verifier prints its diagnostic after its report on failures.
	if line, _, _ := strings.Cut(out.String(), "\n"); json.Unmarshal([]byte(line), &result) == nil && result.Kind == "verify_result" {
		if err := receiptProbeResultError(code, result.ExitCode, result.Verdict, fixture.name, probe.Directory, location); err != nil {
			t.Fatal(err)
		}
		return
	}
	if code == 0 || !strings.Contains(out.String(), "pipelock verify-receipt") {
		t.Fatalf("exit %d without a receipt-profile verdict or refusal: %s", code, oracleDiagnostic(out.String()))
	}
	// Keep the existing command-specific refusal through the generic reader
	// guard, so users see which operation was refused.
	if name == "transcript-root" && !strings.Contains(out.String(), "by transcript root in this release") {
		t.Fatal("transcript-root did not identify the refused operation")
	}
}

func receiptProbeResultError(code int, reportCode *int, verdict, fixture string, directory bool, location string) error {
	if reportCode == nil || code != *reportCode || verdict == "" {
		return fmt.Errorf("v3 verdict %q does not explain exit %d", verdict, code)
	}
	if code == 0 && verdict != "VALID" {
		return fmt.Errorf("successful v3 verification has verdict %q", verdict)
	}
	switch fixture {
	case "signed":
		if verdict != "VALID" || code != 0 {
			return fmt.Errorf("signed fixture verdict = %q, exit %d", verdict, code)
		}
	case "damaged", "renamed":
		if code == 0 {
			return fmt.Errorf("%s fixture incorrectly verified as %q", fixture, verdict)
		}
	case "nested":
		if directory && location == "" && code == 0 {
			return fmt.Errorf("nested directory incorrectly verified as %q", verdict)
		}
	}
	return nil
}

func oracleDiagnostic(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "payloadType") {
			return "command printed receipt bytes"
		}
	}
	return output[:min(len(output), 380)]
}

func oracleReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func oracleWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
