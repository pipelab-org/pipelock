// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestReceiptCommandTreeOracle(t *testing.T) {
	root := cli.ExportRootCmd()
	dir := func(args ...string) testreceipt.ReceiptProbe {
		return testreceipt.ReceiptProbe{Args: args, Directory: true}
	}
	probe := func(args ...string) testreceipt.ReceiptProbe {
		return testreceipt.ReceiptProbe{Args: args}
	}
	receiptDir := dir("--receipt-dir", "$dir")
	sessionDir := dir("--receipt-dir", "$dir", "--session", "proxy", "--key", "$pub")
	chain := dir("--chain", "$dir", "--key", "$pub")
	file := probe("$file", "--key", "$pub")
	digest := strings.Repeat("0", 64)
	plans := map[string][]testreceipt.ReceiptProbe{
		"anchor receipts":                        {file, dir("$dir", "--dir", "--key", "$pub")},
		"doctor":                                 {{Args: []string{"--config", "$config", "--no-color"}, Directory: true, Doctor: true}},
		"evidence compact":                       {sessionDir},
		"evidence doctor":                        {dir("$dir")},
		"evidence expire":                        {receiptDir},
		"evidence inspect-epochs":                {dir("--receipt-dir", "$dir", "--session", "proxy", "--key", "$pub", "--out", "$tmp/pin.json")},
		"evidence inventory-legacy-epochs":       {dir("--receipt-dir", "$dir", "--session", "proxy", "--out", "$tmp/inventory.json")},
		"evidence repair-group-transition":       {dir("--dir", "$dir", "--group", strings.Repeat("a", 32), "--key-file", "$keyfile")},
		"evidence serve":                         {dir("--receipt-dir", "$dir", "--listen", "127.0.0.1:0")},
		"evidence verify-epoch-pin":              {dir("--receipt-dir", "$dir", "--session", "proxy", "--key", "$pub", "--pin", "$tmp/pin.json", "--pin-sha256", digest)},
		"evidence verify-legacy-epoch-inventory": {dir("--receipt-dir", "$dir", "--session", "proxy", "--inventory", "$tmp/inventory.json", "--sha256", digest)},
		"evidence view":                          {dir("--receipt-dir", "$dir", "--out", "$tmp/report.html")},
		"explain event":                          {probe("example", "--log", "$file")},
		"learn compile":                          {probe("--agent", "example", "--input", "$file", "--output", "$tmp/contract.yaml")},
		"learn forget":                           {dir("--candidate", "$tmp/contract.yaml", "--rule-id", "example", "--reason", "example", "--receipt-out", "$dir/legacy.jsonl")},
		"learn promote":                          {dir("--contract-store", "$dir", "--contract", digest, "--selector", "default", "--roster", "$tmp/roster.json", "--roster-root-fingerprint", digest, "--activation-key", "example")},
		"learn ratify":                           {dir("--candidate", "$tmp/contract.yaml", "--receipt-out", "$dir/legacy.jsonl")},
		"learn rollback":                         {dir("--contract-store", "$dir", "--to", digest, "--roster", "$tmp/roster.json", "--roster-root-fingerprint", digest, "--activation-key", "example")},
		"learn shadow":                           {dir("--contract", "$tmp/contract.yaml", "--recorder-dir", "$dir"), dir("--contract", "$tmp/contract.yaml", "--sessions", "$dir")},
		"logs":                                   {probe("--file", "$file")},
		"policy replay":                          {dir("--sessions", "$dir", "--config", "$config")},
		"report":                                 {probe("--input", "$file")},
		"signing receipt-rotation endorse":       {dir("--chain", "$dir", "--session", "proxy", "--prior-key-file", "$keyfile", "--new-key-file", "$keyfile", "--root-key", "$pub", "--out", "$tmp/endorsement.json")},
		"transcript-root":                        {file, chain},
		"verify-receipt":                         {file, chain},
	}
	if cmd, _, err := root.Find([]string{"dashboard", "serve"}); err == nil && cmd.Name() == "serve" {
		tokenPath := prepareOracleDashboard(t)
		plans["dashboard coverage-cert generate"] = []testreceipt.ReceiptProbe{
			dir("--receipt-dir", "$dir", "--agent", "example", "--signing-key", "$keyfile", "--window-start", "2026-01-01T00:00:00Z", "--window-end", "2026-01-02T00:00:00Z", "--out", "$tmp/cert.json"),
		}
		plans["dashboard rebuild-read-model"] = []testreceipt.ReceiptProbe{dir("--receipt-dir", "$dir", "--output", "$tmp/index.json")}
		plans["dashboard serve"] = []testreceipt.ReceiptProbe{dir("--receipt-dir", "$dir", "--listen", "127.0.0.1:0", "--auth-token-file", tokenPath)}
	}
	testreceipt.RunReceiptCommandOracle(t, root, func(args []string, out io.Writer) int {
		cmd := cli.ExportRootCmd()
		cmd.SetArgs(args)
		cmd.SetOut(out)
		cmd.SetErr(out)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		err := cmd.ExecuteContext(ctx)
		if err == nil {
			return 0
		}
		_, _ = fmt.Fprintln(out, err)
		return cliutil.ExitCodeOf(err)
	}, plans, oraclePathExclusions)
}

func prepareOracleDashboard(t *testing.T) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, err := license.Issue(license.License{
		ID: "lic_receipt_oracle", Email: "reader@example.com",
		Features: []string{license.FeatureAgents}, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(license.EnvLicenseKey, token)
	t.Setenv(license.EnvLicensePublicKey, hex.EncodeToString(pub))
	t.Setenv(license.EnvLicenseCRLFile, "")
	t.Setenv(license.EnvLicenseIntermediateFile, "")
	tokenPath := filepath.Join(t.TempDir(), "dashboard-auth")
	if err := os.WriteFile(tokenPath, []byte(hex.EncodeToString(pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	return tokenPath
}

var oraclePathExclusions = map[string]string{
	"assess finalize":                         "reads only assessment primitive results in its assessment run layout",
	"assess init":                             "creates an assessment plan at its output path",
	"assess run":                              "loads an assessment plan and writes primitive results",
	"assess status":                           "reads only the assessment manifest",
	"assess verify":                           "checks assessment packet files bound to an assessment manifest",
	"assess verify-attestation":               "verifies an assessment attestation and its named packet files",
	"audit":                                   "scans project source files for secrets",
	"audit capsule":                           "writes a posture proof to the output directory",
	"conductor audit-queue-key init":          "initializes the queue key in the Conductor store",
	"conductor audit-queue-key inspect":       "inspects Conductor queue key metadata",
	"conductor audit-queue-key migrate":       "migrates only Conductor queue encryption keys",
	"conductor audit-queue-key recover":       "recovers Conductor queue key state",
	"conductor audit-queue-key revoke":        "revokes a Conductor queue key by ID",
	"conductor audit-queue-key rotate":        "rotates a Conductor queue key",
	"conductor bootstrap":                     "writes development fleet configuration to the output directory",
	"conductor fleet report":                  "the path is a Conductor SQLite store; signed stored payloads are covered by fleet report tests",
	"conductor serve":                         "opens the configured Conductor service store",
	"conductor store backup":                  "copies a Conductor SQLite store",
	"conductor store inspect-offline":         "inspects Conductor store metadata",
	"conductor store repair":                  "repairs Conductor database storage",
	"conductor store restore":                 "restores a Conductor database backup",
	"contain audit-workspace":                 "inspects a workspace tree",
	"contain grant-workspace":                 "binds a workspace directory",
	"contain revoke-workspace":                "removes a workspace directory grant",
	"continue install":                        "writes Continue extension configuration",
	"continue remove":                         "removes Continue extension configuration",
	"dashboard backup":                        "archives dashboard state files",
	"dashboard restore":                       "restores a dashboard state tar archive",
	"demo":                                    "receipts-dir is a receipt output destination",
	"discover":                                "looks for configured integrations or deployment assets",
	"explain":                                 "explains scanner decisions for URL, tool, command, or file-write input",
	"fleet-sink":                              "opens a fleet SQLite store; ingestion payload refusal has its own tests",
	"generate mcporter":                       "reads an MCP server configuration",
	"guard explain":                           "classifies a filesystem path against guard policy",
	"integrity check":                         "hashes project files against an integrity manifest",
	"integrity init":                          "creates a project integrity manifest",
	"integrity update":                        "updates a project integrity manifest",
	"learn diff":                              "compares two derived shadow report JSON files",
	"learn observe":                           "capture-dir is an output destination for a running proxy",
	"learn review":                            "renders a candidate contract YAML file",
	"license crl inspect":                     "inspects a license revocation list file",
	"license crl reset-highwater":             "operates on license revocation high-water state",
	"license crl verify":                      "verifies a license revocation list file",
	"mcp integrity manifest generate":         "creates an MCP binary integrity manifest",
	"mcp integrity manifest sign":             "signs an MCP binary integrity manifest",
	"mcp integrity manifest verify":           "checks an MCP executable and arguments against a manifest",
	"mcp integrity manifest verify-signature": "checks an MCP binary integrity manifest signature",
	"mcp proxy":                               "capture-output is an output destination for the proxy",
	"preflight":                               "scans a project directory before deployment",
	"rules diff":                              "diffs a rules bundle",
	"rules install":                           "installs a rules bundle",
	"rules list":                              "lists rules bundles",
	"rules remove":                            "removes a rules bundle",
	"rules reset-freshness":                   "operates on rules freshness state",
	"rules update":                            "updates a rules bundle",
	"rules verify":                            "verifies a rules bundle",
	"run":                                     "capture-output is an output destination for the server",
	"scan":                                    "scans arbitrary source bytes for secrets",
	"sign":                                    "creates a detached signature over arbitrary file bytes",
	"signing reset inspect":                   "inspects a reset delegation document",
	"signing reset revoke":                    "removes a reset delegation document",
	"skill-scan":                              "scans instruction files or directories",
	"trust":                                   "imports a public key file",
	"verify":                                  "verifies a detached signature over arbitrary file bytes",
}
