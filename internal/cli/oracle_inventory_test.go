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
	"github.com/luckyPipewrench/pipelock/internal/testwait"
	"github.com/spf13/cobra"
)

func TestReceiptCommandTreeOracle(t *testing.T) {
	root := cli.ExportRootCmd()
	testreceipt.RunReceiptCommandOracle(t, root, func(args []string, out io.Writer) int {
		return executeReceiptProbe(t, args, out, 5*time.Second)
	}, receiptCommandProbes(t, root), oraclePathExclusions)
}

func receiptCommandProbes(t *testing.T, root *cobra.Command) map[string][]testreceipt.ReceiptProbe {
	t.Helper()
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
		"contain explain":                        {probe("example", "--events", "$file"), probe("", "--events", "$file")},
		"doctor":                                 {dir("--config", "$config", "--no-color")},
		"evidence compact":                       {sessionDir},
		"evidence doctor":                        {dir("$dir")},
		"evidence expire":                        {receiptDir, dir("--config", "$config")},
		"evidence inspect-epochs":                {dir("--receipt-dir", "$dir", "--session", "proxy", "--key", "$pub", "--out", "$tmp/pin.json")},
		"evidence inventory-legacy-epochs":       {dir("--receipt-dir", "$dir", "--session", "proxy", "--out", "$tmp/inventory.json")},
		"evidence repair-group-transition":       {dir("--dir", "$dir", "--group", strings.Repeat("a", 32), "--key-file", "$keyfile")},
		"evidence serve":                         {dir("--receipt-dir", "$dir", "--listen", "127.0.0.1:0")},
		"evidence verify-epoch-pin":              {dir("--receipt-dir", "$dir", "--session", "proxy", "--key", "$pub", "--pin", "$tmp/pin.json", "--pin-sha256", digest)},
		"evidence verify-legacy-epoch-inventory": {dir("--receipt-dir", "$dir", "--session", "proxy", "--inventory", "$tmp/inventory.json", "--sha256", digest)},
		"evidence view":                          {dir("--receipt-dir", "$dir", "--out", "$tmp/report.html")},
		"explain event":                          {probe("example", "--log", "$file"), probe("example", "--config", "$config")},
		"learn compile":                          {probe("--agent", "example", "--input", "$file", "--output", "$tmp/contract.yaml"), probe("--agent", "example", "--config", "$config", "--output", "$tmp/contract.yaml")},
		"learn forget":                           {dir("--candidate", "$tmp/contract.yaml", "--rule-id", "example", "--reason", "example", "--receipt-out", "$dir/legacy.jsonl")},
		"learn promote":                          {dir("--contract-store", "$dir", "--contract", digest, "--selector", "default", "--roster", "$tmp/roster.json", "--roster-root-fingerprint", digest, "--activation-key", "example")},
		"learn ratify":                           {dir("--candidate", "$tmp/contract.yaml", "--receipt-out", "$dir/legacy.jsonl")},
		"learn rollback":                         {dir("--contract-store", "$dir", "--to", digest, "--roster", "$tmp/roster.json", "--roster-root-fingerprint", digest, "--activation-key", "example")},
		"learn shadow":                           {dir("--contract", "$tmp/contract.yaml", "--recorder-dir", "$dir"), dir("--contract", "$tmp/contract.yaml", "--sessions", "$dir"), dir("--agent", "example", "--contract", "$tmp/contract.yaml", "--config", "$config")},
		"logs":                                   {probe("--file", "$file")},
		"policy replay":                          {dir("--sessions", "$dir", "--config", "$config")},
		"posture emit":                           {dir("--config", "$config", "--output", "$tmp/posture")},
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
	return plans
}

func executeReceiptProbe(t *testing.T, args []string, out io.Writer, deadline time.Duration) int {
	t.Helper()
	cmd := cli.ExportRootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(out)
	cmd.SetErr(out)
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(deadline))
	defer cancel()
	err := cmd.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	_, _ = fmt.Fprintln(out, err)
	return cliutil.ExitCodeOf(err)
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
	"adaptive":                                "uses the configured adaptive enforcement API",
	"adaptive flush":                          "flushes adaptive enforcement state through the configured API",
	"adaptive status":                         "queries adaptive enforcement state through the configured API",
	"adaptive whoami":                         "queries authentication through the configured API",
	"assess finalize":                         "reads only assessment primitive results in its assessment run layout",
	"assess init":                             "creates an assessment plan at its output path",
	"assess run":                              "loads an assessment plan and writes primitive results",
	"assess status":                           "reads only the assessment manifest",
	"assess verify":                           "checks assessment packet files bound to an assessment manifest",
	"assess verify-attestation":               "verifies an assessment attestation and its named packet files",
	"audit":                                   "scans project source files for secrets",
	"audit capsule":                           "writes a posture proof to the output directory",
	"audit score":                             "scores protection settings from the configuration",
	"baseline":                                "manages behavioral baselines through the configured API",
	"baseline forget":                         "deletes a behavioral baseline through the configured API",
	"baseline list":                           "lists behavioral baselines through the configured API",
	"baseline ratify":                         "ratifies a behavioral baseline through the configured API",
	"baseline show":                           "queries a behavioral baseline through the configured API",
	"check":                                   "checks configuration and signing key prerequisites",
	"claude hook":                             "installs Claude hooks using the configured proxy settings",
	"claude setup":                            "configures Claude proxy integration",
	"cline install":                           "passes the config path into the generated Cline integration",
	"codex install":                           "passes the config path into the generated Codex integration",
	"commitment-key backup":                   "copies only commitment keyring state",
	"commitment-key initialize":               "creates a commitment keyring",
	"commitment-key inspect":                  "inspects only commitment keyring metadata",
	"commitment-key restore":                  "restores only commitment keyring state",
	"commitment-key retire":                   "retires a commitment key",
	"commitment-key rotate":                   "rotates a commitment key",
	"commitment-key test":                     "tests access to the commitment keyring",
	"conductor audit-queue-key init":          "initializes the queue key in the Conductor store",
	"conductor audit-queue-key inspect":       "inspects Conductor queue key metadata",
	"conductor audit-queue-key migrate":       "migrates only Conductor queue encryption keys",
	"conductor audit-queue-key recover":       "recovers Conductor queue key state",
	"conductor audit-queue-key revoke":        "revokes a Conductor queue key by ID",
	"conductor audit-queue-key rotate":        "rotates a Conductor queue key",
	"conductor bootstrap":                     "writes development fleet configuration to the output directory",
	"conductor fleet report":                  "the path is a Conductor SQLite store; signed stored payloads are covered by fleet report tests",
	"conductor publish":                       "publishes the config YAML as bundle policy",
	"conductor replay":                        "replays Conductor decision artifacts and state snapshots",
	"conductor serve":                         "opens the configured Conductor service store",
	"conductor store backup":                  "copies a Conductor SQLite store",
	"conductor store inspect-offline":         "inspects Conductor store metadata",
	"conductor store repair":                  "repairs Conductor database storage",
	"conductor store restore":                 "restores a Conductor database backup",
	"contain audit-workspace":                 "inspects a workspace tree",
	"contain grant-workspace":                 "binds a workspace directory",
	"contain install":                         "copies configuration for the managed service",
	"contain revoke-workspace":                "removes a workspace directory grant",
	"contain run":                             "needs root and contained identities; its signed posture capsule counts flight recorder receipts through posture.Emit, whose v3 refusal is covered by TestCollectFlightRecorderEvidenceRefusesReceiptProfile",
	"contain service-posture":                 "loads configuration for containment posture output",
	"continue install":                        "writes Continue extension configuration",
	"continue remove":                         "removes Continue extension configuration",
	"cursor hook":                             "installs Cursor hooks using the configured proxy settings",
	"cursor install":                          "configures Cursor proxy integration",
	"dashboard backup":                        "archives dashboard state files",
	"dashboard restore":                       "restores a dashboard state tar archive",
	"demo":                                    "receipts-dir is a receipt output destination",
	"diagnose":                                "checks deployment and configuration settings",
	"discover":                                "looks for configured integrations or deployment assets",
	"exec":                                    "uses listener and CA settings to launch a child",
	"explain":                                 "explains scanner decisions for URL, tool, command, or file-write input",
	"explain mcp-response":                    "scans an MCP response supplied on stdin",
	"explain response":                        "scans an HTTP response supplied on stdin",
	"fleet-sink":                              "opens a fleet SQLite store; ingestion payload refusal has its own tests",
	"generate mcporter":                       "reads an MCP server configuration",
	"git install-hooks":                       "writes Git hook configuration",
	"git scan-diff":                           "loads scanner settings and scans a Git diff",
	"guard":                                   "loads guard policy and writes receipts for the child",
	"guard explain":                           "classifies a filesystem path against guard policy",
	"guard show":                              "displays a configured guard profile",
	"hermes hook":                             "loads scanner and proxy settings for the hook",
	"integrity check":                         "hashes project files against an integrity manifest",
	"integrity init":                          "creates a project integrity manifest",
	"integrity update":                        "updates a project integrity manifest",
	"jetbrains install":                       "passes the config path into the generated JetBrains integration",
	"keys status":                             "displays configured key metadata",
	"learn diff":                              "compares two derived shadow report JSON files",
	"learn observe":                           "capture-dir is an output destination for a running proxy",
	"learn review":                            "renders a candidate contract YAML file",
	"license crl inspect":                     "inspects a license revocation list file",
	"license crl reset-highwater":             "operates on license revocation high-water state",
	"license crl verify":                      "verifies a license revocation list file",
	"license status":                          "checks the configured license and revocation settings",
	"mcp identity inspect":                    "inspects configured MCP identity metadata",
	"mcp integrity manifest generate":         "creates an MCP binary integrity manifest",
	"mcp integrity manifest sign":             "signs an MCP binary integrity manifest",
	"mcp integrity manifest verify":           "checks an MCP executable and arguments against a manifest",
	"mcp integrity manifest verify-signature": "checks an MCP binary integrity manifest signature",
	"mcp proxy":                               "capture-output is an output destination for the proxy",
	"mcp scan":                                "uses scanner settings to scan MCP input",
	"opencode install":                        "passes the config path into the generated OpenCode integration",
	"pi install":                              "uses the named listener from the config for Pi integration",
	"policy capture":                          "writes new replay observations",
	"posture verify":                          "verifies a posture artifact and compares the local config hash",
	"preflight":                               "scans a project directory before deployment",
	"reload":                                  "requests proxy configuration reload",
	"rules diff":                              "diffs a rules bundle",
	"rules install":                           "installs a rules bundle",
	"rules list":                              "lists rules bundles",
	"rules remove":                            "removes a rules bundle",
	"rules reset-freshness":                   "operates on rules freshness state",
	"rules status":                            "reports configured rules bundle state",
	"rules update":                            "updates a rules bundle",
	"rules verify":                            "verifies a rules bundle",
	"run":                                     "capture-output is an output destination for the server",
	"sandbox":                                 "uses configuration to launch the sandboxed command",
	"scan":                                    "scans arbitrary source bytes for secrets",
	"session":                                 "uses the configured live session API",
	"session deferred":                        "uses the configured live deferred-action API",
	"session deferred approve":                "approves a deferred action through the configured API",
	"session deferred deny":                   "denies a deferred action through the configured API",
	"session deferred list":                   "lists deferred actions through the configured API",
	"session explain":                         "queries a live session through the configured API",
	"session inspect":                         "inspects a live session through the configured API",
	"session list":                            "lists live sessions through the configured API",
	"session recover":                         "recovers a session through the configured API",
	"session release":                         "releases a session through the configured API",
	"session reset":                           "resets a session through the configured API",
	"session risk":                            "queries session risk through the configured API",
	"session terminate":                       "terminates a session through the configured API",
	"sign":                                    "creates a detached signature over arbitrary file bytes",
	"signing pubkey":                          "reads the configured signing key to derive its public key",
	"signing reset inspect":                   "inspects a reset delegation document",
	"signing reset revoke":                    "removes a reset delegation document",
	"simulate":                                "evaluates configured policy against sample actions",
	"skill-scan":                              "scans instruction files or directories",
	"status":                                  "queries the configured proxy API for runtime status",
	"support bundle":                          "includes sanitized configuration and support diagnostics",
	"test":                                    "evaluates scanner behavior using the supplied config",
	"trust":                                   "imports a public key file",
	"verify":                                  "verifies a detached signature over arbitrary file bytes",
	"verify-install":                          "checks deployment prerequisites and emits a posture report",
	"vscode install":                          "passes the config path into the generated VS Code integration",
	"zed install":                             "passes the config path into the generated Zed integration",
}
