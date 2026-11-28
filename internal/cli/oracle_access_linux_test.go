// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"io"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli"
	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestObservedV3Access(t *testing.T) {
	root := cli.ExportRootCmd()
	_, _, enterpriseErr := root.Find([]string{"dashboard", "serve"})
	binary := testreceipt.BuildAccessBinary(t, "pipelock", enterpriseErr == nil)
	testreceipt.RunObservedAccessOracle(t, testreceipt.AccessOracle{
		Root:     root,
		MustOpen: []string{"posture emit", "verify-receipt", "mcp proxy", "run", "learn observe"},
		Runtimes: []string{"mcp proxy", "run", "learn observe"},
		Probes:   receiptCommandProbes(t, root),
		Inputs: map[string][]string{
			"init":           {"--output", "$config", "--scan-home", "$tmp", "--skip-canary", "--skip-validate"},
			"run":            {"--capture-output", "$tmp/capture", "--capture-duration", "100ms"},
			"mcp proxy":      {"--", "/bin/true"},
			"policy capture": {"--output", "$tmp/capture", "--duration", "100ms"},
			"exec":           {"--dry-run", "--", "/bin/true"},
			"guard":          {"--dry-run", "--", "/bin/true"},
			"sandbox":        {"--dry-run", "--", "/bin/true"},
		},
		Exclusions: observedAccessExclusions,
		Invoke: func(t *testing.T, args []string, out io.Writer, dir string, existingProbe bool) int {
			t.Helper()
			if len(args) >= 2 && args[0] == "learn" && args[1] == "observe" {
				return executeReceiptProbe(t, args, out, time.Second)
			}
			if existingProbe {
				return executeReceiptProbe(t, args, out, 5*time.Second)
			}
			return testreceipt.ExecuteAccessBinary(t, binary, args, out, dir)
		},
	})
}

var observedAccessExclusions = map[string]testreceipt.AccessOracleExclusion{
	"contain add-tool":         {Reason: "writes managed system tool configuration", Package: "internal/cli/contain", Test: "TestAddTool_RecordsTargetInToolsList"},
	"contain ca-refresh":       {Reason: "refreshes the managed system CA", Package: "internal/cli/contain", Test: "TestRunCARefresh_UsesContainManagedTLSCA"},
	"contain grant-workspace":  {Reason: "requires a managed mount namespace", Package: "internal/cli/contain", Test: "TestRunGrantWorkspace_RecordsMetadata"},
	"contain install":          {Reason: "installs system configuration and services", Package: "internal/cli/contain", Test: "TestRunInstall_ConfigPreflightRefusesBeforeServiceMutation"},
	"contain netns-forward":    {Reason: "requires a managed namespace listener", Package: "internal/cli/contain", Test: "TestNetnsForwardReportsReadyAfterBind"},
	"contain reload-nft-rules": {Reason: "replaces host nftables rules", Package: "internal/cli/contain", Test: "TestReloadNFTRulesReconcilesBeforeLoading"},
	"contain revoke-workspace": {Reason: "requires a managed mount namespace", Package: "internal/cli/contain", Test: "TestRunRevokeWorkspaceExecutesCommandsAndUpdatesInventory"},
	"contain rollback":         {Reason: "removes host containment installation", Package: "internal/cli/contain", Test: "TestRollback_RemovesToolsList"},
	"contain run":              {Reason: "needs root and managed identities before it calls posture.Emit", Package: "internal/posture", Test: "TestCollectFlightRecorderEvidenceRefusesReceiptProfile"},
	"contain upgrade":          {Reason: "replaces the installed binary and restarts host services", Package: "internal/cli/contain", Test: "TestUpgrade_UnsafeManagedConfigRefusesBeforeMutation"},
	"update":                   {Reason: "downloads a release and replaces the CLI", Package: "internal/cli/selfupdate", Test: "TestRunCommand_YesUpdateJSON"},
	"verify-install":           {Reason: "performs live installation network checks", Package: "internal/cli/diag", Test: "TestVerifyInstallCmd_AllPass"},
}
