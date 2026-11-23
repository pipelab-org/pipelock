// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"

	"github.com/spf13/cobra"
)

const (
	defaultControlAuditDir = "/var/lib/pipelock-contain"
	controlAuditExitCodes  = `Exit codes:
  0  Clean, or all findings are allowed by the supplied flags.
  1  Integrity, I/O, or usage error.
  2  Unaccepted changes, unaccepted partial discovery, incomplete observation,
     or missing baseline.`
)

type controlAuditOptions struct {
	workspace    string
	agentUser    string
	record       bool
	replace      bool
	json         bool
	allowChanges bool
	allowPartial bool
}

func auditWorkspaceCmd() *cobra.Command {
	var opts controlAuditOptions
	cmd := &cobra.Command{
		Use:   "audit-workspace [--workspace PATH | --agent-user USER]",
		Short: "Record or audit a workspace control surface on Linux",
		Long: `Compare workspace control paths against a host-local baseline. Run with sudo.
Use --record to create a baseline and --record --replace to review and accept
the observed differences. Baselines are unsigned.

` + controlAuditExitCodes,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 0 {
				return errors.New("unexpected positional arguments; run pipelock contain audit-workspace --help")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch {
			case (opts.workspace == "") == (opts.agentUser == ""):
				return errors.New("select exactly one of --workspace PATH or --agent-user USER; run pipelock contain audit-workspace --help")
			case opts.record && (opts.json || opts.allowChanges || opts.allowPartial):
				return errors.New("audit flags require audit mode; run pipelock contain audit-workspace --help")
			case opts.replace && !opts.record:
				return errors.New("--replace requires --record; run pipelock contain audit-workspace --help")
			default:
				return runControlAudit(cmd.OutOrStdout(), opts)
			}
		},
	}
	cmd.Flags().StringVar(&opts.workspace, "workspace", "", "workspace path")
	cmd.Flags().StringVar(&opts.agentUser, "agent-user", "", "audit or record every workspace grant for this user, including expired grants")
	cmd.Flags().BoolVar(&opts.record, "record", false, "record the current workspace control surface")
	cmd.Flags().BoolVar(&opts.replace, "replace", false, "print the observed differences and replace the existing baseline")
	cmd.Flags().BoolVar(&opts.json, "json", false, "emit JSON audit results")
	cmd.Flags().BoolVar(&opts.allowChanges, "allow-control-surface-changes", false, "accept observed control path changes for this audit")
	cmd.Flags().BoolVar(&opts.allowPartial, "allow-partial-nested-discovery", false, "accept partial nested discovery for this audit")
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return errors.Join(err, errors.New("run pipelock contain audit-workspace --help"))
	})
	return cmd
}
