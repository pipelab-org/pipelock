// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"fmt"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/evidence/receiptinput"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func repairGroupTransitionCmd() *cobra.Command {
	var dir, groupID, keyFile string
	var priorKeys []string
	cmd := &cobra.Command{
		Use:   "repair-group-transition",
		Short: "Complete a missing transition for a stopped receipt group",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := receiptinput.Refuse(dir, "evidence repair-group-transition", "the legacy evidence reader"); err != nil {
				return err
			}
			key, err := signing.LoadPrivateKeyFileForPurpose(keyFile, signing.PurposeReceiptSigning)
			if err != nil {
				return fmt.Errorf("load opening key: %w", err)
			}
			hash, err := receipt.RepairReceiptGroupTransitionWithGuard(
				filepath.Clean(dir), groupID, key, priorKeys,
				verification.Options{Context: cmd.Context()},
				func(lockedDir string) error {
					return receiptinput.Refuse(lockedDir, "evidence repair-group-transition", "the legacy evidence reader")
				},
			)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Published receipt group transition %s\n", hash)
			return err
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "stopped evidence directory")
	cmd.Flags().StringVar(&groupID, "group", "", "successor group ID from the startup error")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "private key used to sign the successor opening")
	cmd.Flags().StringArrayVar(&priorKeys, "prior-signer", nil, "pinned past receipt signer in hex (repeatable)")
	for _, flag := range []string{"dir", "group", "key-file"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	return cmd
}
