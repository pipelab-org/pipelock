// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/ed25519"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func receiptRecoveryCmd() *cobra.Command {
	var keyInputs []string
	cmd := &cobra.Command{
		Use:   "receipt-recovery DIR",
		Short: "Check whether a stopped v3 receipt history can be resumed",
		Long:  "Check the directory lock and verify a v3 receipt history against pinned keys. An unproven end can pass this check. Incomplete histories require recovery before restart. The writer flushes the predecessor again during startup.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keys := make([]ed25519.PublicKey, 0, len(keyInputs))
			for _, input := range keyInputs {
				key, err := signing.LoadPublicKey(input)
				if err != nil {
					return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("load receipt signer: %w", err))
				}
				keys = append(keys, key)
			}
			result, inspectErr := v3.InspectStartup(cmd.Context(), args[0], keys)
			if result.Kind != "" {
				body, err := result.JSON()
				if err != nil {
					return fmt.Errorf("encode receipt recovery result: %w", err)
				}
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(body)); err != nil {
					return fmt.Errorf("write receipt recovery result: %w", err)
				}
			}
			if inspectErr != nil {
				return cliutil.ExitCodeError(cliutil.ExitGeneral, inspectErr)
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&keyInputs, "key", nil, "pinned receipt signer key or public-key file; repeat for prior signers")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}
