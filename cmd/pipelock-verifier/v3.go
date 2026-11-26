// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func newV3Cmd() *cobra.Command {
	var caller v3.CallerOptions
	var claims bool
	var output string
	cmd := &cobra.Command{
		Use:   "v3 [flags] PATH...",
		Short: "Verify v3 receipt evidence and write canonical JSON",
		RunE: func(cmd *cobra.Command, paths []string) error {
			err := runV3(cmd, paths, caller, claims, output)
			var status *cliutil.ExitError
			if errors.As(err, &status) {
				return status
			}
			return cliutil.ExitCodeError(cliutil.ExitConfig, err)
		},
	}
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	})
	flags := cmd.Flags()
	flags.StringArrayVar(&caller.Keys, "key", nil, "trusted Ed25519 public key in lowercase hex (repeatable)")
	flags.BoolVar(&caller.AllowUnpinned, "allow-unpinned", false, "allow successful exit without a pinned key")
	flags.BoolVar(&caller.AllowPrefix, "allow-prefix", false, "allow successful exit for a verified prefix")
	flags.StringArrayVar(&caller.AcceptDiscontinuities, "accept-discontinuity", nil, "accept a discontinuity by stream-open record ID")
	flags.StringArrayVar(&caller.AllowPartialHistories, "allow-partial-history", nil, "accept a stream's missing predecessor")
	flags.StringVar(&caller.ExpectLineage, "expect-lineage", "", "require this history lineage")
	flags.StringArrayVar(&caller.ExpectHeads, "expect-head", nil, "require a stream tip as stream:seq:sha256:hex")
	flags.StringArrayVar(&caller.ExpectSequences, "expect-seq", nil, "require a stream tip sequence as stream:seq")
	flags.StringVar(&caller.Format, "format", "", "explicit receipt format for a file (v3)")
	flags.StringVar(&output, "output", "result", "document to write (result or projection)")
	flags.BoolVar(&claims, "claims", false, "report whether the v3 detector claims a single file")
	return cmd
}

func runV3(cmd *cobra.Command, paths []string, caller v3.CallerOptions, claims bool, output string) error {
	if claims && (len(paths) != 1 || cmd.Flags().NFlag() != 1) {
		return errors.New("--claims requires one file and no other options")
	}
	if !v3.IsV3Output(output) {
		return errors.New("output must be result or projection")
	}
	if cmd.Flags().Changed("format") && caller.Format != "v3" {
		return errors.New("format must be v3")
	}
	if len(paths) == 1 && !claims {
		info, err := os.Stat(paths[0])
		if err != nil {
			return fmt.Errorf("stat evidence input: %w", err)
		}
		caller.Directory = info.IsDir()
	}
	if !caller.Directory {
		for _, path := range paths {
			if err := checkV3File(path); err != nil {
				return err
			}
		}
	}
	if claims {
		claimed, err := v3.ClaimsInput(paths[0], false)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), claimed)
		return err
	}
	opts, err := caller.Parse(len(paths))
	if err != nil {
		return err
	}
	result, err := v3.VerifyPaths(cmd.Context(), paths, opts)
	if err != nil {
		return err
	}
	data, err := result.ResultBytes(output)
	if err != nil {
		return err
	}
	if _, err := cmd.OutOrStdout().Write(data); err != nil {
		return fmt.Errorf("write v3 receipt result: %w", err)
	}
	if result.ExitCode != 0 {
		return &cliutil.ExitError{Code: result.ExitCode}
	}
	return nil
}

func checkV3File(path string) error {
	// A filename can claim v3 without opening its contents. Check readability
	// independently so an absent named input remains an input error.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve evidence path: %w", err)
	}
	file, _, err := recorder.OpenEvidenceFile(resolved)
	if err != nil {
		return fmt.Errorf("open evidence: %w", err)
	}
	return file.Close()
}
