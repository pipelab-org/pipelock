// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

// Package command adapts v3 verification to the Go receipt commands.
package command

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// Flags are the v3 options shared by the two executables.
type Flags struct {
	Format        string
	Lineage       string
	Discontinuity []string
	Partial       []string
	DiskIndex     bool
}

func (f *Flags) Bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.Format, "format", "", "explicit receipt format for a file (v3)")
	cmd.Flags().StringVar(&f.Lineage, "expect-lineage", "", "v3: require this history lineage")
	cmd.Flags().StringArrayVar(&f.Discontinuity, "accept-discontinuity", nil, "v3: accept an unproven end by successor stream-open record ID")
	cmd.Flags().StringArrayVar(&f.Partial, "allow-partial-history", nil, "v3: accept this stream's missing predecessor")
	cmd.Flags().BoolVar(&f.DiskIndex, "disk-index", false, "v3: use an on-disk index for decision appraisal")
}

func (f Flags) Detect(paths []string, dir string, seq SeqFlag) (bool, error) {
	if f.Format != "" {
		if f.Format != "v3" || len(paths) != 1 || dir != "" {
			return false, usage(errors.New("--format v3 requires exactly one explicit file"))
		}
		return true, nil
	}
	requiresV3 := f.Lineage != "" || len(f.Discontinuity) != 0 || len(f.Partial) != 0 || f.DiskIndex || seq.V3 != ""
	if dir != "" {
		claims, err := v3.ClaimsInput(dir, true)
		if claims || requiresV3 && err != nil {
			return claims, err
		}
	}
	for _, path := range paths {
		claims, err := v3.ClaimsInput(path, false)
		if claims || requiresV3 && err != nil {
			return claims, err
		}
	}
	if requiresV3 {
		return false, usage(errors.New("the selected receipt options require v3 evidence"))
	}
	return false, nil
}

// SeqFlag preserves the legacy numeric argument and accepts the v3 form too.
type SeqFlag struct {
	Legacy uint64
	V3     string
}

func (s *SeqFlag) Set(value string) error {
	if strings.Contains(value, ":") {
		if _, err := v3.ParseSequence(value); err != nil {
			return err
		}
		s.V3 = value
		return nil
	}
	s.V3 = ""
	return (endproof.SeqFlag{Seq: &s.Legacy}).Set(value)
}

func (s *SeqFlag) String() string {
	if s.V3 != "" {
		return s.V3
	}
	return strconv.FormatUint(s.Legacy, 10)
}

func (*SeqFlag) Type() string { return "sequence" }

type Input struct {
	Paths               []string
	Directory           string
	Keys                []string
	Head                string
	Seq                 SeqFlag
	SeqSet              bool
	AllowPrefix         bool
	AllowUnpinned       bool
	LegacyOptions       bool
	LegacySelection     v3.LegacySelection
	GenericLegacyLabels bool
}

// Run writes the same canonical result document in both executables.
func (f Flags) Run(cmd *cobra.Command, in Input) error {
	if in.LegacyOptions {
		return usage(errors.New("these options apply only to legacy evidence; v3 does not offer whole-recorder proof"))
	}
	keys, err := v3.DecodeKeys(in.Keys)
	if err != nil {
		return usage(err)
	}
	opts := v3.Options{
		Keys: keys, AllowPrefix: in.AllowPrefix, AllowUnpinned: in.AllowUnpinned,
		ExpectLineage: f.Lineage, AcceptDiscontinuities: f.Discontinuity,
		AllowPartialHistories: f.Partial, Directory: in.Directory != "",
		ExplicitV3: f.Format == "v3", DiskIndex: f.DiskIndex, GenericLegacyLabels: in.GenericLegacyLabels,
	}
	opts.LegacySelection = in.LegacySelection
	if in.Head != "" {
		head, err := v3.ParseHead(in.Head)
		if err == nil {
			opts.ExpectHeads = []v3.Head{head}
		} else if in.Directory != "" && !strings.Contains(in.Head, ":") {
			opts.LegacyEnd = &v3.LegacyEnd{Head: in.Head}
		} else {
			return usage(err)
		}
	}
	if in.SeqSet {
		if in.Seq.V3 == "" && in.Directory != "" {
			if opts.LegacyEnd == nil {
				opts.LegacyEnd = &v3.LegacyEnd{}
			}
			opts.LegacyEnd.Sequence = &in.Seq.Legacy
		} else {
			sequence, err := v3.ParseSequence(in.Seq.V3)
			if err != nil {
				return usage(err)
			}
			opts.ExpectSequences = []v3.Sequence{sequence}
		}
	}
	paths := in.Paths
	if in.Directory != "" {
		paths = []string{in.Directory}
	}
	result, err := v3.VerifyPaths(cmd.Context(), paths, opts)
	if err != nil {
		return usage(err)
	}
	data, err := result.JSON()
	if err != nil {
		return fmt.Errorf("encode v3 receipt result: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(data)); err != nil {
		return fmt.Errorf("write v3 receipt result: %w", err)
	}
	if result.ExitCode != 0 {
		return cliutil.ExitCodeError(result.ExitCode, errors.New(result.Verdict))
	}
	return nil
}

func usage(err error) error {
	return cliutil.ExitCodeError(cliutil.ExitConfig, err)
}

// ResolveDirectory returns the directory a --dir style input verifies. A root
// that holds v3 receipts is verified as a whole, so its streams, cutover
// inventory and legacy chains stay in scope even when a subdirectory also holds
// recorder evidence. Otherwise the recorder location rules choose the directory.
func ResolveDirectory(dir, locationID string) (string, error) {
	if locationID == "" {
		if root, err := recorder.ResolveEvidenceRoot(dir); err == nil {
			if handle, openErr := recorder.OpenEvidenceDirectory(root); openErr == nil {
				claimed, _ := v3.ClaimsInput(root, true)
				_ = handle.Close()
				if claimed {
					return root, nil
				}
			}
		}
	}
	// An explicit location selects one directory for the profile verifier, which
	// checks any receipt-profile files in it. The root listing must not refuse
	// the selection, so this is one of the verifier's mixed-profile opt-ins.
	location, err := recorder.ResolveEvidenceLocation(dir, locationID, recorder.MixedReceiptProfiles)
	if err != nil {
		return "", err
	}
	return location.Dir, nil
}
