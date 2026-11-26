// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"crypto/ed25519"
	"errors"
	"strings"
)

// CallerOptions contains the shared textual options for standalone and browser verification.
type CallerOptions struct {
	Keys                  []string `json:"keys"`
	ExpectHeads           []string `json:"expect_heads"`
	ExpectSequences       []string `json:"expect_sequences"`
	AcceptDiscontinuities []string `json:"accept_discontinuities"`
	AllowPartialHistories []string `json:"allow_partial_histories"`
	ExpectLineage         string   `json:"expect_lineage"`
	Format                string   `json:"format"`
	Directory             bool     `json:"directory"`
	AllowPrefix           bool     `json:"allow_prefix"`
	AllowUnpinned         bool     `json:"allow_unpinned"`
}

// Parse converts text pins and verifies their scope before inspecting evidence.
func (caller CallerOptions) Parse(fileCount int) (Options, error) {
	if caller.Format != "" && caller.Format != "v3" {
		return Options{}, errors.New("format must be v3")
	}
	if caller.Format == "v3" && fileCount != 1 {
		return Options{}, errors.New("explicit v3 format requires exactly one file")
	}
	for _, key := range caller.Keys {
		if len(key) != 2*ed25519.PublicKeySize || key != strings.ToLower(key) {
			return Options{}, errors.New("public key must be 64 lowercase hexadecimal characters")
		}
	}
	keys, err := DecodeKeys(caller.Keys)
	if err != nil {
		return Options{}, err
	}
	opts := Options{
		Keys: keys, Directory: caller.Directory, ExplicitV3: caller.Format == "v3",
		AllowPrefix: caller.AllowPrefix, AllowUnpinned: caller.AllowUnpinned,
		ExpectLineage: caller.ExpectLineage, AcceptDiscontinuities: caller.AcceptDiscontinuities,
		AllowPartialHistories: caller.AllowPartialHistories,
	}
	for _, text := range caller.ExpectHeads {
		head, err := ParseHead(text)
		if err != nil {
			return Options{}, err
		}
		opts.ExpectHeads = append(opts.ExpectHeads, head)
	}
	for _, text := range caller.ExpectSequences {
		seq, err := ParseSequence(text)
		if err != nil {
			return Options{}, err
		}
		opts.ExpectSequences = append(opts.ExpectSequences, seq)
	}
	return opts, opts.validate()
}

// UseHostVerifier reports that browser bounds prevented verification.
func UseHostVerifier(opts Options) Result {
	result := newResult(opts)
	result.Counts.Scope = "not_appraised"
	result.Findings = append(result.Findings, Finding{Code: codeUseHostVerifier, Class: findingClasses[codeUseHostVerifier]})
	result.finish(opts)
	return result
}

// ResultBytes writes the selected canonical document with its terminal newline.
func (r Result) ResultBytes(output string) ([]byte, error) {
	var data []byte
	var err error
	switch output {
	case "result":
		data, err = r.JSON()
	case "projection":
		data, err = r.Projection()
	default:
		return nil, errors.New("output must be result or projection")
	}
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// IsV3Output reports whether the standalone verifier's document selection is valid.
func IsV3Output(output string) bool {
	return output == "result" || output == "projection"
}
