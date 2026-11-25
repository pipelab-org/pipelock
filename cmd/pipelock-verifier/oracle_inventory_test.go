// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestReceiptCommandTreeOracle(t *testing.T) {
	file := testreceipt.ReceiptProbe{Args: []string{"$file", "--key", "$pub"}}
	dir := testreceipt.ReceiptProbe{Args: []string{"$dir", "--dir", "--key", "$pub"}, Directory: true}
	testreceipt.RunReceiptCommandOracle(t, newRootCmd(), func(args []string, out io.Writer) int {
		return execute(args, out, out)
	}, map[string][]testreceipt.ReceiptProbe{
		"audit-packet": {{Args: []string{"$file"}}, {Args: []string{"$dir"}, Directory: true}},
		"chain":        {file, dir},
		"completeness": {file, {Args: []string{"$dir", "--key", "$pub"}, Directory: true}},
		"independent":  {{Args: []string{"$file", "--bundle", "$tmp/bundle.json"}}, {Args: []string{"$dir", "--dir", "--bundle", "$tmp/bundle.json"}, Directory: true}},
		"receipt":      {file, {Args: []string{"$file", "--recheck-source", "$tmp/source"}}},
		"replay":       {file},
		"verify-run":   {{Args: []string{"$dir"}, Directory: true}},
	}, map[string]string{
		"aarp":       "the path is an AARP attestation envelope or AARP chain",
		"provenance": "the path is an experimental provenance fixture document",
	})
}
