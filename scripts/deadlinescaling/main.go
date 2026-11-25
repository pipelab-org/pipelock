// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Command deadlinescaling reports select waits that fail a test on a raw timer.
//
// A loaded CI runner is slower than a laptop. internal/testwait.Deadline
// multiplies those waits by four when CI is set. A select that fails the test
// when its own timer fires opts out of that scaling unless the duration is
// already a Deadline call, and the run goes red on scheduling noise.
//
// The scan is syntactic. It flags a select receive from time.After, from an
// identifier assigned from time.After in the same function, or from a
// time.NewTimer channel, when that case body fails the test. Poll ticks and
// absence checks do not fail the test on expiry, so they stay unscaled.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run scans test files and returns 0 when clean, 1 when it reports findings
// or leaves a fix unapplied, and 2 when it cannot scan.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("deadlinescaling", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fix := fs.Bool("fix", false, "wrap raw failing-wait durations in testwait.Deadline")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	paths := fs.Args()
	if len(paths) == 0 {
		_, _ = fmt.Fprintln(stderr, "deadlinescaling: no test files given; refusing an empty scan")
		return 2
	}
	findings, err := analyze(paths)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "deadlinescaling: %v\n", err)
		return 2
	}
	if *fix {
		return applyFixes(findings, stdout, stderr)
	}
	for _, f := range findings {
		_, _ = fmt.Fprintf(stdout, "%s:%d:%d: failing wait uses a raw duration\n", f.path, f.line, f.col)
	}
	if len(findings) > 0 {
		return 1
	}
	return 0
}
