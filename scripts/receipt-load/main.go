// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Command receipt-load drives a real Pipelock forward proxy and a local sink
// and reports two separate verdicts: performance (rates and latency to a fully
// read response body) and integrity. The single-destination workload checks
// aggregate receipt accounting and authenticated per-action/chain links. The
// per-request destination workload also checks each planned request left its
// expected receipt families. Neither mode distinguishes v2 decision phases.
// Exit codes are 0 success, 1 integrity/unknown, 2 usage, 3 performance, and
// 4 setup failure before receipt evidence (see README.md).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"
)

const (
	exitOK        = 0
	exitIntegrity = 1
	exitUsage     = 2
	exitPerf      = 3
	exitHarness   = 4
)

func main() { os.Exit(realMain(os.Args[1:])) }

// logf writes a timestamped status line to stderr. Values from flags, the
// proxy log, and error text are quoted by the callers' verbs, so a hostile
// string cannot forge a second status line.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", time.Now().Format("2006/01/02 15:04:05"), fmt.Sprintf(format, args...))
}

func realMain(args []string) int {
	if len(args) > 0 && args[0] == "summarize" {
		path, err := summarizeCommand(args[1:])
		if err != nil {
			logf("summarize: %v", err)
			return exitUsage
		}
		logf("matrix summary: %q", path)
		return exitOK
	}
	opt, modes, lockFile, err := parseFlags(args)
	if err != nil {
		logf("%v", err)
		if isSetupFailure(err) {
			return exitHarness
		}
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if lockFile != "" {
		logf("waiting for %q", lockFile)
		release, lockErr := holdLock(lockFile)
		if lockErr != nil {
			logf("lock %q: %v", lockFile, lockErr)
			return exitHarness
		}
		defer release()
	}
	return runModes(ctx, opt, modes)
}

// runModes runs every requested mode even after one fails, so a single
// invocation reports every verdict, and returns the most serious exit code.
func runModes(ctx context.Context, opt options, modes []string) int {
	code := exitOK
	for _, mode := range modes {
		res, err := runMode(ctx, opt, mode)
		if res == nil {
			logf("%q: %v", mode, err)
		}
		next := modeExitCode(res, err)
		// Integrity takes precedence over harness failure, then performance.
		if next == exitIntegrity || (next == exitHarness && code != exitIntegrity) || (next == exitPerf && code == exitOK) {
			code = next
		}
		if ctx.Err() != nil {
			break
		}
	}
	return code
}

// setupError is only attached when receipt emission cannot yet have been attempted.
// An unmarked error (even without a result) is an integrity failure.
type setupError struct{ err error }

func (e *setupError) Error() string { return e.err.Error() }
func (e *setupError) Unwrap() error { return e.err }

func isSetupFailure(err error) bool {
	// A joined or wrapped error could include a later, unclassified failure.
	// Only the direct setup marker proves setup-only failure.
	return reflect.TypeOf(err) == reflect.TypeFor[*setupError]()
}

func modeExitCode(res *result, err error) int {
	if isSetupFailure(err) {
		return exitHarness
	}
	if res == nil || err != nil || res.Integrity.Verdict != verdictPass {
		return exitIntegrity
	}
	if res.Performance.Verdict != perfMeasured {
		return exitPerf
	}
	return exitOK
}

func parseFlags(args []string) (options, []string, string, error) {
	fs := flag.NewFlagSet("receipt-load", flag.ContinueOnError)
	binary := fs.String("binary", "./pipelock", "pipelock binary")
	out := fs.String("out", "", "unique output directory")
	n := fs.Int("requests", 1000000, "measured requests per mode")
	restartAfter := fs.Int("restart-after", 0, "restart once after N measured requests (0 disables; N must be less than --requests)")
	warmup := fs.Int("warmup", 1000, "warmup requests per mode, sent through the same proxy process and excluded from performance")
	concurrency := fs.Int("concurrency", 128, "concurrent clients")
	modes := fs.String("modes", "off,best,required", "comma-separated modes")
	destinations := fs.String("destinations", destinationsSingle, "destination workload: single or per-request")
	chains := fs.Int("chains", 1, "number of signed receipt chains (1 to 32)")
	rules := fs.String("rules", rulesEmpty, `rule bundles to load: "empty" for none, or a directory that is copied and hashed`)
	seed := fs.Uint64("seed", 1, "workload seed; fixes request keys and which requests are blocked")
	window := fs.Duration("window", 5*time.Second, "width of each per-window rate")
	readyTimeout := fs.Duration("ready-timeout", 10*time.Second, "maximum time for the proxy to listen at initial launch and after restart")
	shutdown := fs.Duration("shutdown-timeout", time.Minute, "how long the proxy gets to exit after SIGTERM before it is killed")
	verifyTimeout := fs.Duration("verify-timeout", time.Minute, "maximum time allowed for external receipt verification")
	lock := fs.String("lock-file", "", "advisory lock file held for the whole invocation, to serialize runs on one machine")
	if err := fs.Parse(args); err != nil {
		return options{}, nil, "", err
	}
	if *destinations != destinationsSingle && *destinations != destinationsPerRequest {
		return options{}, nil, "", fmt.Errorf("invalid --destinations %q", *destinations)
	}
	maxInt := int(^uint(0) >> 1)
	if *restartAfter != 0 && (*restartAfter < 0 || *restartAfter >= *n) {
		return options{}, nil, "", fmt.Errorf("--restart-after must be zero or positive and less than --requests")
	}
	if *out == "" || *n < 1 || *warmup < 0 || *n > maxInt-*warmup || *concurrency < 1 || *chains < 1 || *chains > 32 || *window <= 0 || *readyTimeout <= 0 || *shutdown <= 0 || *verifyTimeout <= 0 {
		return options{}, nil, "", fmt.Errorf("--out, positive --requests, non-negative --warmup with a non-overflowing total, positive --concurrency, --chains from 1 to 32, and positive --window, --ready-timeout, --shutdown-timeout, and --verify-timeout are required")
	}
	absBinary, err := filepath.Abs(*binary)
	if err != nil {
		return options{}, nil, "", err
	}
	if info, statErr := os.Stat(absBinary); statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return options{}, nil, "", &setupError{fmt.Errorf("binary %q is %w", absBinary, errNotExecutable)}
	}
	absOut, err := filepath.Abs(*out)
	if err != nil {
		return options{}, nil, "", err
	}
	if err := os.MkdirAll(absOut, 0o750); err != nil {
		return options{}, nil, "", &setupError{err}
	}
	var list []string
	for _, mode := range strings.Split(*modes, ",") {
		if mode != modeOff && mode != modeBest && mode != modeRequired {
			return options{}, nil, "", fmt.Errorf("invalid mode %q", mode)
		}
		list = append(list, mode)
	}
	return options{
		destinations: *destinations, binary: absBinary, out: absOut, rules: *rules, requests: *n, warmup: *warmup, concurrency: *concurrency,
		chains: *chains, seed: *seed, window: *window, readyTimeout: *readyTimeout, shutdownTimeout: *shutdown, verifyTimeout: *verifyTimeout, restartAfter: *restartAfter,
	}, list, *lock, nil
}
