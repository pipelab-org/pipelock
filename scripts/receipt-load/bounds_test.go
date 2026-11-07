// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
)

func TestSummaryRejectsFailedVerifier(t *testing.T) {
	root := t.TempDir()
	r := fakeResult(100, 90, 95, verdictPass, perfMeasured)
	putResult(t, root, 2, 1, 1, modeRequired, r)
	args := []string{"--root", root, "--modes", modeRequired, "--cpus", "2", "--chains", "1"}
	if _, err := summarizeCommand(args); err != nil {
		t.Fatal(err)
	}
	r.Integrity.Verify.Exit = 1
	putResult(t, root, 2, 1, 1, modeRequired, r)
	if code := realMain(append([]string{"summarize"}, args...)); code == exitOK {
		t.Fatal("failed verifier returned success")
	}
	row := readSummary(t, root)["2/1/required"]
	if row["integrity"] != verdictFail || row["integrity_failures"] != "1" || row["verify_failures"] != "1" || row["median_req_s"] != "" {
		t.Fatalf("failed verifier row: %v", row)
	}
}

func TestSummaryRejectsPreAuditGapContract(t *testing.T) {
	root := t.TempDir()
	r := fakeResult(100, 90, 95, verdictPass, perfMeasured)
	r.Inputs.Harness.ContractVersion = "7" // predates proxy audit-gap validation
	putResult(t, root, 2, 1, 1, modeRequired, r)
	args := []string{"summarize", "--root", root, "--modes", modeRequired, "--cpus", "2", "--chains", "1"}
	if code := realMain(args); code == exitOK {
		t.Fatal("result without audit-gap validation returned success")
	}
	row := readSummary(t, root)["2/1/required"]
	if row["integrity"] != verdictFail || row["median_req_s"] != "" {
		t.Fatalf("old contract presented as valid measurement: %v", row)
	}
}

func TestSummaryBoundsSamples(t *testing.T) {
	root := t.TempDir()
	for _, count := range []int{0, -1, maxSummarySamples + 1, int(^uint(0) >> 1)} {
		_, err := summarizeCommand([]string{"--root", root, "--samples", strconv.Itoa(count), "--modes", modeOff, "--cpus", "2", "--chains", "1"})
		if err == nil || !strings.Contains(err.Error(), "--samples") {
			t.Fatalf("sample bound %d: %v", count, err)
		}
		if err := writeSummary(summaryParams{root: root, samples: count}); err == nil {
			t.Fatalf("writeSummary accepted %d", count)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "summary.csv")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid samples wrote summary: %v", err)
	}
}

func TestBundleLogBounds(t *testing.T) {
	for _, tc := range []struct{ name, data string }{
		{"line", strings.Repeat("x", 70*1024)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "proxy.log")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := bundleLogLines(path); err == nil {
				t.Fatal("oversized log accepted")
			}
		})
	}
}

func TestBundleLogBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		want       int
	}{
		{"empty", "", 0},
		{"matches", strings.Repeat("pipelock: DEGRADED — 1 rule bundle(s) unavailable: community\n", maxBundleLogLines+1), maxBundleLogLines},
		{"large-file", strings.Repeat("x\n", 8*1024*1024/2), 0},
		{"line-limit", strings.Repeat("x", maxProxyLogLineBytes-2) + "\npipelock: DEGRADED — 1 rule bundle(s) unavailable: community\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "proxy.log")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			lines, err := bundleLogLines(path)
			if err != nil || len(lines) != tc.want {
				t.Fatalf("lines=%v error=%v", lines, err)
			}
		})
	}
}

func TestUnavailableProcessStatsPreserveIntegrity(t *testing.T) {
	old := readProcessStat
	readProcessStat = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { readProcessStat = old })
	opt := smallOptions(t, realPipelock(t))
	opt.requests, opt.warmup = 10, 2
	res, err := runMode(context.Background(), opt, modeRequired)
	if err != nil {
		t.Fatalf("process stats aborted integrity collection: %v", err)
	}
	if res.Integrity.Verdict != verdictPass || !res.Integrity.Shutdown.Clean || res.Performance.Verdict != perfInvalid || !hasReason(res.Performance.Reasons, "measurement unavailable") {
		t.Fatalf("result: %+v", res)
	}
}

func TestFailedSignalHasBoundedWait(t *testing.T) {
	// Releasing a second handle makes Signal fail even while the real child lives.
	port, err := freePort(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	addr := "127.0.0.1:" + strconv.Itoa(port)
	cmd := localCommand(context.Background(), newFakePipelock(t, "hang"), "", os.Environ(), "run", "--listen", addr)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	original := cmd.Process
	exited := make(chan struct{})
	logFile, err := os.CreateTemp(t.TempDir(), "proxy-log-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	p := &proxyProc{cmd: cmd, exited: exited, log: logFile}
	go func() { _, p.exitErr = original.Wait(); close(exited) }()
	t.Cleanup(func() { _ = original.Kill(); <-exited })
	if err := awaitProxy(context.Background(), addr, p, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	duplicate, err := os.FindProcess(original.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := duplicate.Release(); err != nil {
		t.Fatal(err)
	}
	cmd.Process = duplicate
	done := make(chan shutdownReport, 1)
	go func() { done <- p.stop(20 * time.Millisecond) }()
	select {
	case rep := <-done:
		if rep.Clean || p.stopped {
			t.Fatal("live child marked stopped after signal and kill failures")
		}
		cmd.Process = original
		p.cleanup()
		if !p.stopped {
			t.Fatal("cleanup did not retry termination")
		}
	case <-time.After(time.Second):
		_ = original.Kill()
		<-done
		t.Fatal("failed signal waited without a deadline")
	}
}

func TestRelativeOutputIsNormalized(t *testing.T) {
	binary := newFakePipelock(t, "ok")
	root := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(wd, root)
	if err != nil {
		t.Fatal(err)
	}
	opt, _, _, err := parseFlags([]string{"--binary", binary, "--out", relative, "--requests", strconv.Itoa(1), "--warmup", "0", "--modes", modeOff})
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(opt.out) {
		t.Fatalf("output not absolute: %q", opt.out)
	}
	if res, err := runMode(context.Background(), opt, modeOff); err != nil || res.Integrity.Verdict != verdictPass {
		t.Fatalf("relative output run: %v %v", res, err)
	}
}

func TestBundleLogMatchesProducerMessages(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		want       int
	}{
		{"security warning", "pipelock: SECURITY WARNING: rule bundle community degraded (integrity): bad signature\n", 1},
		{"degraded summary", "pipelock: DEGRADED — 1 rule bundle(s) unavailable: community\n", 1},
		{"standard pack", `pipelock: DEGRADED: standard pack "core" failed to load: missing — running core-only` + "\n", 1},
		{"loader warning", `pipelock: bundle "community" loaded although min_pipelock "3.8.0" could not be verified` + "\n", 1},
		{"freshness warning", `pipelock: WARNING: bundle "community" expired at 2026-01-01 (running in stale mode)` + "\n", 1},
		{"allow degraded", "pipelock: SECURITY WARNING: rules.allow_degraded=true; strict mode is booting with degraded rule-bundle integrity\n", 1},
		{"reload loader warning", `WARNING: config reload: bundle "community" loaded although min_pipelock "3.8.0" could not be verified` + "\n", 1},
		{"reload freshness warning", `WARNING: config reload: WARNING: bundle "community" expired at 2026-01-01 (running in stale mode)` + "\n", 1},
		{"reload degraded summary", "WARNING: config reload: DEGRADED — 1 rule bundle(s) unavailable: community\n", 1},
		{"reload bundle error", "WARNING: config reload: rule bundle community degraded (integrity): bad signature\n", 1},
		{"reload coverage drop", "WARNING: config reload: rule bundle community cleanly removed 1 live pattern(s)\n", 1},
		{"reload opt in", "WARNING: config reload: rules.allow_degraded=true; accepting degraded rule-bundle coverage after explicit operator opt-in\n", 1},
		{"unrelated reload", "WARNING: config reload: fetch_proxy.listen changed from localhost:8888 to localhost:8889 - requires restart, ignoring\n", 0},
		{"audit event", `{"level":"warn","event":"rule_bundle_degraded","bundle":"community"}` + "\n", 1},
		{"escaped audit event", `{"event":"rule_bundle_\u0064egraded"}` + "\n", 1},
		{"startup path", "  Recorder: /out/rule_bundle_review/recorder (flight recorder enabled)\n", 0},
		{"config path", "pipelock: config /out/rule bundle review/pipelock.yaml\n", 0},
		{"URL field", `{"event":"forward_http","url":"http://api.vendor.example/rule_bundle_x?q=rule+bundle"}` + "\n", 0},
		{"other event", `{"event":"error","error":"rule bundle mentioned in a request error"}` + "\n", 0},
		{"unprefixed", "SECURITY WARNING: rule bundle community degraded\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "proxy.log")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			lines, err := bundleLogLines(path)
			if err != nil || len(lines) != tc.want {
				t.Fatalf("lines=%v error=%v", lines, err)
			}
		})
	}
}

func TestBundleLogReportsUndecodableRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.log")
	data := `{"event":"rule_bundle_degraded"` + "\npipelock: DEGRADED — 1 rule bundle(s) unavailable: community\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err := bundleLogLines(path)
	if err == nil || len(lines) != 1 {
		t.Fatalf("lines=%v error=%v; want the later message and a decode error", lines, err)
	}
}

func TestRealBundlePathDoesNotFailIntegrity(t *testing.T) {
	bin := realPipelock(t)
	opt := smallOptions(t, bin)
	opt.out = filepath.Join(opt.out, "rule_bundle_review")
	if err := os.Mkdir(opt.out, 0o750); err != nil {
		t.Fatal(err)
	}
	opt.requests, opt.warmup = 10, 2
	if code := runModes(context.Background(), opt, []string{modeOff}); code != exitOK {
		t.Fatalf("exit=%d: %+v", code, readResult(t, filepath.Join(opt.out, modeOff)).Integrity)
	}
}

func TestBundleLogMemoryBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("ordinary log line\n", 500000)), 0o600); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	lines, err := bundleLogLines(path)
	runtime.ReadMemStats(&after)
	if err != nil || len(lines) != 0 {
		t.Fatalf("large ordinary log: lines=%v error=%v", lines, err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1024*1024 {
		t.Fatalf("log scan allocated %d bytes; want at most 1 MiB", allocated)
	}
}

func TestAuditGapLines(t *testing.T) {
	gap := `{"level":"error","event":"error","error":"event=receipt_channel_broken audit_gap=true phase=outcome"}` + "\n"
	for _, tc := range []struct {
		name, data string
		count      int
		kept       int
	}{
		{"empty", "", 0, 0},
		{"none", "{\"event\":\"forward_http\"}\naudit_gap=false\n", 0, 0},
		{"one", "noise\n" + gap, 1, 1},
		{"many", strings.Repeat(gap, maxAuditGapLines+3), maxAuditGapLines + 3, 1},
		{"long", `{"event":"error","error":"event=receipt_channel_broken audit_gap=true ` + strings.Repeat("x", 2*maxAuditGapLineSize) + `"}` + "\n", 1, 1},
		{"startup path", "  Recorder: /audit_gap=true/recorder (flight recorder enabled)\n", 0, 0},
		{"URL field", `{"event":"forward_http","url":"http://api.vendor.example/?audit_gap=true"}` + "\n", 0, 0},
		{"error URL", `{"event":"error","error":"Get http://api.vendor.example/?audit_gap=true: EOF"}` + "\n", 0, 0},
		{"false prefix", `{"event":"error","error":"event=receipt_channel_broken audit_gap=trueish"}` + "\n", 0, 0},
		{"no diagnostic", `{"event":"error"}`, 0, 0},
		{"no event label", "pipelock: warning notice audit_gap=true\n", 0, 0},
		{"empty event label", "pipelock: warning event= audit_gap=true\n", 0, 0},
		{"escaped marker", `{"event":"error","error":"event=receipt_channel_broken audit_gap=\u0074rue"}`, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "proxy.log")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			count, lines, err := auditGapLines(path)
			if err != nil || count != tc.count || len(lines) != tc.kept {
				t.Fatalf("count=%d lines=%d error=%v", count, len(lines), err)
			}
			for _, line := range lines {
				if len(line) > maxAuditGapLineSize {
					t.Fatalf("kept line of %d bytes", len(line))
				}
			}
		})
	}
	path := filepath.Join(t.TempDir(), "proxy.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 70*1024)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auditGapLines(path); err == nil {
		t.Fatal("oversized log accepted")
	}
	if _, _, err := auditGapLines(filepath.Join(t.TempDir(), "absent.log")); err == nil {
		t.Fatal("missing log accepted")
	}
	if err := os.WriteFile(path, []byte(`{"event":"error","error":"event=receipt_channel_broken audit_gap=true`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auditGapLines(path); err == nil {
		t.Fatal("incomplete audit record accepted")
	}
}

// A proxy that reports a receipt it failed to record fails integrity, with
// its own line as the reason, even when every other count balances.
func TestProxyAuditGapFailsIntegrity(t *testing.T) {
	for _, tc := range []struct {
		behavior string
		code     int
	}{{"ok", exitOK}, {"auditgap", exitIntegrity}} {
		t.Run(tc.behavior, func(t *testing.T) {
			opt := smallOptions(t, newFakePipelock(t, tc.behavior))
			code := runModes(context.Background(), opt, []string{modeOff})
			got := readResult(t, filepath.Join(opt.out, modeOff))
			gap := hasReason(got.Integrity.Reasons, "proxy reported 1 audit gap(s); first: ") && hasReason(got.Integrity.Reasons, "event=receipt_channel_broken")
			if code != tc.code || gap != (tc.code != exitOK) {
				t.Fatalf("code=%d integrity=%+v", code, got.Integrity)
			}
		})
	}
}

func TestBundleActivitySurvivesMalformedRecord(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "bundle-malformed"))
	if code := runModes(context.Background(), opt, []string{modeOff}); code != exitIntegrity {
		t.Fatalf("exit=%d, want integrity failure", code)
	}
	got := readResult(t, filepath.Join(opt.out, modeOff))
	if len(got.Inputs.Rules.ProxyLogLines) == 0 {
		t.Fatalf("bundle lines dropped next to a malformed record: %+v", got.Inputs.Rules)
	}
	if !hasReason(got.Integrity.Reasons, "proxy reported rule bundle activity under --rules empty: ") {
		t.Fatalf("bundle reason missing: %+v", got.Integrity)
	}
	// The bundle scan and the audit-gap scan each report the bad record.
	decodeErrors := 0
	for _, reason := range got.Integrity.Reasons {
		if strings.HasPrefix(reason, "reading proxy.log failed: ") {
			decodeErrors++
		}
	}
	if decodeErrors != 2 {
		t.Fatalf("decode errors reported = %d, want one per scan: %+v", decodeErrors, got.Integrity)
	}
}

func TestRealAuditGapPathDoesNotFailIntegrity(t *testing.T) {
	bin := realPipelock(t)
	for _, mode := range []string{modeOff, modeBest, modeRequired} {
		t.Run(mode, func(t *testing.T) {
			opt := smallOptions(t, bin)
			opt.out = filepath.Join(opt.out, auditGapMarker)
			if err := os.Mkdir(opt.out, 0o750); err != nil {
				t.Fatal(err)
			}
			opt.requests, opt.warmup = 10, 2
			opt.chains, opt.restartAfter = 2, 5
			if code := runModes(context.Background(), opt, []string{mode}); code != exitOK {
				t.Fatalf("exit=%d: %+v", code, readResult(t, filepath.Join(opt.out, "chains-2-"+mode)).Integrity)
			}
		})
	}
}

func TestAuditGapRealLogger(t *testing.T) {
	var log bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, &log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	ctx, err := audit.NewHTTPLogContext(http.MethodGet, "http://api.vendor.example/?audit_gap=true", "127.0.0.1", "request-1", "")
	if err != nil {
		t.Fatal(err)
	}
	logger.LogForwardHTTP(ctx, http.StatusOK, 1, time.Millisecond)
	logger.LogError(audit.NewResourceLogContext("config_reload", "/audit_gap=true/config.yaml"), errors.New("reload rejected"))
	path := filepath.Join(t.TempDir(), "proxy.log")
	if err := os.WriteFile(path, log.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if count, lines, err := auditGapLines(path); err != nil || count != 0 {
		t.Fatalf("ordinary audit events counted as gaps: count=%d lines=%q err=%v", count, lines, err)
	}
	log.Reset()
	const diagnostic = "event=receipt_channel_broken audit_gap=true verdict=allow phase=outcome layer=outcome failure=other"
	logger.LogError(audit.NewRequestLogContext("private-context"), errors.New(diagnostic))
	if err := os.WriteFile(path, log.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if count, lines, err := auditGapLines(path); err != nil || count != 1 || len(lines) != 1 || lines[0] != diagnostic {
		t.Fatalf("gap diagnostic not isolated from context: count=%d lines=%q err=%v", count, lines, err)
	}
}

func TestAuditGapWarningDiagnostics(t *testing.T) {
	// These prefixes are emitted by internal/mcp/taint.go and
	// internal/deferred/manager.go. Their suffixes contain raw errors/IDs.
	for _, event := range []string{"block_receipt_emit_failed", "hold_failure_receipt_emit_failed", "deferred_journal_write_failed", "deferred_resolution_receipt_failed"} {
		t.Run(event, func(t *testing.T) {
			prefix := "event=" + event + " " + auditGapMarker
			message, err := auditGapMessage([]byte("pipelock: warning " + prefix + " source=cancel defer_id=private-id: private-error"))
			if err != nil || message != prefix {
				t.Fatalf("diagnostic=%q error=%v", message, err)
			}
		})
	}
}

func TestAuditGapSamplesKeepDistinctMessagesWithOneLabel(t *testing.T) {
	// Samples are deduplicated by the whole message, not the failure label,
	// so a different phase or verdict with the same cause still prints.
	dirs := newRunDirs(t.TempDir())
	intent := "event=receipt_channel_broken audit_gap=true verdict=allow phase=intent layer=none failure=append_lock_timeout"
	outcome := "event=receipt_channel_broken audit_gap=true verdict=block phase=outcome layer=none failure=append_lock_timeout"
	log := `{"event":"error","error":"` + intent + `"}` + "\n" + `{"event":"error","error":"` + outcome + `"}` + "\n"
	if err := os.WriteFile(filepath.Join(dirs.root, "proxy.log"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	var integrity integrityReport
	failOnAuditGaps(&integrity, dirs, false)
	if !hasReason(integrity.Reasons, "proxy reported 2 audit gap(s); first:") {
		t.Fatalf("integrity did not count both gaps: %q", integrity.Reasons)
	}
	for _, message := range []string{intent, outcome} {
		if !hasReason(integrity.Reasons, message) {
			t.Fatalf("sample %q missing from printed reasons: %q", message, integrity.Reasons)
		}
	}
}

func TestAuditGapFailureSamples(t *testing.T) {
	dirs := newRunDirs(t.TempDir())
	var log strings.Builder
	labels := []string{"other", "append_lock_timeout", "content_rejected", "content_changed", "scan_incomplete", "chain_sealed"}
	for _, label := range labels {
		// Repeated symptoms must not fill the sample before a different
		// underlying failure appears. Every occurrence still counts.
		line := `{"event":"error","request_id":"private-context","error":"event=receipt_channel_broken audit_gap=true verdict=allow phase=intent layer=none failure=` + label + `"}` + "\n"
		log.WriteString(strings.Repeat(line, 10))
	}
	if err := os.WriteFile(filepath.Join(dirs.root, "proxy.log"), []byte(log.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	var integrity integrityReport
	failOnAuditGaps(&integrity, dirs, false)
	if integrity.Verdict != verdictFail || len(integrity.Reasons) != maxAuditGapLines || !hasReason(integrity.Reasons, "proxy reported 60 audit gap(s); first:") {
		t.Fatalf("integrity did not retain the gap count and bounded samples: %+v", integrity)
	}
	for _, label := range labels[:maxAuditGapLines] {
		if !hasReason(integrity.Reasons, "failure="+label) {
			t.Fatalf("failure class %q missing from printed reasons: %q", label, integrity.Reasons)
		}
	}
	if hasReason(integrity.Reasons, "private-context") || hasReason(integrity.Reasons, "chain_sealed") {
		t.Fatalf("samples included context or exceeded their bound: %q", integrity.Reasons)
	}
}

// A malformed record neither hides gaps found before it nor stops the scan
// from finding gaps after it; the decode error comes back with them.
func TestAuditGapLinesKeepsGapsAroundBadRecords(t *testing.T) {
	gap := `{"event":"error","error":"event=receipt_channel_broken audit_gap=true phase=outcome"}` + "\n"
	path := filepath.Join(t.TempDir(), "proxy.log")
	if err := os.WriteFile(path, []byte(gap+"{not json\n"+gap), 0o600); err != nil {
		t.Fatal(err)
	}
	count, lines, err := auditGapLines(path)
	if err == nil || count != 2 || len(lines) != 1 {
		t.Fatalf("count=%d lines=%d error=%v, want both gaps counted, one distinct sample and the decode error", count, len(lines), err)
	}
	path = filepath.Join(t.TempDir(), "proxy.log")
	if err := os.WriteFile(path, []byte(gap+strings.Repeat("x", 70*1024)), 0o600); err != nil {
		t.Fatal(err)
	}
	count, lines, err = auditGapLines(path)
	if err == nil || count != 1 || len(lines) != 1 || !strings.Contains(err.Error(), "scan proxy log") {
		t.Fatalf("count=%d lines=%d error=%v, want the gap before the oversized line and the scan error", count, len(lines), err)
	}
	// A malformed record and then an oversized line return both errors.
	path = filepath.Join(t.TempDir(), "proxy.log")
	if err := os.WriteFile(path, []byte(gap+"{not json\n"+strings.Repeat("x", 70*1024)), 0o600); err != nil {
		t.Fatal(err)
	}
	count, lines, err = auditGapLines(path)
	if err == nil || count != 1 || len(lines) != 1 ||
		!strings.Contains(err.Error(), "decode proxy audit log") || !strings.Contains(err.Error(), "scan proxy log") {
		t.Fatalf("count=%d lines=%d error=%v, want the gap and both the decode and scan errors", count, len(lines), err)
	}
}

// A run that fails partway still reports the gaps the proxy logged before it
// failed, next to the run failure.
func TestFailedRunStillReportsAuditGaps(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "auditgap-restartfail"))
	opt.restartAfter = 17
	code := runModes(context.Background(), opt, []string{modeOff})
	got := readResult(t, filepath.Join(opt.out, modeOff))
	if code != exitIntegrity || !hasReason(got.Integrity.Reasons, "restart readiness") || !hasReason(got.Integrity.Reasons, "audit gap(s); first: event=receipt_channel_broken") {
		t.Fatalf("code=%d integrity=%+v", code, got.Integrity)
	}
}
