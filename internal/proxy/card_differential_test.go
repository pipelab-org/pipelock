// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cardcorpus"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	cardMainRevision = "a689c65b1e911029f1e834efd1559199af36053a"
	cardMainGolden   = "testdata/card-main-a689c65b1.jsonl.gz"
)

// cardRaceStride thins the corpus under the race detector. The full corpus
// runs in normal builds, where the oracle's coverage lives. Under -race the
// test checks the scanner workers for data races. Every 17th case still
// covers each family, context, separator, and family-context and
// context-separator pair, and stays under the per-test time ceiling. A
// stride of 16 lines up with the 16 separators and misses pairs.
const cardRaceStride = 17

// cardCaseChecked reports whether case i runs in this build. Recording a
// golden always uses the full corpus.
func cardCaseChecked(i int) bool {
	return !raceEnabled || *recordCardMain != "" || i%cardRaceStride == 0
}

var recordCardMain = flag.String("card-record-main", "", "write main oracle to this path (requires a detached checkout of the pinned main revision)")

type (
	cardOracleHeader struct {
		Revision, CorpusSHA256 string
		Cases                  int
	}
	cardOracleRow struct {
		ID      string
		Verdict uint8
	}
)

func cardCorpusHash(cases []cardcorpus.Case) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, c := range cases {
		if err := enc.Encode(c); err != nil {
			panic(err)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func cardOracleVerdicts(t *testing.T, cases []cardcorpus.Case) []uint8 {
	return cardOracleVerdictsWithAction(t, cases, config.ActionBlock)
}

func cardOracleVerdictsWithAction(t *testing.T, cases []cardcorpus.Case, action string) []uint8 {
	t.Helper()
	cfg := config.Defaults()
	cfg.DLP.CardBareAction = action
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	// Keep the shipped card rule from each checkout, including its validator and
	// provenance. Other credential patterns and injection/entropy are orthogonal.
	var cards []config.DLPPattern
	for _, p := range cfg.DLP.Patterns {
		if p.Name == "Credit Card Number" {
			cards = append(cards, p)
		}
	}
	if len(cards) != 1 {
		t.Fatal("missing shipped card rule")
	}
	cfg.DLP.Patterns = cards
	cfg.ResponseScanning.Enabled = false
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold = 0
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 0
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	matcher := redact.NewDefaultMatcher()
	out := make([]uint8, len(cases))
	jobs := make(chan int)
	errors := make(chan string, 2*len(cases))
	var wg sync.WaitGroup
	for range min(8, runtime.GOMAXPROCS(0)) {
		wg.Go(func() {
			for i := range jobs {
				c := cases[i]
				ctx := t.Context()
				text := sc.ScanTextForDLP(ctx, c.Text)
				if text.Incomplete {
					errors <- fmt.Sprintf("%s incomplete text scan", c.ID)
				}
				for _, m := range text.Matches {
					if !m.Warn {
						out[i] |= 1
						break
					}
				}
				_, body := scanRequestBody(ctx, BodyScanRequest{Body: strings.NewReader(c.JSON), ContentType: contentTypeJSON, MaxBytes: 1 << 20, Scanner: sc, Action: config.ActionBlock, Host: "api.vendor.example"})
				if body.ScanError != "" {
					errors <- fmt.Sprintf("%s body scan error: %s", c.ID, body.ScanError)
				}
				if !body.Clean && body.Action == config.ActionBlock {
					out[i] |= 2
				}
				if result := sc.Scan(ctx, c.URL); !result.Allowed {
					out[i] |= 4
				}
				if len(matcher.Scan(c.Text)) > 0 {
					out[i] |= 8
				}
			}
		})
	}
	for i := range cases {
		if cardCaseChecked(i) {
			jobs <- i
		}
	}
	close(jobs)
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	return out
}

func TestCardMainDifferential(t *testing.T) {
	started := time.Now()
	cases := cardcorpus.Cases()
	if cardcorpus.PartitionCount(15) != 4096 || cardcorpus.PartitionCount(16) != 4096 {
		t.Fatal("composition sample collapsed")
	}
	header := cardOracleHeader{cardMainRevision, cardCorpusHash(cases), len(cases)}
	got := cardOracleVerdicts(t, cases)
	checkCardShippedBaseline(t, cases, got)
	warn := cardOracleVerdictsWithAction(t, cases, config.ActionWarn)
	for i, c := range cases {
		if !cardCaseChecked(i) {
			continue
		}
		for surface, name := range []string{"text", "json-body", "url", "redact"} {
			bit := uint8(1 << surface)
			if got[i]&bit != 0 && warn[i]&bit == 0 {
				input := []string{c.Text, c.JSON, c.URL, c.Text}[surface]
				if !cardcorpus.AllowedBareWarning(name, input) {
					t.Errorf("unapproved warn loss %s %s: %q", name, c.ID, input)
				}
			}
		}
	}
	if *recordCardMain != "" {
		head, err := cardCheckoutHead()
		if err != nil || head != cardMainRevision {
			t.Fatalf("golden must be recorded from a detached checkout of %s: head %q, %v", cardMainRevision, head, err)
		}
		f, err := os.OpenFile(filepath.Clean(*recordCardMain), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		z := gzip.NewWriter(f)
		enc := json.NewEncoder(z)
		if err := enc.Encode(header); err != nil {
			t.Fatal(err)
		}
		for i, c := range cases {
			if err := enc.Encode(cardOracleRow{c.ID, got[i]}); err != nil {
				t.Fatal(err)
			}
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		t.Logf("recorded %d cases from %s, corpus sha256 %s in %s", len(cases), cardMainRevision, header.CorpusSHA256, time.Since(started))
		return
	}
	f, err := os.Open(cardMainGolden)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = z.Close() }()
	dec := json.NewDecoder(z)
	var wantHeader cardOracleHeader
	if err := dec.Decode(&wantHeader); err != nil {
		t.Fatal(err)
	}
	if wantHeader != header {
		t.Fatalf("golden corpus/provenance mismatch: got %+v want %+v; regenerate only against pinned main", wantHeader, header)
	}
	totals := map[string]int{}
	details := map[string]int{}
	failures := 0
	for i, c := range cases {
		var row cardOracleRow
		if err := dec.Decode(&row); err != nil {
			t.Fatal(err)
		}
		if row.ID != c.ID {
			t.Fatalf("golden row %d has id %s", i, row.ID)
		}
		if !cardCaseChecked(i) {
			continue
		}
		for surface, name := range []string{"text", "json-body", "url", "redact"} {
			bit := uint8(1 << surface)
			before, after := row.Verdict&bit != 0, got[i]&bit != 0
			direction := "pass->pass"
			if before && after {
				direction = "block->block"
			} else if before {
				direction = "block->pass"
			} else if after {
				direction = "pass->block"
			}
			totals[name+" "+direction]++
			if before && !after {
				input := []string{c.Text, c.JSON, c.URL, c.Text}[surface]
				allowed := cardcorpus.AllowedLoss(name, input)
				if allowed == "" {
					failures++
					details[name+" unapproved/"+c.Context+"/"+strconv.Quote(c.Separator)]++
					if failures <= 25 {
						t.Errorf("unapproved %s loss case=%s family=%s sep=%q context=%s presentation=%q text=%q", name, c.ID, c.Family, c.Separator, c.Context, c.Value, c.Text)
					}
				} else {
					details[name+" loss/"+allowed]++
				}
			}
			if !before && after {
				details[name+" added/"+c.Category()]++
			}
		}
	}
	var extra cardOracleRow
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("trailing golden content: %v", err)
	}
	keys := make([]string, 0, len(totals)+len(details))
	for k := range totals {
		keys = append(keys, k)
	}
	for k := range details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("transition %s: %d", k, totals[k]+details[k])
	}
	if raceEnabled {
		t.Logf("race build: checked every %dth case", cardRaceStride)
	}
	t.Logf("corpus=%d unapproved-losses=%d elapsed=%s sha256=%s", len(cases), failures, time.Since(started), header.CorpusSHA256)
	if failures > 0 {
		t.Fatalf("%d unapproved main-to-branch losses", failures)
	}
}

// cardCheckoutHead reads HEAD from the enclosing Git checkout without running
// another program, so this package keeps ordinary test caching.
func cardCheckoutHead() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		dotGit := filepath.Join(dir, ".git")
		info, statErr := os.Stat(dotGit)
		if statErr == nil {
			gitDir := dotGit
			if !info.IsDir() {
				pointer, readErr := os.ReadFile(filepath.Clean(dotGit))
				if readErr != nil {
					return "", readErr
				}
				target, ok := strings.CutPrefix(strings.TrimSpace(string(pointer)), "gitdir: ")
				if !ok {
					return "", fmt.Errorf("unrecognized .git file in %s", dir)
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(dir, target)
				}
				gitDir = target
			}
			head, readErr := os.ReadFile(filepath.Clean(filepath.Join(gitDir, "HEAD")))
			return strings.TrimSpace(string(head)), readErr
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no Git checkout above the test directory")
		}
		dir = parent
	}
}

// checkCardShippedBaseline pins the shipped presentation floor separately from the
// earlier migration oracle. Policy changes permit no new default-config passes.
func checkCardShippedBaseline(t *testing.T, cases []cardcorpus.Case, got []uint8) {
	t.Helper()
	f, err := os.Open("testdata/card-main-98a06a950.jsonl.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = z.Close() }()
	dec := json.NewDecoder(z)
	var header cardOracleHeader
	if err := dec.Decode(&header); err != nil {
		t.Fatal(err)
	}
	if header.Revision != "98a06a950aa398d16817d09060d1c0d0f6ba2e5e" || header.CorpusSHA256 != cardCorpusHash(cases) || header.Cases != len(cases) {
		t.Fatalf("invalid shipped baseline: %+v", header)
	}
	for i, c := range cases {
		var row cardOracleRow
		if err := dec.Decode(&row); err != nil {
			t.Fatal(err)
		}
		if row.ID != c.ID {
			t.Fatalf("baseline row %d id %s", i, row.ID)
		}
		if !cardCaseChecked(i) {
			continue
		}
		if lost := row.Verdict &^ got[i]; lost != 0 {
			t.Errorf("new default pass vs shipped main: %s surfaces=%04b text=%q", c.ID, lost, c.Text)
		}
	}
	var extra cardOracleRow
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("trailing baseline data: %v", err)
	}
}
