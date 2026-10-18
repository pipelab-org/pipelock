// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func hostileSplitHexInputs() map[string]string {
	const size = 1 << 20
	return map[string]string{
		"two-char pieces":   strings.Repeat("ab ", size/3),
		"four-char pieces":  strings.Repeat("abcd ", size/5),
		"eight-char pieces": strings.Repeat("0123abcd\n", size/9),
		"long pieces":       strings.Repeat(strings.Repeat("deadbeef", 8)+",", size/65),
	}
}

func splitHexKey() string { return hex.EncodeToString([]byte("AKIA" + "IOSFODNN7" + "EXAMPLQ")) }

func splitInto(s string, n int) string {
	var parts []string
	for len(s) > n {
		parts = append(parts, s[:n])
		s = s[n:]
	}
	return strings.Join(append(parts, s), " ")
}

// Decoy hex ahead of a split credential must not hide it: no budget or
// window limit exists to exhaust.
func TestScanTextForDLP_SplitHexAfterDecoys(t *testing.T) {
	s := MustNew(config.Defaults())
	defer s.Close()
	h := splitHexKey()
	for _, kib := range []int{8, 64, 512} {
		decoy := strings.Repeat("deadbeef ", kib*1024/9)
		text := decoy + h[:20] + " " + h[20:] + "\ndone"
		if r := s.ScanTextForDLP(context.Background(), text); r.Clean {
			t.Errorf("split key after %d KiB of decoy hex not detected", kib)
		}
	}
}

// Any piece length works, including pieces shorter than a byte pair.
func TestScanTextForDLP_SplitHexShortPieces(t *testing.T) {
	s := MustNew(config.Defaults())
	defer s.Close()
	h := splitHexKey()
	for _, n := range []int{2, 3, 4, 5, 7} {
		text := "note: " + splitInto(h, n) + " end"
		if r := s.ScanTextForDLP(context.Background(), text); r.Clean {
			t.Errorf("key split into %d-char pieces not detected", n)
		}
	}
}

// Wall-clock guard on the whole text DLP scan of 1 MiB hostile hex. The
// limit is loose for slow runners; an unbounded split pass took over 15 s.
func TestScanTextForDLP_HostileSplitHexScanTime(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing test; the race detector slows the scan several times over")
	}
	s := MustNew(config.Defaults())
	defer s.Close()
	for name, text := range hostileSplitHexInputs() {
		start := time.Now()
		_ = s.ScanTextForDLP(context.Background(), text)
		elapsed := time.Since(start)
		t.Logf("%s: %v", name, elapsed)
		if elapsed > 6*time.Second {
			t.Errorf("%s: scan took %v", name, elapsed)
		}
	}
}

// Hex identifiers next to each other (commit ids, digests, UUID parts) must
// not produce findings through the split-hex pass.
func TestScanTextForDLP_AdjacentHexIdentifiersClean(t *testing.T) {
	s := MustNew(config.Defaults())
	defer s.Close()
	// Deterministic pseudo-random bytes from a hash chain.
	state := sha256.Sum256([]byte("split-hex-identifiers"))
	hexOf := func(n int) string {
		var out []byte
		for len(out) < n {
			state = sha256.Sum256(state[:])
			out = append(out, state[:]...)
		}
		return hex.EncodeToString(out[:n])
	}
	var sb strings.Builder
	for range 2000 {
		fmt.Fprintf(&sb, "%s %s\n", hexOf(20), hexOf(4))
		u := hexOf(16)
		fmt.Fprintf(&sb, "%s-%s-%s-%s-%s\n", u[:8], u[8:12], u[12:16], u[16:20], u[20:])
		fmt.Fprintf(&sb, "sha256 %s md5 %s\n", hexOf(32), hexOf(16))
	}
	if r := s.ScanTextForDLP(context.Background(), sb.String()); !r.Clean {
		t.Fatalf("adjacent hex identifiers flagged: %+v", r.Matches)
	}
}
