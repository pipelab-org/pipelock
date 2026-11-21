// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// BenchmarkTextDLPThroughput measures inbound text DLP on large bodies, the
// path an MCP media response or download takes. It includes prose, short
// lines, JSON with encoded blobs, API records, service logs, Go source, and
// Markdown.
//
// It uses only the scanner's exported API, so scripts/bench_throughput_gate.py
// can run this exact file against an older base commit and compare the two on
// one runner.
func BenchmarkTextDLPThroughput(b *testing.B) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	b.Cleanup(s.Close)
	shapes := []struct {
		name string
		text func(*testing.B) string
	}{
		{"prose/1MiB", func(*testing.B) string { return throughputBody("prose", 1<<20) }},
		{"short/1MiB", func(*testing.B) string { return throughputBody("short", 1<<20) }},
		{"b64json/1MiB", func(*testing.B) string { return throughputBody("b64json", 1<<20) }},
		{"json_api/1MiB", func(*testing.B) string { return throughputBody("json_api", 1<<20) }},
		{"log_lines/1MiB", func(*testing.B) string { return throughputBody("log_lines", 1<<20) }},
		{"go_source/1MiB", func(b *testing.B) string { return throughputGoSource(b, 1<<20) }},
		{"markdown/64KiB", func(b *testing.B) string { return throughputMarkdown(b, 64<<10) }},
	}
	for _, shape := range shapes {
		b.Run(shape.name, func(b *testing.B) {
			text := shape.text(b)
			if text == "" {
				b.Fatal("benchmark corpus is empty")
			}
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			for b.Loop() {
				ctx, release := scanner.WithSharedDecodes(scanner.WithInboundDirection(context.Background()))
				res := s.ScanTextForDLPInboundWithTypedCardView(ctx, text, text)
				release()
				if !res.Clean {
					b.Fatalf("benchmark input must scan clean: %+v", res.Matches)
				}
			}
		})
	}
}

func throughputToolchainFS(b testing.TB) fs.FS {
	b.Helper()
	goRoot, err := exec.CommandContext(b.Context(), "go", "env", "GOROOT").Output()
	if err != nil {
		b.Fatalf("locate Go toolchain: %v", err)
	}
	root, err := os.OpenRoot(strings.TrimSpace(string(goRoot)))
	if err != nil {
		b.Fatalf("open Go toolchain: %v", err)
	}
	b.Cleanup(func() {
		if err := root.Close(); err != nil {
			b.Errorf("close Go toolchain: %v", err)
		}
	})
	return root.FS()
}

// Both sides of the paired benchmark run with the same Go toolchain, so
// source from GOROOT keeps the corpus stable across checkout revisions.
func throughputGoSource(b testing.TB, size int) string {
	b.Helper()
	toolchain := throughputToolchainFS(b)
	var corpus strings.Builder
	for _, pkg := range []string{"net/http", "encoding/json", "net/url", "strings", "fmt", "time", "regexp", "math/big"} {
		dir := path.Join("src", pkg)
		files, err := fs.ReadDir(toolchain, dir)
		if err != nil {
			b.Fatal(err)
		}
		for _, file := range files {
			name := file.Name()
			if file.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			body, err := fs.ReadFile(toolchain, path.Join(dir, name))
			if err != nil {
				b.Fatal(err)
			}
			corpus.Write(body)
			corpus.WriteByte('\n')
			if corpus.Len() >= size {
				text := corpus.String()[:size]
				return text[:strings.LastIndexByte(text, '\n')+1]
			}
		}
	}
	b.Fatalf("Go source corpus is %d bytes, want at least %d", corpus.Len(), size)
	return ""
}

func throughputMarkdown(b testing.TB, size int) string {
	b.Helper()
	toolchain := throughputToolchainFS(b)
	var corpus strings.Builder
	for _, file := range []string{"src/cmd/compile/README.md", "src/cmd/compile/abi-internal.md", "src/runtime/HACKING.md"} {
		body, err := fs.ReadFile(toolchain, file)
		if err != nil {
			b.Fatal(err)
		}
		corpus.Write(body)
		corpus.WriteByte('\n')
		if corpus.Len() >= size {
			text := corpus.String()[:size]
			return text[:strings.LastIndexByte(text, '\n')+1]
		}
	}
	b.Fatalf("Markdown corpus is %d bytes, want at least %d", corpus.Len(), size)
	return ""
}

// throughputBody returns deterministic, credential-free text of about n bytes.
func throughputBody(shape string, n int) string {
	words := []string{"the", "agent", "reads", "a", "document", "about", "river", "pipes", "valve", "pressure", "and", "flow"}
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		switch shape {
		case "prose":
			b.WriteString(words[i%len(words)])
			if i%97 == 96 {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
		case "short":
			fmt.Fprintf(&b, "%s %s %d\n", words[i%len(words)], words[(i*7)%len(words)], i%1000)
		case "json_api":
			fmt.Fprintf(&b, `{"id":%d,"title":"River pressure report %d","url":"https://api.vendor.example/v2/items/%d?page=%d&sort=updated","size":%d,"tags":["pipes","flow","draft"],"active":%v}`+"\n",
				i, i, i, i%9, i%1000, i%2 == 0)
		case "log_lines":
			fmt.Fprintf(&b, "INFO service=inventory method=GET path=/v1/items/%d status=200 duration_ms=%d message=\"record loaded\"\n", i, i%500)
		case "b64json":
			// Distinct binary blobs derived from the record index. Each decodes to its own
			// view, which is what fills the scan's replay descriptor table on
			// large base64 bodies.
			raw := throughputBlob(i)
			fmt.Fprintf(&b, `{"id":%d,"blob":"%s","note":"%s"},`, i, base64.StdEncoding.EncodeToString(raw), words[i%len(words)])
		default:
			return ""
		}
	}
	return b.String()
}

// throughputBlob returns 64 to 400 bytes of fixed, record-specific binary data
// from a SHA-256 chain, so every run scans the same bytes.
func throughputBlob(i int) []byte {
	sum := sha256.Sum256([]byte(strconv.Itoa(i)))
	n := 64 + int(binary.BigEndian.Uint16(sum[:2])%337)
	raw := make([]byte, 0, n+sha256.Size)
	for len(raw) < n {
		sum = sha256.Sum256(sum[:])
		raw = append(raw, sum[:]...)
	}
	return raw[:n]
}
