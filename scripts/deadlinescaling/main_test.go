// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, src string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture_test.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func violations(t *testing.T, src string) []finding {
	t.Helper()
	path := writeFixture(t, src)
	got, err := analyze([]string{path})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	return got
}

func argText(t *testing.T, src string, f finding) string {
	t.Helper()
	if f.start < 0 || f.end > len(src) || f.start > f.end {
		t.Fatalf("offsets %d:%d outside fixture", f.start, f.end)
	}
	return src[f.start:f.end]
}

func TestAnalyzeFailingWaits(t *testing.T) {
	t.Parallel()
	const head = `package p

import (
	"testing"
	"time"
)
`
	tests := []struct {
		name string
		src  string
		want int
		arg  string
	}{
		{
			name: "inline raw failing wait",
			src: head + `func TestA(t *testing.T) {
	select {
	case <-time.After(time.Second):
		t.Fatal("expired")
	}
}
`,
			want: 1,
			arg:  "time.Second",
		},
		{
			name: "deadline form",
			src: head + `import "github.com/luckyPipewrench/pipelock/internal/testwait"

func TestA(t *testing.T) {
	select {
	case <-time.After(testwait.Deadline(time.Second)):
		t.Fatal("expired")
	}
}
`,
			want: 0,
		},
		{
			name: "aliased testwait import",
			src: `package p

import (
	"testing"
	"time"

	tw "github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestA(t *testing.T) {
	select {
	case <-time.After(tw.Deadline(time.Second)):
		t.Fatal("expired")
	}
}
`,
			want: 0,
		},
		{
			name: "empty absence case",
			src: head + `func TestA(t *testing.T) {
	select {
	case <-time.After(time.Second):
	default:
	}
}
`,
			want: 0,
		},
		{
			name: "non-failing body",
			src: head + `func TestA(t *testing.T) {
	timedOut := false
	select {
	case <-time.After(time.Second):
		timedOut = true
	default:
	}
	_ = timedOut
}
`,
			want: 0,
		},
		{
			name: "fatal on the other case",
			src: head + `func TestA(t *testing.T) {
	ctx := t.Context()
	select {
	case <-time.After(time.Millisecond):
	case <-ctx.Done():
		t.Fatal("ctx canceled during poll")
	}
}
`,
			want: 0,
		},
		{
			name: "assigned after channel",
			src: head + `func TestA(t *testing.T) {
	deadline := time.After(time.Second)
	select {
	case <-deadline:
		t.Fatal("expired")
	}
}
`,
			want: 1,
			arg:  "time.Second",
		},
		{
			name: "new timer channel",
			src: head + `func TestA(t *testing.T) {
	timer := time.NewTimer(time.Second)
	select {
	case <-timer.C:
		t.Fatalf("expired")
	}
}
`,
			want: 1,
			arg:  "time.Second",
		},
		{
			name: "failure only inside a nested function",
			src: head + `func TestA(t *testing.T) {
	select {
	case <-time.After(time.Second):
		go func() { t.Fatal("later") }()
	}
	go func() {
		select {
		case <-time.After(2 * time.Second):
			t.Fatal("expired")
		}
	}()
}
`,
			want: 1,
			arg:  "2 * time.Second",
		},
		{
			name: "require fail now",
			src: `package p

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestA(t *testing.T) {
	select {
	case <-time.After(time.Second):
		require.FailNow(t, "expired")
	}
}
`,
			want: 1,
			arg:  "time.Second",
		},
		{
			name: "assert fail",
			src: `package p

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestA(t *testing.T) {
	select {
	case <-time.After(time.Second):
		assert.Fail(t, "expired")
	}
}
`,
			want: 1,
			arg:  "time.Second",
		},
		{
			name: "duration identifier already scaled",
			src: `package p

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestA(t *testing.T) {
	d := testwait.Deadline(time.Second)
	select {
	case <-time.After(d):
		t.Fatal("expired")
	}
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := violations(t, tt.src)
			if len(got) != tt.want {
				t.Fatalf("findings = %d, want %d", len(got), tt.want)
			}
			if tt.arg == "" {
				return
			}
			if text := argText(t, tt.src, got[0]); text != tt.arg {
				t.Fatalf("duration = %q, want %q", text, tt.arg)
			}
		})
	}
}

func TestParseErrorExit(t *testing.T) {
	t.Parallel()
	path := writeFixture(t, "package p\nfunc (\n")
	var stdout, stderr bytes.Buffer
	if code := run([]string{path}, &stdout, &stderr); code == 0 {
		t.Fatalf("exit = 0, want non-zero\n%s", stderr.String())
	}
}

func TestParseErrorProcessExit(t *testing.T) {
	if os.Getenv("PIPELOCK_DEADLINE_CHILD") == "1" {
		os.Exit(run([]string{os.Getenv("PIPELOCK_DEADLINE_FILE")}, os.Stdout, os.Stderr))
	}
	path := writeFixture(t, "package p\nfunc (\n")
	// #nosec G204 G702 -- os.Args[0] is this test binary, re-execed to observe os.Exit.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestParseErrorProcessExit$")
	cmd.Env = append(os.Environ(), "PIPELOCK_DEADLINE_CHILD=1", "PIPELOCK_DEADLINE_FILE="+path)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
		t.Fatalf("process exit = %v, want non-zero", err)
	}
}

func TestEmptyScanRefuses(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code == 0 {
		t.Fatal("exit = 0, want non-zero")
	}
}

func TestFixWrapsAndImports(t *testing.T) {
	t.Parallel()
	path := writeFixture(t, `package p

import (
	"testing"
	"time"
)

func TestA(t *testing.T) {
	select {
	case <-time.After(time.Second):
		t.Fatal("expired")
	}
}
`)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-fix", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("fix exit = %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	// #nosec G304 -- path is the temp fixture this test just wrote.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("testwait.Deadline(time.Second)")) {
		t.Fatalf("duration was not wrapped:\n%s", got)
	}
	if !bytes.Contains(got, []byte(`"github.com/luckyPipewrench/pipelock/internal/testwait"`)) {
		t.Fatalf("import was not added:\n%s", got)
	}
	left, err := analyze([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("findings after fix = %d", len(left))
	}
}

func TestFixSkipsLocalTestwaitName(t *testing.T) {
	t.Parallel()
	src := `package p

import (
	"testing"
	"time"
)

func TestA(t *testing.T) {
	testwait := time.Second
	select {
	case <-time.After(testwait):
		t.Fatal("expired")
	}
}
`
	path := writeFixture(t, src)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-fix", path}, &stdout, &stderr); code == 0 {
		t.Fatalf("fix exit = 0, want skip\n%s", stderr.String())
	}
	// #nosec G304 -- path is the temp fixture this test just wrote.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != src {
		t.Fatalf("file changed:\n%s", got)
	}
}
