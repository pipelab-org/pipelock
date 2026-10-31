// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func findingLines(t *testing.T, src string) []int {
	t.Helper()
	out, err := analyze([]string{writeFixture(t, src)})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	lines := make([]int, 0, len(out))
	for _, f := range out {
		lines = append(lines, f.line)
	}
	return lines
}

func TestAnalyzeFindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		want []int
	}{
		{
			name: "same-name methods retain the stopping declaration",
			src: `package x
type first struct{}
type second struct{}
func (first) wait(t *testing.T, errCh <-chan error) {
	select { case err := <-errCh: t.Fatal(err) }
}
func (second) wait(t *testing.T, errCh <-chan error) {}
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		first{}.wait(t, errCh)
		return nil
	})
}
`,
			want: []int{10},
		},
		{
			name: "fatal on run exit receive",
			src: `package x
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		select {
		case err := <-errCh:
			t.Fatalf("exited: %v", err)
		case <-ready:
		}
		return nil
	})
}
`,
			want: []int{6},
		},
		{
			name: "fatal on a function-returned run exit channel",
			src: `package x
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		select {
		case err := <-exitErrs():
			t.Fatalf("exited: %v", err)
		case <-ready:
		}
		return nil
	})
}
`,
			want: []int{6},
		},
		{
			name: "returned run exit error",
			src: `package x
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		select {
		case err := <-errCh:
			return err
		case <-ready:
		}
		return nil
	})
}
`,
		},
		{
			name: "timeout backstop may end the test",
			src: `package x
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		select {
		case <-ready:
		case <-time.After(time.Second):
			select {
			case err := <-errCh:
				t.Fatalf("timed out, then exited: %v", err)
			default:
			}
			t.Fatal("timed out")
		}
		return nil
	})
}
`,
		},
		{
			name: "helper ending the test on run exit",
			src: `package x
func awaitReady(t *testing.T, errCh <-chan error) {
	select {
	case err := <-errCh:
		t.Fatal(err)
	case <-ready:
	}
}
func middle(t *testing.T, errCh <-chan error) { awaitReady(t, errCh) }
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		middle(t, errCh)
		return nil
	})
}
`,
			want: []int{12},
		},
		{
			name: "fatal on an exit observer result in the if init",
			src: `package x
func observe(errCh <-chan error) error {
	select {
	case err := <-errCh:
		return err
	case <-ready:
	}
	return nil
}
func wrap(t *testing.T) {
	if err := observe(errCh); err != nil {
		t.Fatal(err)
	}
}
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		wrap(t)
		return nil
	})
}
`,
			want: []int{17},
		},
		{
			name: "fatal on an exit observer result assigned first",
			src: `package x
func observe(errCh <-chan error) error {
	select {
	case err := <-errCh:
		return err
	case <-ready:
	}
	return nil
}
func wrap(t *testing.T) {
	err := observe(errCh)
	if err != nil {
		t.Fatal(err)
	}
}
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		wrap(t)
		return nil
	})
}
`,
			want: []int{18},
		},
		{
			name: "unrelated fatal after an observer assignment",
			src: `package x
func observe(errCh <-chan error) error {
	select {
	case err := <-errCh:
		return err
	case <-ready:
	}
	return nil
}
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		err := observe(errCh)
		if other != nil {
			t.Fatal(other)
		}
		return err
	})
}
`,
		},
		{
			name: "upstream not excluded from readiness",
			src: `package x
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		upstream := httptest.NewServer(handler)
		defer upstream.Close()
		return waitForPortOrCommandExitResult(addrs[0], errCh, buf)
	})
}
`,
			want: []int{6},
		},
		{
			name: "upstream excluded from readiness",
			src: `package x
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		upstream := httptest.NewServer(handler)
		defer upstream.Close()
		return waitForPortOrCommandExitResult(addrs[0], errCh, buf, upstream)
	})
}
`,
		},
		{
			name: "helper with an unexcluded upstream",
			src: `package x
func scenario(addr string) error {
	upstream := httptest.NewServer(handler)
	defer upstream.Close()
	return waitForPortOrCommandExitResult(addr, errCh, buf)
}
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		return scenario(addrs[0])
	})
}
`,
			want: []int{9},
		},
		{
			name: "fatal outside any retry callback",
			src: `package x
func TestA(t *testing.T) {
	select {
	case err := <-errCh:
		t.Fatal(err)
	case <-ready:
	}
}
`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := findingLines(t, tc.src)
			if len(got) != len(tc.want) {
				t.Fatalf("finding lines = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("finding lines = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestRunExitStatus(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if got := run(nil, &stdout, &stderr); got != 2 {
		t.Fatalf("run without files = %d, want 2", got)
	}

	broken := writeFixture(t, "package x\nfunc (\n")
	stderr.Reset()
	if got := run([]string{broken}, &stdout, &stderr); got != 2 {
		t.Fatalf("run on a parse error = %d, want 2", got)
	}
	if !strings.Contains(stderr.String(), "parse ") {
		t.Fatalf("parse error stderr = %q", stderr.String())
	}

	clean := writeFixture(t, "package x\n")
	if got := run([]string{clean, "notes.txt"}, &stdout, &stderr); got != 0 {
		t.Fatalf("run on a clean file = %d, want 0", got)
	}

	bad := writeFixture(t, `package x
func TestA(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-ready:
		}
		return nil
	})
}
`)
	stdout.Reset()
	if got := run([]string{bad}, &stdout, &stderr); got != 1 {
		t.Fatalf("run on a finding = %d, want 1", got)
	}
	want := bad + ":6:\t\t\trequire.NoError(t, err)\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}

// TestRetryShapes runs the analyzer over testdata/retry_shapes.go.txt and
// checks that it reports exactly the lines marked "// want".
func TestRetryShapes(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile(filepath.Join("testdata", "retry_shapes.go.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var want []int
	for i, line := range strings.Split(string(src), "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), "// want") {
			want = append(want, i+1)
		}
	}
	if len(want) == 0 {
		t.Fatal("fixture has no want markers")
	}
	got := findingLines(t, string(src))
	if !slices.Equal(got, want) {
		t.Fatalf("finding lines = %v, want %v", got, want)
	}
}
