// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateCore = flag.Bool("update-core-projections", false, "generate core projections")

func TestCoreProjections(t *testing.T) {
	root := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "v3")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		vector := filepath.Join(root, entry.Name())
		raw, err := os.ReadFile(filepath.Clean(filepath.Join(vector, "request.json")))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var request struct {
			CallerOptions
			Inputs []string `json:"inputs"`
			Legacy bool     `json:"legacy"`
		}
		if err := json.Unmarshal(raw, &request); err != nil {
			t.Fatal(err)
		}
		if request.Legacy {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			opts, err := request.Parse(len(request.Inputs))
			if err != nil {
				t.Fatal(err)
			}
			paths := make([]string, 0, len(request.Inputs))
			for _, name := range request.Inputs {
				paths = append(paths, filepath.Join(vector, name))
			}
			if opts.Directory {
				dir := t.TempDir()
				for _, name := range request.Inputs {
					source := filepath.Join(vector, name)
					target := filepath.Join(dir, name)
					if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
						t.Fatal(err)
					}
					contents, err := os.ReadFile(filepath.Clean(source))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(target, contents, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				paths = []string{dir}
			}
			result, err := verifyCorePaths(t.Context(), paths, opts)
			if err != nil {
				t.Fatal(err)
			}
			projected, err := result.Projection()
			if err != nil {
				t.Fatal(err)
			}
			projected = append(projected, '\n')
			normal, err := os.ReadFile(filepath.Clean(filepath.Join(vector, "projection.json")))
			if err != nil {
				t.Fatal(err)
			}
			corePath := filepath.Join(vector, "projection.core.json")
			if *updateCore {
				if bytes.Equal(normal, projected) {
					if err := os.Remove(corePath); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(corePath, projected, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			expected, err := os.ReadFile(filepath.Clean(corePath))
			if os.IsNotExist(err) {
				expected = normal
			} else if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(projected, expected) {
				t.Fatalf("core projection differs: got %s want %s", projected, expected)
			}
			if bytes.Equal(projected, normal) && !bytes.Equal(expected, normal) {
				t.Fatal("redundant core projection")
			}
		})
	}
}
