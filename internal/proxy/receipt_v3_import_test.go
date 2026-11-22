// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestV3WriterOnlyThroughProxyAdapter(t *testing.T) {
	files := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || path == "receipt_v3.go" {
			return nil
		}
		parsed, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if importPath == "github.com/luckyPipewrench/pipelock/internal/receipt/v3" {
				t.Errorf("%s imports receipt v3 outside the proxy adapter", files.Position(spec.Pos()))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
