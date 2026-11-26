// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"syscall/js"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

var errV3BrowserBound = errors.New("v3 input exceeds browser verification bounds")

// verifyReceiptV3 takes a name-to-Uint8Array object and receipt caller options.
// It returns canonical JSON with a terminal LF, or an object with an error field for usage errors.
func verifyReceiptV3(_ js.Value, args []js.Value) (reply any) {
	defer func() {
		if failure := recover(); failure != nil {
			reply = v3BrowserError(fmt.Errorf("verify v3 receipt: %v", failure))
		}
	}()
	if len(args) < 2 || len(args) > 3 {
		return v3BrowserError(errors.New("expected named files, receipt options, and optional output mode"))
	}
	output := "result"
	if len(args) == 3 {
		output = args[2].String()
		if !v3.IsV3Output(output) {
			return v3BrowserError(errors.New("output must be result or projection"))
		}
	}
	files, keys, err := v3NamedFiles(args[0])
	if err != nil {
		return v3BrowserError(err)
	}
	var caller v3.CallerOptions
	raw := js.Global().Get("JSON").Call("stringify", args[1])
	if err := json.Unmarshal([]byte(raw.String()), &caller); err != nil {
		return v3BrowserError(fmt.Errorf("decode receipt options: %w", err))
	}
	opts, err := caller.Parse(keys.Length())
	if err != nil {
		return v3BrowserError(err)
	}
	result, err := verifyNamedV3(files, keys, opts)
	if err != nil {
		return v3BrowserError(err)
	}
	data, err := result.ResultBytes(output)
	if err != nil {
		return v3BrowserError(err)
	}
	return string(data)
}

func verifyNamedV3(files, keys js.Value, opts v3.Options) (v3.Result, error) {
	paths, cleanup, err := mountNamedV3(files, keys)
	if errors.Is(err, errV3BrowserBound) {
		return v3.UseHostVerifier(opts), nil
	}
	if err != nil {
		return v3.Result{}, err
	}
	defer cleanup()
	if opts.Directory {
		paths = paths[:1]
	} else {
		paths = paths[1:]
	}
	return v3.VerifyPaths(context.Background(), paths, opts)
}

func claimsReceiptV3(_ js.Value, args []js.Value) (reply any) {
	defer func() {
		if failure := recover(); failure != nil {
			reply = v3BrowserError(fmt.Errorf("inspect v3 receipt: %v", failure))
		}
	}()
	if len(args) != 1 {
		return v3BrowserError(errors.New("expected one named file"))
	}
	files, keys, err := v3NamedFiles(args[0])
	if err != nil {
		return v3BrowserError(err)
	}
	if keys.Length() != 1 {
		return v3BrowserError(errors.New("expected one named file"))
	}
	paths, cleanup, err := mountNamedV3(files, keys)
	if err != nil {
		return v3BrowserError(err)
	}
	defer cleanup()
	claimed, err := v3.ClaimsInput(paths[1], false)
	if err != nil {
		return v3BrowserError(err)
	}
	return claimed
}

func v3BrowserError(err error) js.Value {
	return js.ValueOf(map[string]any{"error": err.Error()})
}

func v3NamedFiles(files js.Value) (js.Value, js.Value, error) {
	if files.Type() != js.TypeObject || files.IsNull() || js.Global().Get("Array").Call("isArray", files).Bool() {
		return js.Value{}, js.Value{}, errors.New("expected an object containing named files")
	}
	return files, js.Global().Get("Object").Call("keys", files), nil
}

func mountNamedV3(files, keys js.Value) ([]string, func(), error) {
	// Named files are already expanded. The archive entry, count and total
	// bounds apply here, and the compressed ZIP bound belongs to ZIP readers.
	if keys.Length() > maxReceiptGroupArchiveFiles {
		return nil, nil, errV3BrowserBound
	}
	mount := js.Global().Get("pipelockMountReceiptGroup")
	unmount := js.Global().Get("pipelockUnmountReceiptGroup")
	if mount.Type() != js.TypeFunction || unmount.Type() != js.TypeFunction {
		return nil, nil, errors.New("in-memory receipt filesystem is unavailable")
	}
	object := js.Global().Get("Object")
	entries := object.Call("create", js.Null())
	byteArray := js.Global().Get("Uint8Array")
	typedArray := object.Call("getPrototypeOf", byteArray.Get("prototype"))
	byteLength := object.Call("getOwnPropertyDescriptor", typedArray, "byteLength").Get("get")
	names := make([]string, 0, keys.Length())
	total := 0
	for i := range keys.Length() {
		name := keys.Index(i).String()
		if !safeReceiptArchiveName(name) || strings.HasSuffix(name, "/") {
			return nil, nil, fmt.Errorf("unsafe named evidence path %q", name)
		}
		value := files.Get(name)
		if value.Type() != js.TypeObject || !value.InstanceOf(byteArray) {
			return nil, nil, fmt.Errorf("named evidence %q must contain Uint8Array bytes", name)
		}
		length := byteLength.Call("call", value).Float()
		if length > maxReceiptGroupArchiveEntrySize || length > float64(maxReceiptGroupArchiveTotalSize-total) {
			return nil, nil, errV3BrowserBound
		}
		total += int(length)
		names = append(names, name)
		entries.Set(name, value)
	}
	for _, name := range names {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if !entries.Get(parent).IsUndefined() {
				return nil, nil, fmt.Errorf("named evidence %q is also a parent directory", parent)
			}
		}
	}
	root, err := os.MkdirTemp("", "pipelock-receipt-v3-")
	if err != nil {
		return nil, nil, fmt.Errorf("create in-memory v3 receipt root: %w", err)
	}
	// Unmount directly from the private filesystem even on a partial mount.
	mounted := false
	cleanup := func() { unmount.Invoke(root) }
	defer func() {
		if !mounted {
			cleanup()
		}
	}()
	mount.Invoke(root, entries)
	paths := make([]string, 1, len(names)+1)
	paths[0] = root
	for _, name := range names {
		paths = append(paths, path.Join(root, name))
	}
	mounted = true
	return paths, cleanup, nil
}
