// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
)

// Join containment's lifecycleExecStart typed command contract. The legacy
// tuple is documented in org.freedesktop.systemd1(5); upstream v249/v252
// src/core/dbus-execute.c:append_exec_ex_command replaces its ignore-failure
// boolean with all command flags. Checking Ex also rejects '+'/'!' credential
// overrides that the legacy tuple cannot express. The managed unit has no flags.
func observeInvocation(ctx context.Context, opts CheckOptions, b backend, s *snapshot, catalog map[string]string) error {
	if len(opts.ExpectedExecStart) == 0 || opts.ExpectedExecStart[0] != opts.Binary {
		return errors.New("invalid prospective invocation expectation")
	}
	for _, property := range []struct{ name, signature string }{
		{"ExecStart", "a(sasbttttuii)"}, {"ExecStartEx", "a(sasasttttuii)"},
	} {
		if catalog[property.name] != property.signature {
			return errors.New("required typed service invocation is unavailable")
		}
		raw, err := readProperty(ctx, b, unitObject, serviceInterface, property.name)
		if err != nil {
			return err
		}
		if err := matchInvocation(raw, property.signature, opts.ExpectedExecStart); err != nil {
			return err
		}
		s.Properties[property.name] = string(raw)
	}
	return nil
}

func matchInvocation(raw []byte, signature string, expected []string) error {
	var rows [][]json.RawMessage
	if decodeProperty(raw, signature, &rows) != nil || len(rows) != 1 || len(rows[0]) != 10 {
		return errors.New("invalid typed service invocation")
	}
	row := rows[0]
	var path string
	var argv []string
	if json.Unmarshal(row[0], &path) != nil || json.Unmarshal(row[1], &argv) != nil || path != expected[0] || !slices.Equal(argv, expected) {
		return errors.New("loaded pipelock.service invocation differs from the prospective command")
	}
	if signature == "a(sasbttttuii)" {
		if !bytes.Equal(bytes.TrimSpace(row[2]), []byte("false")) {
			return errors.New("loaded service command ignores failures")
		}
	} else {
		var flags []string
		if json.Unmarshal(row[2], &flags) != nil || !bytes.Equal(bytes.TrimSpace(row[2]), []byte("[]")) || len(flags) != 0 {
			return errors.New("loaded service command has unsupported execution flags")
		}
	}
	// Runtime fields are observed too, so a concurrent invocation change cannot
	// leave a successful validation bound to an older command observation.
	for i := 3; i < 10; i++ {
		if bytes.Equal(bytes.TrimSpace(row[i]), []byte("null")) {
			return errors.New("invalid typed service invocation runtime field")
		}
		var err error
		if i < 7 {
			var value uint64
			err = json.Unmarshal(row[i], &value)
		} else if i == 7 {
			var value uint32
			err = json.Unmarshal(row[i], &value)
		} else {
			var value int32
			err = json.Unmarshal(row[i], &value)
		}
		if err != nil {
			return errors.New("invalid typed service invocation runtime field")
		}
	}
	return nil
}
