// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

func TestCallerPins(t *testing.T) {
	stream := strings.Repeat("1", 32)
	head := Digest(nil)
	for _, tc := range []struct {
		seq string
		ok  bool
	}{
		{"1", true},
		{"9007199254740991", true},
		{"", false},
		{"-1", false},
		{"01", false},
		{"+1", false},
		{"9007199254740992", false},
	} {
		t.Run(tc.seq, func(t *testing.T) {
			pin, err := ParseSequence(stream + ":" + tc.seq)
			if (err == nil) != tc.ok || tc.ok && pin.Stream != stream {
				t.Fatalf("sequence %+v, error %v", pin, err)
			}
			pos, err := ParseHead(stream + ":" + tc.seq + ":" + head)
			if (err == nil) != tc.ok || tc.ok && (pos.Record != head || pos.Seq != pin.Seq || pos.Stream != stream) {
				t.Fatalf("head %+v, error %v", pos, err)
			}
		})
	}
	for _, key := range []string{"gg", "00"} {
		if _, err := DecodeKeys([]string{key}); err == nil {
			t.Fatalf("accepted malformed key %q", key)
		}
	}
	for _, opts := range []Options{
		{Directory: true, ExplicitV3: true},
		{ExpectLineage: "bad"},
		{AllowPartialHistories: []string{"bad"}},
		{AcceptDiscontinuities: []string{"bad"}},
	} {
		if _, err := VerifyPaths(t.Context(), nil, opts); err == nil {
			t.Fatal("accepted invalid verification options")
		}
	}
}

func TestInputClaims(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "example.jsonl")
	if err := os.WriteFile(profile, []byte(profilePrefix), 0o600); err != nil {
		t.Fatal(err)
	}
	unknownProfile := filepath.Join(dir, "example.receipt-v4.jsonl")
	if err := os.WriteFile(unknownProfile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path              string
		directory, claim, fails bool
	}{
		{"filename", unknownProfile, false, true, false},
		{"content", profile, false, true, false},
		{"directory", dir, true, true, false},
		{"empty directory", t.TempDir(), true, false, false},
		{"missing directory", filepath.Join(dir, "absent"), true, false, true},
		{"missing file", filepath.Join(dir, "absent"), false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claim, err := ClaimsInput(tc.path, tc.directory)
			if claim != tc.claim || (err != nil) != tc.fails {
				t.Fatalf("claim %t, error %v", claim, err)
			}
		})
	}
}

func TestBoundedLineReads(t *testing.T) {
	fault := errors.New("read failed")
	big := strings.Repeat("x", maxLineBytes+1)
	for _, tc := range []struct {
		name, data string
		err        error
		complete   bool
		length     int
	}{
		{"complete", "entry\n", nil, true, 6},
		{"last partial", "entry", nil, false, 5},
		{"overlong line", big + "\n", nil, true, 16},
		{"overlong tail", big, nil, false, 16},
		{"immediate error", "", fault, false, 0},
		{"error during drain", big, fault, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reader io.Reader = strings.NewReader(tc.data)
			if tc.err != nil {
				reader = io.MultiReader(reader, iotest.ErrReader(tc.err))
			}
			input := bufio.NewReaderSize(reader, 16)
			line, complete, err := readBounded(input)
			if !errors.Is(err, tc.err) || complete != tc.complete || len(line) != tc.length {
				t.Fatalf("length %d, complete %t, error %v", len(line), complete, err)
			}
		})
	}
}

func TestVerificationReadErrors(t *testing.T) {
	empty := t.TempDir()
	path := filepath.Join(empty, "absent")
	for _, tc := range []struct {
		name  string
		paths []string
		opts  Options
	}{
		{"missing directory", []string{path}, Options{Directory: true}},
		{"missing named stream", []string{filepath.Join(empty, strings.Repeat("1", 32)+"-0000000000000000"+layoutFileSuffix)}, Options{}},
		{"directory with non-file", []string{empty}, Options{ExplicitV3: true}},
		{"invalid directory scope", nil, Options{Directory: true}},
		{"invalid explicit scope", nil, Options{ExplicitV3: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyPaths(t.Context(), tc.paths, tc.opts); err == nil {
				t.Fatal("expected a verification input error")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := VerifyPaths(ctx, nil, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verification: %v", err)
	}
}

func TestVerifierRefusesScratchDatabaseFailures(t *testing.T) {
	ctx := t.Context()
	store, err := newStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	stream := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	path := stream.write(t.TempDir())
	file, _ := identify(path)
	v := verification{
		ctx: ctx, store: store,
		keys: map[string]validatedKey{Digest(stream.public()): validateKey(stream.public())},
		used: map[string]bool{}, streams: map[string]*verifiedStream{},
	}
	stmt, err := store.PrepareContext(ctx, "SELECT 1")
	if err != nil {
		t.Fatal(err)
	}
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.stageFile(file, stmt); err == nil || !strings.Contains(err.Error(), "stage verified record") {
		t.Fatalf("staging did not propagate the write failure: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		check func() error
	}{
		{"stage", func() error { return v.stageFiles([]inputFile{file}) }},
		{"appraise", v.appraiseDecisions},
		{"predecessor", func() error {
			parent := &verifiedStream{limit: maxInteger}
			child := &verifiedStream{body: StreamOpen{Previous: &Previous{Stream: stream.id}}}
			return v.checkPin(parent, child)
		}},
		{"broken stream", v.verifyStreams},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check(); err == nil {
				t.Fatal("verification used a closed scratch database")
			}
		})
	}
}

func TestWalkRecordsRefusesMalformedScratchRows(t *testing.T) {
	for _, tc := range []struct {
		name             string
		payload, unknown string
	}{
		{"column type", "{}", "unreadable"},
		{"payload", "{", "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := newStore(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer store.close()
			const insert = "INSERT INTO records (stream,seq,id,payload,unknown,body_code) VALUES (?,0,'record',?,?, '')"
			if _, err := store.ExecContext(t.Context(), insert, "stream", tc.payload, tc.unknown); err != nil {
				t.Fatal(err)
			}
			err = walkRecords(t.Context(), store, "stream", maxInteger, func(stagedRecord) error {
				t.Fatal("passed a corrupt record to verification")
				return nil
			})
			if err == nil {
				t.Fatal("bad scratch data produced no error")
			}
		})
	}
}

func TestResultCanonicalStrings(t *testing.T) {
	raw, err := canonicalJSON(map[string]string{
		"string": "quote\": slash/ <>& \\ \b\f\n\r\t\x01\u2028\u2029",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"string\":\"quote\\\": slash/ <>& \\\\ \\b\\f\\n\\r\\t\\u0001\u2028\u2029\"}"
	if string(raw) != want {
		t.Fatalf("canonical value %q, want %q", raw, want)
	}
	if _, err := canonicalJSON(make(chan struct{})); err == nil {
		t.Fatal("serialized an unsupported result value")
	}
}

func TestScratchDirectoryCreationFailure(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	if _, err := newStore(t.Context()); err == nil || !strings.Contains(err.Error(), "scratch directory") {
		t.Fatalf("unexpected scratch-directory result: %v", err)
	}
}

func TestWireRejectsMalformedMembers(t *testing.T) {
	stream := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	for _, tc := range []struct {
		name, from, to string
	}{
		{"signature prefix", ",\"sig\":\"", ", \"sig\":\""},
		{"signature terminator", "\"}],\"payload\":", "\"} ],\"payload\":"},
		{"payload type", "\"payload\":{", "\"payload\":["},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := bytes.Replace(stream.lines, []byte(tc.from), []byte(tc.to), 1)
			if bytes.Equal(line, stream.lines) {
				t.Fatal("test did not change the line")
			}
			if exported, code := ExportDSSE(line); exported != nil || code != codeLineLayout {
				t.Fatalf("invalid line exported: %s, %q", code, exported)
			}
		})
	}
	record, code := parseLine(stream.lines, "")
	if code != "" {
		t.Fatal(code)
	}
	if code := checkSignature(record, validatedKey{}, ""); code != codeSignatureKey {
		t.Fatalf("used a key outside the signer's identity: %s", code)
	}
}

func TestParserRefusesTruncatedValues(t *testing.T) {
	for _, data := range []string{`{"first":`, `{"first":"`, `{"first":"\`, `{"first?":1}`, `{first:1}`} {
		t.Run(data, func(t *testing.T) {
			cursor := payloadParser{data: []byte(data)}
			if _, ok := cursor.object(1); ok {
				t.Fatalf("accepted malformed payload %q", data)
			}
		})
	}
}
