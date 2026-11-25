// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	contract "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

func TestCallerOptionsAndResultFormat(t *testing.T) {
	_, err := (CallerOptions{Format: "unknown"}).Parse(1)
	if err == nil {
		t.Fatal("accepted unknown receipt format")
	}
	if _, err := UseHostVerifier(Options{}).ResultBytes("unknown"); err == nil {
		t.Fatal("accepted unknown result format")
	}
}

func TestCallerPins(t *testing.T) {
	stream := strings.Repeat("1", 32)
	head := Digest(nil)
	for _, tc := range []struct {
		seq  string
		want int64
		ok   bool
	}{
		{"1", 1, true},
		{"9007199254740991", 9007199254740991, true},
		{"", 0, false},
		{"-1", 0, false},
		{"01", 0, false},
		{"+1", 0, false},
		{"9007199254740992", 0, false},
	} {
		t.Run(tc.seq, func(t *testing.T) {
			pin, err := ParseSequence(stream + ":" + tc.seq)
			if (err == nil) != tc.ok || tc.ok && (pin.Stream != stream || pin.Seq != tc.want) {
				t.Fatalf("sequence %+v, error %v", pin, err)
			}
			pos, err := ParseHead(stream + ":" + tc.seq + ":" + head)
			if (err == nil) != tc.ok || tc.ok && (pos.Record != head || pos.Seq != tc.want || pos.Stream != stream) {
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
		if err := opts.validate(); err == nil {
			t.Fatal("accepted invalid verification options")
		}
	}
}

func TestInputClaims(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "example.jsonl")
	if err := os.WriteFile(profile, []byte(contract.ProfileEnvelopePrefix), 0o600); err != nil {
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
			line, complete, err := readBounded(t.Context(), input)
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
	_, err := VerifyPaths(t.Context(), nil, Options{LegacyEnd: &LegacyEnd{}})
	const want = "legacy endpoint expectations require mixed directory scope and an expected head or sequence"
	if err == nil || err.Error() != want {
		t.Fatalf("legacy endpoint error = %v, want %q", err, want)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := VerifyPaths(ctx, nil, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verification: %v", err)
	}
}

func TestRecordStagingRefusesDisappearedEvidence(t *testing.T) {
	ctx := t.Context()
	store, err := newStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()

	stream := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	path := stream.write(t.TempDir())
	file, ok := identify(path)
	if !ok {
		t.Fatal("signed test stream was not identified")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	v := verification{ctx: ctx, store: store}
	if err := v.stageFiles([]inputFile{file}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stage disappeared evidence: got %v, want %v", err, os.ErrNotExist)
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

func TestDirectoryClaimsAfterUnreadableCandidate(t *testing.T) {
	dir := t.TempDir()
	unreadable := filepath.Join(dir, "activation-receipts.jsonl")
	if err := os.WriteFile(unreadable, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Skipf("cannot make candidate unreadable: %v", err)
	}
	if _, err := ClaimsInput(dir, true); err == nil {
		t.Skip("candidate remains readable")
	}
	path := filepath.Join(dir, "z.receipt-v4.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if claimed, err := ClaimsInput(dir, true); !claimed || err != nil {
		t.Fatalf("directory claim = %t, error = %v", claimed, err)
	}
}

func TestEvidenceDiscoveryFollowsDirectoryPath(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "resolved")
	child := filepath.Join(dir, "child")
	if err := os.MkdirAll(child, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(child, link); err != nil {
		t.Skipf("cannot create symbolic link: %v", err)
	}
	stream := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	stream.close()
	stream.write(dir)
	path := link + string(os.PathSeparator) + ".."
	result, err := VerifyPaths(t.Context(), []string{path}, Options{Directory: true})
	if err != nil || result.Verdict != "SELF-CONSISTENT ONLY" {
		t.Fatalf("resolved directory verdict = %q, error = %v", result.Verdict, err)
	}
}

func TestSchemaMutationHandlesInvalidShapes(t *testing.T) {
	stream := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	stream.add(kindAction, []int{1})
	line := bytes.SplitAfter(stream.lines, []byte{'\n'})[1]
	if _, code := parseLine(line, ""); code != codeCommonSchema {
		t.Fatalf("non-object body: got %s, want %s", code, codeCommonSchema)
	}
	parseLine(line, codeCommonSchema)
	for _, fields := range []map[string]any{
		{},
		{"policy": map[string]any{}, "redaction": map[string]any{"classes": []any{"example"}}},
	} {
		var record Record
		record.Kind, record.BodyV, record.values = kindAction, 1, fields
		if _, code := checkBody(record, ""); code != codeBodySchema {
			t.Fatalf("malformed action: got %s, want %s", code, codeBodySchema)
		}
		checkBody(record, codeBodySchema)
	}
}

func TestBoundedLineDrainCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 64)+"\n"), 16)
	cancel()
	if _, _, err := readBounded(ctx, reader); !errors.Is(err, context.Canceled) {
		t.Fatalf("oversized line drain error = %v", err)
	}
}

func TestValidateLegacyOptions(t *testing.T) {
	keys := []ed25519.PublicKey{make(ed25519.PublicKey, ed25519.PublicKeySize)}
	bindings := &contract.ChainVerifyOptions{}
	const scopeError = "legacy options require mixed directory scope"
	const groupError = "--group requires pinned keys and no other legacy selection"
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{"file with session", Options{LegacySelection: LegacySelection{Session: "example"}}, scopeError},
		{"file with group", Options{LegacySelection: LegacySelection{Group: "example"}}, scopeError},
		{"file with bindings", Options{LegacySelection: LegacySelection{Bindings: bindings}}, scopeError},
		{"group without keys", Options{Directory: true, LegacySelection: LegacySelection{Group: "example"}}, groupError},
		{"group with session", Options{Directory: true, Keys: keys, LegacySelection: LegacySelection{Group: "example", Session: "example"}}, groupError},
		{"group with unpinned allowed", Options{Directory: true, Keys: keys, AllowUnpinned: true, LegacySelection: LegacySelection{Group: "example"}}, groupError},
		{"group with bindings", Options{Directory: true, Keys: keys, LegacySelection: LegacySelection{Group: "example", Bindings: bindings}}, groupError},
		{"group with endpoint", Options{Directory: true, Keys: keys, LegacyEnd: &LegacyEnd{Head: Digest(nil)}, LegacySelection: LegacySelection{Group: "example"}}, groupError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.opts.validate(); err == nil || err.Error() != tc.want {
				t.Fatalf("validate() = %v, want %q", err, tc.want)
			}
		})
	}
}
