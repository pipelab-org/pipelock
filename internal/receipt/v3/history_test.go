// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	legacyreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type testStream struct {
	t     *testing.T
	id    string
	key   ed25519.PrivateKey
	lines []byte
	seq   int64
	tip   string
	open  string
}

func signedStream(t *testing.T, number int, previous *Previous, inventory *Cutover) *testStream {
	t.Helper()
	s := &testStream{t: t, id: fmt.Sprintf("%032x", number), key: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))}
	s.tip = Genesis(s.id)
	body := StreamOpen{
		Lineage: strings.Repeat("a", 32), Previous: previous, LegacyCutover: inventory,
		Coverage: Coverage{
			Surfaces: []string{"mcp"}, ReceiptsRequired: true,
			RedactionRuleset: Ruleset{Hash: Digest(nil), ID: "example", Version: "1"},
		},
		Writer:    Writer{Instance: "example", Product: "Pipelock", Version: "3"},
		SignerKey: SignerKey{Alg: "ed25519", Public: base64.StdEncoding.EncodeToString(s.public())},
		Policy:    StreamPolicy{Hash: Digest(nil), Source: "writer_config"},
	}
	s.add(kindStreamOpen, body)
	s.open = s.tip
	return s
}

func (s *testStream) public() ed25519.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}

func (s *testStream) add(kind string, body any) {
	s.t.Helper()
	s.addVersion(kind, 1, body)
}

func (s *testStream) addVersion(kind string, version int64, body any) {
	s.t.Helper()
	bodyJSON, err := canonicalJSON(body)
	if err != nil {
		s.t.Fatal(err)
	}
	signer := Digest(s.public())
	payload, err := canonicalJSON(Common{
		Kind: kind, BodyV: version, V: 3, Body: bodyJSON, Prev: s.tip,
		Seq: s.seq, Signer: signer, Stream: s.id, TS: "2026-01-01T00:00:00.000Z",
	})
	if err != nil {
		s.t.Fatal(err)
	}
	pae := PAE(payload)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, pae))
	line := fmt.Sprintf("%s{\"keyid\":\"%s\",\"sig\":\"%s\"}%s%s%s",
		layoutPrefix, signer, signature, layoutPayloadPrefix, payload, layoutSuffix)
	s.lines = append(s.lines, line...)
	s.tip, s.seq = Digest(pae), s.seq+1
}

func (s *testStream) close() {
	s.t.Helper()
	s.add(kindStreamClose, StreamClose{Reason: "shutdown", Records: s.seq + 1})
}

func (s *testStream) write(dir string) string {
	s.t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("%s-%016d%s", s.id, 0, layoutFileSuffix))
	if err := os.WriteFile(path, s.lines, 0o600); err != nil {
		s.t.Fatal(err)
	}
	return path
}

func TestWriteErrorTipIgnoresPhysicalTail(t *testing.T) {
	root := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	newStream := signedStream(t, 2, &Previous{Stream: root.id, Ended: "write_error", Record: root.tip}, nil)
	newStream.close()
	path := t.TempDir()
	oldPath, nextPath := root.write(path), newStream.write(path)
	opts := Options{Keys: []ed25519.PublicKey{root.public()}, ExpectHeads: []Head{
		{Stream: root.id, Position: Position{Record: root.tip}},
	}}
	without, err := VerifyPaths(t.Context(), []string{nextPath, oldPath}, opts)
	if err != nil || without.Verdict != "VALID" {
		t.Fatalf("write-error pin: %+v, %v", without, err)
	}
	root.add(kindAction, Action{
		ActionID: "example", ActionType: "write", Actor: "example", Caller: Caller{Authn: "none"},
		Data: Data{Reversibility: "unknown", SideEffectClass: "unknown"}, EffectBoundary: "approval_prompt",
		EffectRelation: "before", Hold: &Hold{ID: "approval", Policy: "example"}, Phase: "hold",
		Policy: CapturePolicy("").ActionPolicy(), Principal: "example", Target: "api.vendor.example", Transport: "mcp", Verdict: "defer",
	})
	root.close()
	root.write(path)
	opts.DiskIndex = true
	with, err := VerifyPaths(t.Context(), []string{oldPath, nextPath}, opts)
	if err != nil {
		t.Fatal(err)
	}
	left, err := without.Projection()
	if err != nil {
		t.Fatal(err)
	}
	right, err := with.Projection()
	if err != nil || !bytes.Equal(left, right) {
		t.Fatalf("unconfirmed tail changed projection\n%s\n%s\n%v", left, right, err)
	}
	var unconfirmed int
	for _, finding := range with.Findings {
		if finding.Code == codeUnconfirmed {
			unconfirmed++
		}
	}
	if unconfirmed != 2 {
		t.Fatalf("got %d unconfirmed records, want hold and close", unconfirmed)
	}
}

func TestCutoverInventoryBytes(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		pin  Cutover
		code string
	}{
		{name: "implicit empty", pin: Cutover{Inventory: EmptyInventoryDigest()}},
		{name: "journal only", data: "{\"chains\":[],\"journal\":\"" + Digest(nil) + "\",\"v\":1}"},
		{name: "wrong count", data: emptyInventory, pin: Cutover{Chains: 1}, code: codeCutoverInventoryMismatch},
		{name: "wrong digest", data: emptyInventory, pin: Cutover{Inventory: Digest(nil)}, code: codeCutoverInventoryMismatch},
		{name: "not supplied", pin: Cutover{Inventory: Digest(nil)}, code: codeCutoverInventoryNotPresented},
		{name: "final newline", data: emptyInventory + "\n", code: codeCutoverInventoryMismatch},
		{name: "duplicate member", data: "{\"chains\":[],\"v\":1,\"v\":1}", code: codeCutoverInventoryMismatch},
		{name: "malformed JSON", data: "{", code: codeCutoverInventoryMismatch},
		{name: "unknown format", data: `{"chains":[{"chain":"example","format":"future","record":"` + Digest(nil) + `","seq":0}],"v":1}`, pin: Cutover{Chains: 1}, code: codeCutoverInventoryMismatch},
		{name: "invalid row", data: "{\"chains\":[{\"chain\":\"example\",\"format\":\"future\",\"record\":\"example\",\"seq\":0}],\"v\":1}", pin: Cutover{Chains: 1}, code: codeCutoverInventoryMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var name string
			if tc.data != "" {
				name = filepath.Join(t.TempDir(), "inventory.json")
				if err := os.WriteFile(name, []byte(tc.data), 0o600); err != nil {
					t.Fatal(err)
				}
				if tc.pin.Inventory == "" {
					tc.pin.Inventory = Digest([]byte(tc.data))
				}
			}
			_, code, err := readInventory(name, tc.pin, "")
			if err != nil || code != tc.code {
				t.Fatalf("got %s %v, want %s", code, err, tc.code)
			}
		})
	}
}

func TestCutoverInventoryReadFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	if _, _, err := readInventory(path, Cutover{Inventory: Digest(nil)}, ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing inventory read error, got %v", err)
	}
}

func TestCutoverInventoryResolvesSymlinkBeforeDotDot(t *testing.T) {
	root := t.TempDir()
	resolvedDir := filepath.Join(root, "resolved")
	child := filepath.Join(resolvedDir, "child")
	if err := os.MkdirAll(child, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(child, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	id := EmptyInventoryDigest()
	name := InventoryFilename(id)
	for file, data := range map[string]string{
		filepath.Join(root, name):        "{}",
		filepath.Join(resolvedDir, name): emptyInventory,
	} {
		if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := link + string(os.PathSeparator) + ".." + string(os.PathSeparator) + name
	if _, code, err := readInventory(path, Cutover{Inventory: id}, ""); code != "" || err != nil {
		t.Fatalf("resolved inventory: %s, %v", code, err)
	}
}

func TestDirectoryLegacyMembership(t *testing.T) {
	path := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "frozen", "v1", "action-receipt-v1-chain.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "evidence-conformance-session-0.jsonl"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	root := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	root.close()
	root.write(path)
	result, err := VerifyPaths(t.Context(), []string{path}, Options{Directory: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "INVALID" || !slices.ContainsFunc(result.Findings, func(f Finding) bool {
		return f.Code == codeLegacyChainUnlisted
	}) {
		t.Fatalf("unlisted legacy chain not detected: %+v", result)
	}
}

func TestDiskDecisionIndexMatchesMemory(t *testing.T) {
	root := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	hold := Action{
		ActionID: "example", ActionType: "write", Actor: "example", Caller: Caller{Authn: "none"},
		Data: Data{Reversibility: "unknown", SideEffectClass: "unknown"}, EffectBoundary: "approval_prompt",
		EffectRelation: "before", Hold: &Hold{ID: "approval", Policy: "example"}, Phase: "hold",
		Policy: CapturePolicy("").ActionPolicy(), Principal: "example", Target: "api.vendor.example", Transport: "mcp", Verdict: "defer",
	}
	root.add(kindAction, hold)
	resolution := hold
	resolution.Phase, resolution.Verdict, resolution.EffectRelation = "resolution", "block", "after"
	resolution.Hold = &Hold{ID: "approval", ResolutionSource: "operator", ResolutionPolicy: "example"}
	root.add(kindAction, resolution)
	root.close()
	path := root.write(t.TempDir())
	opts := Options{Keys: []ed25519.PublicKey{root.public()}}
	memory, err := VerifyPaths(t.Context(), []string{path}, opts)
	if err != nil || memory.Verdict != "VALID" || memory.Counts.Decisions == nil {
		t.Fatalf("memory verdict: %+v, %v", memory, err)
	}
	if rows := *memory.Counts.Decisions; !slices.Equal(rows, []StateCount{{Count: 1, State: "blocked"}}) {
		t.Fatalf("decisions: %+v", rows)
	}
	opts.DiskIndex = true
	disk, err := VerifyPaths(t.Context(), []string{path}, opts)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := memory.JSON()
	if err != nil {
		t.Fatal(err)
	}
	obtained, err := disk.JSON()
	if err != nil || !bytes.Equal(expected, obtained) {
		t.Fatalf("disk result differs from memory\n%s\n%s\n%v", expected, obtained, err)
	}
}

func TestCallerInputs(t *testing.T) {
	for _, tc := range []struct {
		name        string
		closeStream bool
		options     func(*testStream) Options
		verdict     string
		exit        int
	}{
		{"prefix and unpinned", false, func(*testStream) Options { return Options{AllowPrefix: true, AllowUnpinned: true} }, prefixVerdict, 0},
		{"only prefix", false, func(*testStream) Options { return Options{AllowPrefix: true} }, prefixVerdict, 1},
		{"only unpinned", false, func(*testStream) Options { return Options{AllowUnpinned: true} }, prefixVerdict, 3},
		{"exact sequence", false, func(s *testStream) Options {
			return Options{Keys: []ed25519.PublicKey{s.public()}, ExpectSequences: []Sequence{{Stream: s.id}}}
		}, "VALID", 0},
		{"previous record", true, func(s *testStream) Options {
			return Options{ExpectHeads: []Head{{Stream: s.id, Position: Position{Record: s.open}}}}
		}, "INVALID", 1},
		{"clean stream cannot be accepted", true, func(s *testStream) Options {
			return Options{AcceptDiscontinuities: []string{s.open}}
		}, "INVALID", 1},
		{"partial must name a missing edge", true, func(s *testStream) Options {
			return Options{AllowPartialHistories: []string{s.id}}
		}, "INVALID", 1},
		{"lineage must exist", true, func(*testStream) Options {
			return Options{ExpectLineage: strings.Repeat("b", 32)}
		}, "INVALID", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
			if tc.closeStream {
				stream.close()
			}
			path := stream.write(t.TempDir())
			result, err := VerifyPaths(t.Context(), []string{path}, tc.options(stream))
			if err != nil || result.Verdict != tc.verdict || result.ExitCode != tc.exit {
				t.Fatalf("got %s / %d (%v), want %s / %d", result.Verdict, result.ExitCode, err, tc.verdict, tc.exit)
			}
		})
	}
}

func TestCutoverBindsLegacyHead(t *testing.T) {
	path := t.TempDir()
	source := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "frozen", "v1", "action-receipt-v1-chain.jsonl")
	raw, err := os.ReadFile(filepath.Clean(source))
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(path, "evidence-conformance-session-0.jsonl")
	if err := os.WriteFile(name, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	batch, _, err := readLegacy(name)
	if err != nil || len(batch.action) == 0 {
		t.Fatalf("read fixture receipt: %v", err)
	}
	first, last := batch.action[0].ActionRecord, batch.action[len(batch.action)-1].ActionRecord
	firstHash, err := first.Hash()
	if err != nil {
		t.Fatal(err)
	}
	lastHash, err := last.Hash()
	if err != nil {
		t.Fatal(err)
	}
	var lastSeq int64
	if seq := last.ChainSeq; seq <= maxInteger {
		lastSeq = int64(seq)
	} else {
		t.Fatal("legacy sequence out of range")
	}
	id := first.RunNonce
	if id == "" {
		id = legacyHash(firstHash)
	}
	for _, tc := range []struct {
		name   string
		seq    int64
		record string
		code   string
	}{
		{"match", lastSeq, legacyHash(lastHash), codeLegacyEndUnproven},
		{"older pin", lastSeq - 1, legacyHash(lastHash), codeLegacyExtendedAfterCutover},
		{"newer pin", lastSeq + 1, legacyHash(lastHash), codeLegacyChainTruncated},
		{"different tip", lastSeq, Digest(nil), codeLegacyChainHeadMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, filepath.Base(name)), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			inventory := Inventory{V: 1, Chains: []InventoryChain{{Chain: id, Format: legacyAction, Record: tc.record, Seq: tc.seq}}}
			data, err := canonicalJSON(inventory)
			if err != nil {
				t.Fatal(err)
			}
			pin := Digest(data)
			if err := os.WriteFile(filepath.Join(dir, InventoryFilename(pin)), data, 0o600); err != nil {
				t.Fatal(err)
			}
			stream := signedStream(t, 1, nil, &Cutover{Chains: 1, Inventory: pin})
			stream.close()
			stream.write(dir)
			keys, err := DecodeKeys([]string{batch.action[0].SignerKey})
			if err != nil {
				t.Fatal(err)
			}
			keys = append(keys, stream.public())
			opts := Options{Directory: true, Keys: keys}
			result, err := VerifyPaths(t.Context(), []string{dir}, opts)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(result.Findings, func(f Finding) bool { return f.Code == tc.code }) {
				t.Fatalf("wanted %s, got %+v", tc.code, result.Findings)
			}
			if tc.code == codeLegacyEndUnproven {
				opts.AcceptDiscontinuities = []string{stream.open}
				result, err = VerifyPaths(t.Context(), []string{dir}, opts)
				if err != nil || result.Verdict != gapsVerdict || result.ExitCode != 0 {
					t.Fatalf("accepted legacy cutover: %s / %d (%v)", result.Verdict, result.ExitCode, err)
				}
			}
		})
	}
}

func testIncompleteLegacyGroup(t *testing.T) {
	dir := t.TempDir()
	stream := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, stream.key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	group, err := legacyreceipt.OpenInitialReceiptShardSet(legacyreceipt.EmitterConfig{
		Recorder: rec, PrivKey: stream.key, ConfigHash: strings.TrimPrefix(Digest(nil), "sha256:"),
		Principal: "example", Actor: "example",
	}, "example", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, hash := group.Opening()
	inventory, err := canonicalJSON(Inventory{V: 1, Chains: []InventoryChain{
		{Format: legacyGroup, Chain: open.GroupID, Record: legacyHash(hash), Seq: int64(open.ShardCount)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	digest := Digest(inventory)
	if err := os.WriteFile(filepath.Join(dir, InventoryFilename(digest)), inventory, 0o600); err != nil {
		t.Fatal(err)
	}
	root := signedStream(t, 1, nil, &Cutover{Inventory: digest, Chains: 1})
	root.close()
	root.write(dir)
	paths := []string{dir}
	opts := Options{Directory: true, Keys: []ed25519.PublicKey{root.public()}}
	result, err := VerifyPaths(t.Context(), paths, opts)
	if err != nil || !hasFinding(result, codeLegacyGroupIncomplete) {
		t.Fatalf("expected incomplete group: %+v, %v", result, err)
	}
	mutant, err := verifyPaths(t.Context(), paths, opts, codeLegacyGroupIncomplete)
	if err != nil {
		t.Fatal(err)
	}
	requireMutation(t, codeLegacyGroupIncomplete, result, mutant)
}

func TestTornReceiptOrdering(t *testing.T) {
	for _, tc := range []struct {
		name, finding string
		closed        bool
	}{
		{"after close", codeDataAfterClose, true},
		{"before later shard", codeFileLayout, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
			s.close()
			var later []byte
			if !tc.closed {
				first, rest, _ := bytes.Cut(s.lines, []byte{'\n'})
				later = bytes.Clone(rest)
				s.lines = append(slices.Clip(first), '\n')
			}
			s.lines = append(s.lines, '{')
			files := []string{s.write(dir)}
			if later != nil {
				path := filepath.Join(dir, fmt.Sprintf("%s-%016d%s", s.id, 1, layoutFileSuffix))
				if err := os.WriteFile(path, later, 0o600); err != nil {
					t.Fatal(err)
				}
				files = append(files, path)
			}
			result, err := VerifyPaths(t.Context(), files, Options{})
			if err != nil || !hasFinding(result, tc.finding) {
				t.Fatalf("expected %s, got %+v, %v", tc.finding, result, err)
			}
		})
	}
}

func TestCutoverMembershipWithContestedOpener(t *testing.T) {
	const lineage = "example"
	stream := &verifiedStream{body: StreamOpen{Lineage: lineage, LegacyCutover: &Cutover{Inventory: EmptyInventoryDigest()}}}
	v := verification{histories: map[string][]*verifiedStream{lineage: {stream}}}
	for _, tc := range []struct {
		name, kind string
		body       StreamOpen
		want       bool
	}{
		{"not an opener", kindHeartbeat, StreamOpen{}, true},
		{"later branch", kindStreamOpen, StreamOpen{Lineage: lineage, Previous: &Previous{}}, true},
		{"possible root", kindStreamOpen, StreamOpen{Lineage: lineage}, false},
		{"history without a root", kindStreamOpen, StreamOpen{Lineage: "other", Previous: &Previous{}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			v.contested = map[string][]stagedRecord{"example": {{Common: Common{Kind: tc.kind, Body: data}}}}
			if got := v.cutoverMembershipKnown(); got != tc.want {
				t.Fatalf("cutover membership known = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestAcceptUnsealedDiscontinuity(t *testing.T) {
	dir := t.TempDir()
	root := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	successor := signedStream(t, 2, &Previous{Stream: root.id, Record: root.tip, Ended: "unsealed"}, nil)
	successor.close()
	paths := []string{root.write(dir), successor.write(dir)}
	opts := Options{Keys: []ed25519.PublicKey{root.public()}, AcceptDiscontinuities: []string{successor.open}}
	result, err := VerifyPaths(t.Context(), paths, opts)
	if err != nil || result.Verdict != "VALID, GAPS ACCEPTED" || result.ExitCode != 0 {
		t.Fatalf("unexpected accepted discontinuity: %+v, %v", result, err)
	}
	opts.ExpectSequences = []Sequence{{Stream: fmt.Sprintf("%032x", 3), Seq: 0}}
	result, err = VerifyPaths(t.Context(), paths, opts)
	if err != nil || !hasFinding(result, codeExpectationNotMet) {
		t.Fatalf("unpresented stream met an expectation: %+v, %v", result, err)
	}
}

func TestStreamOpenCannotRepeat(t *testing.T) {
	root := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	record, code := parseLine(root.lines, "")
	if code != "" {
		t.Fatal(code)
	}
	root.add(kindStreamOpen, record.Body)
	result, err := VerifyPaths(t.Context(), []string{root.write(t.TempDir())}, Options{})
	if err != nil || !hasFinding(result, codeStreamOrder) {
		t.Fatalf("repeat opener did not fail its stream rule: %+v, %v", result, err)
	}
}

func TestAllForkBranchesReported(t *testing.T) {
	var paths []string
	for beat := int64(1); beat <= 3; beat++ {
		stream := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
		stream.add(kindHeartbeat, Heartbeat{Beat: beat})
		paths = append(paths, stream.write(t.TempDir()))
	}
	result, err := VerifyPaths(t.Context(), paths, Options{})
	if err != nil {
		t.Fatal(err)
	}
	forks := 0
	for _, finding := range result.Findings {
		if finding.Code == codeFork {
			forks++
		}
	}
	if forks != len(paths) || result.Verdict != "INVALID" {
		t.Fatalf("got %d forks and verdict %q", forks, result.Verdict)
	}
}

func TestInventoryRefusesNonRegularFile(t *testing.T) {
	if _, _, err := readInventory(t.TempDir(), Cutover{Inventory: EmptyInventoryDigest()}, ""); err == nil || !strings.Contains(err.Error(), "open cutover inventory") {
		t.Fatalf("non-regular inventory error = %v", err)
	}
}

func TestInventoryRejectsWrongDigestBeforeDecoding(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "inventory")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := file.Truncate(8 << 20); err != nil {
		t.Fatal(err)
	}
	if _, code, err := readInventoryFile(file, Cutover{Inventory: EmptyInventoryDigest()}, ""); err != nil || code != codeCutoverInventoryMismatch {
		t.Fatalf("mismatched inventory: finding %q, error %v", code, err)
	}
	if offset, err := file.Seek(0, io.SeekCurrent); err != nil || offset != 8<<20 {
		t.Fatalf("expected digest pass to finish without rewinding: offset %d, error %v", offset, err)
	}
}
