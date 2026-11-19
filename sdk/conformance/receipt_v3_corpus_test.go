// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

var updateReceiptV3 = flag.Bool("update-receipt-v3", false, "regenerate receipt v3 vectors from their recipes")

const v3Corpus = "testdata/v3"

type v3AARPAuthority struct {
	MediatorID string `json:"mediator_id"`
	Role       string `json:"role"`
}

type v3AARPTrust struct {
	Keys      map[string]string          `json:"keys"`
	Mediators map[string]v3AARPAuthority `json:"mediators"`
}

type v3Request struct {
	AARPTrust             *v3AARPTrust `json:"aarp_trust,omitempty"`
	AcceptDiscontinuities []string     `json:"accept_discontinuities,omitempty"`
	Directory             bool         `json:"directory,omitempty"`
	ExpectLineage         string       `json:"expect_lineage,omitempty"`
	Check                 string       `json:"check"`
	Finding               string       `json:"finding,omitempty"`
	Inputs                []string     `json:"inputs"`
	Keys                  []string     `json:"keys"`
	AllowPrefix           bool         `json:"allow_prefix,omitempty"`
	AllowUnpinned         bool         `json:"allow_unpinned,omitempty"`
	Format                string       `json:"format,omitempty"`
	Legacy                bool         `json:"legacy,omitempty"`
	Endorsements          []string     `json:"endorsements,omitempty"`
}

type v3File struct {
	name  string
	bytes []byte
}

type v3Recipe struct {
	group        int
	name         string
	code         string
	verdict      string
	extraInvalid []string
	request      v3Request
	files        []v3File
}

type v3Common map[string]any

type v3Signed struct {
	line    []byte
	payload []byte
	id      string
}

type v3Stream struct {
	id, lineage string
	key         ed25519.PrivateKey
	records     []v3Signed
}

func v3Key(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("receipt v3 conformance " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func v3Public(key ed25519.PrivateKey) ed25519.PublicKey {
	return key.Public().(ed25519.PublicKey)
}

func v3DefaultOpen(key ed25519.PrivateKey, lineage string) v3Common {
	return v3Common{
		"lineage":    lineage,
		"signer_key": v3Common{"alg": "ed25519", "public": base64.StdEncoding.EncodeToString(v3Public(key))},
		"coverage": v3Common{
			"content_scan": true, "receipts_required": true, "surfaces": []string{"mcp"},
			"redaction_ruleset": v3Common{"id": "example", "hash": v3.Digest(nil), "version": "1"},
		},
		"policy":         v3Common{"source": "writer_config", "hash": v3.Digest(nil)},
		"writer":         v3Common{"instance": "example", "product": "Pipelock", "version": "3"},
		"legacy_cutover": v3Common{"chains": 0, "inventory": v3.EmptyInventoryDigest()},
	}
}

func v3DefaultAction() v3Common {
	return v3Common{
		"action_id": "example", "action_type": "write", "actor": "example",
		"caller": v3Common{"authn": "none"}, "data": v3Common{"reversibility": "unknown", "side_effect_class": "unknown"},
		"effect_boundary": "none", "effect_relation": "not_attempted", "phase": "decision",
		"policy": v3Common{"source": "unavailable"}, "principal": "example", "target": "api.vendor.example",
		"transport": "mcp", "verdict": "block",
	}
}

func v3Close(seq int) v3Common {
	return v3Common{
		"durability": v3Common{"durability_blocks": 0, "fsync_errors_gated": 0},
		"reason":     "shutdown", "records": seq + 1,
	}
}

func v3Heartbeat() v3Common {
	return v3Common{"beat": 1, "durability_blocks": 0, "fsync_errors_gated": 0}
}

func v3Canonical(t *testing.T, value any) []byte {
	t.Helper()
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
	return slices.Clone(out)
}

func v3Sign(payload []byte, key ed25519.PrivateKey) v3Signed {
	return v3SignWith(payload, v3.Digest(v3Public(key)), ed25519.Sign(key, v3.PAE(payload)))
}

func v3SignWith(payload []byte, id string, sig []byte) v3Signed {
	header := fmt.Sprintf("{\"payloadType\":\"%s\",\"signatures\":[{\"keyid\":\"%s\",\"sig\":\"%s\"}],\"payload\":",
		v3.PayloadType, id, base64.StdEncoding.EncodeToString(sig))
	pae := v3.PAE(payload)
	line := append([]byte(header), payload...)
	line = append(line, '}', '\n')
	return v3Signed{line, payload, v3.Digest(pae)}
}

func v3New(t *testing.T) *v3Stream {
	t.Helper()
	s := &v3Stream{id: strings.Repeat("1", 32), lineage: strings.Repeat("2", 32), key: v3Key("first")}
	s.add(t, "stream_open", v3DefaultOpen(s.key, s.lineage), nil)
	return s
}

func (s *v3Stream) add(t *testing.T, kind string, body v3Common, change func(v3Common)) {
	t.Helper()
	seq := len(s.records)
	prev := v3.Genesis(s.id)
	if seq > 0 {
		prev = s.records[seq-1].id
	}
	payload := v3Common{
		"v": 3, "kind": kind, "body_v": 1, "stream": s.id, "seq": seq, "prev": prev,
		"ts": "2026-01-01T00:00:00.000Z", "signer": v3.Digest(v3Public(s.key)), "body": body,
	}
	if change != nil {
		change(payload)
	}
	s.records = append(s.records, v3Sign(v3Canonical(t, payload), s.key))
}

func (s *v3Stream) close(t *testing.T) {
	t.Helper()
	s.add(t, "stream_close", v3Close(len(s.records)), nil)
}

func (s *v3Stream) file(start, end int) v3File {
	var buf bytes.Buffer
	for _, row := range s.records[start:end] {
		buf.Write(row.line)
	}
	return v3File{fmt.Sprintf("%s-%016d.receipt-v3.jsonl", s.id, start), buf.Bytes()}
}

func (s *v3Stream) finish(t *testing.T) v3File {
	t.Helper()
	s.close(t)
	return s.file(0, len(s.records))
}

func v3LineTransform(t *testing.T, tail v3Signed, from, to string) []byte {
	t.Helper()
	changed := bytes.Replace(tail.line, []byte(from), []byte(to), 1)
	if bytes.Equal(changed, tail.line) {
		t.Fatalf("line transform marker not found: %s", from)
	}
	return changed
}

func v3Invalid(group int, name, code string, file v3File) v3Recipe {
	return v3Recipe{group: group, name: name, verdict: "INVALID", code: code, files: []v3File{file}}
}

func TestReceiptV3RegistryDrift(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "python3", "generate_receipt_v3.py", "--check")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("receipt registry generation: %v\n%s", err, output)
	}
}

func TestReceiptV3Corpus(t *testing.T) {
	recipes := append(v3LayoutRecipes(t), v3PayloadRecipes(t)...)
	recipes = append(recipes, v3SignatureRecipes(t)...)
	recipes = append(recipes, v3StreamRecipes(t)...)
	recipes = append(recipes, v3BodyRecipes(t)...)
	recipes = append(recipes, v3TrustRecipes(t)...)
	recipes = append(recipes, v3SpecialRecipes(t)...)
	recipes = append(recipes, v3HistoryRecipes(t)...)
	recipes = append(recipes, v3DecisionRecipes(t)...)
	recipes = append(recipes, v3CutoverRecipes(t)...)
	recipes = append(recipes, v3OperationalOnlyRecipe(t))
	recipes = append(recipes, v3WriterRecipes(t)...)
	for _, recipe := range recipes {
		t.Run(fmt.Sprintf("g%02d-%s", recipe.group, recipe.name), func(t *testing.T) {
			v3RunRecipe(t, recipe)
		})
	}
}

func v3RunRecipe(t *testing.T, recipe v3Recipe) {
	t.Helper()
	capture := t.TempDir()
	name := filepath.Base(t.Name())
	directory := filepath.Join(v3Corpus, name)
	request := recipe.request
	request.Check, request.Finding = recipe.name, recipe.code
	request.Inputs = []string{}
	if request.Keys == nil && request.AARPTrust == nil {
		request.Keys = []string{hex.EncodeToString(v3Public(v3Key("first")))}
	}
	for _, file := range recipe.files {
		path := filepath.Join(capture, file.name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, file.bytes, 0o600); err != nil {
			t.Fatal(err)
		}
		request.Inputs = append(request.Inputs, file.name)
	}
	requestJSON := append(v3Canonical(t, request), '\n')
	if request.Legacy {
		path := filepath.Join(capture, recipe.files[0].name)
		claimed, err := v3.ClaimsInput(path, false)
		if err != nil || claimed {
			t.Fatalf("legacy evidence was claimed by the v3 detector: %t, %v", claimed, err)
		}
		v3CheckLegacy(t, recipe.files[0], request)
		v3WriteFixtures(t, directory, recipe.files, requestJSON, []v3File{{"expect.json", []byte("{\"legacy_compatible\":true}\n")}})
		return
	}
	keys, err := v3.DecodeKeys(request.Keys)
	if err != nil {
		t.Fatal(err)
	}
	opts := v3.Options{
		Keys: keys, AcceptDiscontinuities: request.AcceptDiscontinuities, AllowPrefix: request.AllowPrefix, AllowUnpinned: request.AllowUnpinned,
		ExplicitV3: request.Format == "v3", Directory: request.Directory, ExpectLineage: request.ExpectLineage,
	}
	for _, name := range request.Endorsements {
		endorsement, err := actionreceipt.LoadRotationEndorsementFile(filepath.Join(capture, name))
		if err != nil {
			t.Fatal(err)
		}
		opts.LegacySelection.Endorsements = append(opts.LegacySelection.Endorsements, endorsement)
	}
	paths := make([]string, 0, len(recipe.files))
	for _, file := range recipe.files {
		paths = append(paths, filepath.Join(capture, file.name))
	}
	if request.Directory {
		paths = []string{capture}
	}
	result, err := v3.VerifyPaths(t.Context(), paths, opts)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != recipe.verdict {
		t.Fatalf("got %q, want %q, findings: %+v", result.Verdict, recipe.verdict, result.Findings)
	}
	if recipe.code != "" && !slices.ContainsFunc(result.Findings, func(f v3.Finding) bool {
		return f.Code == recipe.code
	}) {
		t.Fatalf("missing targeted finding %s among %+v", recipe.code, result.Findings)
	}
	for _, extra := range recipe.extraInvalid {
		if !slices.ContainsFunc(result.Findings, func(f v3.Finding) bool { return f.Class == "invalid" && f.Code == extra }) {
			t.Fatalf("missing additional finding %s among %+v", extra, result.Findings)
		}
	}
	for _, f := range result.Findings {
		if f.Class == "invalid" && recipe.code != f.Code && !slices.Contains(recipe.extraInvalid, f.Code) {
			t.Fatalf("unexpected invalid finding %s for target %s", f.Code, recipe.code)
		}
	}
	full, err := result.JSON()
	if err != nil {
		t.Fatal(err)
	}
	projection, err := result.Projection()
	if err != nil {
		t.Fatal(err)
	}
	special := v3CheckSpecial(t, recipe, paths, opts, full)
	outputs := append([]v3File{{"expect.json", append(full, '\n')}, {"projection.json", append(projection, '\n')}}, special...)
	v3WriteFixtures(t, directory, recipe.files, requestJSON, outputs)
}

func v3WriteFixtures(t *testing.T, directory string, inputs []v3File, request []byte, outputs []v3File) {
	t.Helper()
	for _, file := range inputs {
		v3Fixture(t, directory, file.name, file.bytes)
	}
	v3Fixture(t, directory, "request.json", request)
	for _, file := range outputs {
		v3Fixture(t, directory, file.name, file.bytes)
	}
}

func v3Fixture(t *testing.T, directory, name string, want []byte) {
	t.Helper()
	target := filepath.Join(directory, name)
	if *updateReceiptV3 {
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, want, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	actual, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		t.Fatalf("read generated fixture %s: %v", target, err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatalf("generated fixture drift: %s", target)
	}
}
