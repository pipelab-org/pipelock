// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"filippo.io/edwards25519"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

func v3LayoutRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	s := v3New(t)
	valid := s.finish(t)
	head := s.records[0]
	first := s.file(0, 1).name
	recipes := []v3Recipe{{group: 1, name: "valid-line", verdict: "VALID", files: []v3File{valid}}}
	change := []struct{ name, from, to string }{
		{"outer-whitespace", "{\"payloadType\":", "{ \"payloadType\":"},
		{"extra-outer-member", "],\"payload\":", "],\"label\":1,\"payload\":"},
		{"second-payload", "}}\n", "},\"payload\":{}}\n"},
		{"empty-signatures", string(head.line[bytes.IndexByte(head.line, '[')+1 : bytes.IndexByte(head.line, ']')]), ""},
		{"missing-padding", "==\"}", "=\"}"},
	}
	for _, tc := range change {
		recipes = append(recipes, v3Invalid(1, tc.name, "LINE_LAYOUT", v3File{first, v3LineTransform(t, head, tc.from, tc.to)}))
	}
	signatures := bytes.Index(head.line, []byte("\"signatures\":"))
	payloadStart := bytes.Index(head.line, []byte("],\"payload\":"))
	reordered := slices.Concat([]byte("{"), head.line[signatures:payloadStart+2],
		head.line[1:signatures], head.line[payloadStart+2:])
	recipes = append(recipes, v3Invalid(1, "outer-order", "LINE_LAYOUT", v3File{first, reordered}))
	start := bytes.Index(head.line, []byte("\"sig\":\"")) + len("\"sig\":\"")
	end := start + 88
	decoration := []struct {
		name   string
		change func([]byte)
	}{
		{"urlsafe-signature", func(s []byte) {
			if i := bytes.IndexAny(s, "+/"); i >= 0 {
				if s[i] == '+' {
					s[i] = '-'
				} else {
					s[i] = '_'
				}
			} else {
				s[0] = '-'
			}
		}},
		{"nonzero-padding", func(s []byte) {
			const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
			s[len(s)-3] = alphabet[strings.IndexByte(alphabet, s[len(s)-3])+1]
		}},
	}
	for _, tc := range decoration {
		line := bytes.Clone(head.line)
		tc.change(line[start:end])
		recipes = append(recipes, v3Invalid(1, tc.name, "LINE_LAYOUT", v3File{first, line}))
	}
	entryStart := bytes.IndexByte(head.line, '[') + 1
	entryEnd := bytes.IndexByte(head.line, ']')
	entry := head.line[entryStart:entryEnd]
	for _, tc := range []struct {
		name, firstKey string
		extras         int
	}{
		{"too-many-signatures", strings.Repeat("0", 64), 4},
		{"duplicate-keyid", "", 1},
		{"unsorted-keyids", strings.Repeat("0", 64), 1},
	} {
		var signatureList bytes.Buffer
		if tc.name != "too-many-signatures" {
			signatureList.Write(entry)
		}
		for i := range tc.extras {
			if tc.firstKey == "" {
				signatureList.WriteByte(',')
				signatureList.Write(entry)
			} else {
				if signatureList.Len() > 0 {
					signatureList.WriteByte(',')
				}
				fmt.Fprintf(&signatureList, "{\"keyid\":\"sha256:%064x\",\"sig\":\"%s\"}", i, string(head.line[start:end]))
			}
		}
		if tc.name == "too-many-signatures" {
			signatureList.WriteByte(',')
			signatureList.Write(entry)
		}
		line := append(bytes.Clone(head.line[:entryStart]), signatureList.Bytes()...)
		line = append(line, head.line[entryEnd:]...)
		recipes = append(recipes, v3Invalid(1, tc.name, "LINE_LAYOUT", v3File{first, line}))
	}
	recipes = append(recipes,
		v3Invalid(1, "bom", "LINE_LAYOUT", v3File{first, append([]byte{0xef, 0xbb, 0xbf}, head.line...)}),
		v3Invalid(1, "damaged-first-line", "LINE_LAYOUT", v3File{first, append([]byte("broken\n"), valid.bytes...)}),
		v3Invalid(1, "unclaimed-v3", "V3_CONTENT_UNCLAIMED", v3File{"receipt.jsonl", valid.bytes}),
		v3Invalid(1, "unrecognized-input", "UNRECOGNIZED_FILE", v3File{"receipt.json", []byte("{}")}),
		v3Invalid(1, "empty-v3-file", "FILE_LAYOUT", v3File{first, nil}),
		v3Invalid(1, "filename-start", "FILE_LAYOUT", v3File{s.file(1, 2).name, valid.bytes}),
		v3Recipe{group: 1, name: "empty-input", code: "NO_EVIDENCE", verdict: "INCOMPLETE"},
		v3Recipe{
			group: 1, name: "unsupported-version", code: "UNKNOWN_PROFILE", verdict: "UNSUPPORTED",
			files: []v3File{{strings.Replace(first, "v3", "v4", 1), valid.bytes}},
		},
		v3Recipe{
			group: 1, name: "unsupported-payload", code: "UNKNOWN_PROFILE", verdict: "UNSUPPORTED",
			files: []v3File{{first, v3LineTransform(t, head, "v3+json", "v4+json")}},
		},
		v3Recipe{
			group: 1, name: "explicit-v3", verdict: "VALID", request: v3Request{Format: "v3"},
			files: []v3File{{"receipt.jsonl", valid.bytes}},
		},
	)
	for _, delta := range []int{0, 1} {
		line := v3New(t)
		line.add(t, "detail", v3Common{"text": "x"}, nil)
		last := line.records[1]
		text := strings.Repeat("x", (1<<20)+delta-len(last.line)+1)
		payload := bytes.Replace(last.payload, []byte("\"text\":\"x\""), []byte("\"text\":\""+text+"\""), 1)
		line.records[1] = v3Sign(payload, line.key)
		file := line.finish(t)
		if delta == 0 {
			recipes = append(recipes, v3Recipe{group: 1, name: "maximum-line", verdict: "VALID", files: []v3File{file}})
		} else {
			recipes = append(recipes, v3Invalid(1, "overlong-line", "LINE_SIZE", file))
		}
	}
	unicode := v3New(t)
	unicode.add(t, "detail", v3Common{"text": "a\u2028b\u0085c\u2029d"}, nil)
	raw := unicode.records[1].payload
	raw = bytes.ReplaceAll(raw, []byte("\\u2028"), []byte("\u2028"))
	raw = bytes.ReplaceAll(raw, []byte("\\u2029"), []byte("\u2029"))
	unicode.records[1] = v3Sign(raw, unicode.key)
	return append(recipes, v3Recipe{group: 1, name: "literal-line-separators", verdict: "VALID", files: []v3File{unicode.finish(t)}})
}

func v3PayloadRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	var recipes []v3Recipe
	for _, row := range []struct{ name, body string }{
		{"member-order", "{\"z\":1,\"a\":2}"},
		{"duplicate-member", "{\"a\":1,\"a\":2}"},
		{"payload-whitespace", "{\"a\": 1}"},
		{"null", "{\"a\":null}"},
		{"float", "{\"a\":1.2}"},
		{"exponent", "{\"a\":1e2}"},
		{"negative-zero", "{\"a\":-0}"},
		{"leading-zero", "{\"a\":01}"},
		{"integer-range", "{\"a\":9007199254740992}"},
		{"uppercase-member", "{\"A\":1}"},
		{"nonascii-member", "{\"é\":1}"},
		{"escaped-printable", "{\"a\":\"\\u0061\"}"},
		{"escaped-slash", "{\"a\":\"\\/\"}"},
		{"escaped-short-control", "{\"a\":\"\\u000a\"}"},
		{"uppercase-hex-control", "{\"a\":\"\\u001F\"}"},
		{"literal-control", "{\"a\":\"\x01\"}"},
		{"invalid-utf8", "{\"a\":\"\xff\"}"},
		{"encoded-surrogate", "{\"a\":\"\\ud800\"}"},
		{"excess-depth", "{\"a\":" + strings.Repeat("[", 15) + "0" + strings.Repeat("]", 15) + "}"},
	} {
		s := v3New(t)
		s.add(t, "detail", v3Common{"marker": true}, nil)
		s.records[1] = v3Sign(bytes.Replace(s.records[1].payload, []byte("{\"marker\":true}"), []byte(row.body), 1), s.key)
		recipes = append(recipes, v3Invalid(3, row.name, "PAYLOAD_LAYOUT", s.finish(t)))
	}
	for _, row := range []struct{ name, body string }{
		{"canonical-escapes", "{\"a\":\"\\\"\\\\\\b\\f\\n\\r\\t\\u001f\\\\u0061<>&/\u007f\"}"},
		{"maximum-depth", "{\"a\":" + strings.Repeat("[", 14) + "0" + strings.Repeat("]", 14) + "}"},
		{"integer-at-bound", "{\"a\":-9007199254740991}"},
	} {
		s := v3New(t)
		s.add(t, "detail", v3Common{"marker": true}, nil)
		s.records[1] = v3Sign(bytes.Replace(s.records[1].payload, []byte("{\"marker\":true}"), []byte(row.body), 1), s.key)
		recipes = append(recipes, v3Recipe{group: 3, name: row.name, verdict: "VALID", files: []v3File{s.finish(t)}})
	}
	s := v3New(t)
	s.add(t, "action", v3DefaultAction(), func(obj v3Common) { obj["crit"] = []string{} })
	recipes = append(recipes, v3Invalid(3, "empty-optional-member", "COMMON_SCHEMA", s.finish(t)))
	return recipes
}

func v3SignatureRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	var recipes []v3Recipe
	for _, row := range []struct {
		name, code string
		alter      func([]byte)
	}{
		{"signature-bit", "SIGNATURE_EQUATION", func(sig []byte) { sig[32] ^= 1 }},
		{"scalar-at-order", "SIGNATURE_SCALAR", func(sig []byte) {
			order, _ := hex.DecodeString("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
			copy(sig[32:], order)
		}},
		{"scalar-above-order", "SIGNATURE_SCALAR", func(sig []byte) { sig[63] = 0xff }},
		{"identity-r", "SIGNATURE_POINT", func(sig []byte) { clear(sig[:32]); sig[0] = 1 }},
		{"non-canonical-r", "SIGNATURE_POINT", func(sig []byte) { clear(sig[:32]); sig[0] = 1; sig[31] = 0x80 }},
		{"point-off-curve", "SIGNATURE_POINT", func(sig []byte) { clear(sig[:32]); sig[0] = 2 }},
	} {
		s := v3New(t)
		valid := s.finish(t)
		payload := s.records[0].payload
		sig := ed25519.Sign(s.key, v3.PAE(payload))
		row.alter(sig)
		first := v3SignWith(payload, v3.Digest(v3Public(s.key)), sig)
		recipes = append(recipes, v3Invalid(2, row.name, row.code, v3File{valid.name, slices.Concat(first.line, s.records[1].line)}))
	}
	s := v3New(t)
	file := s.finish(t)
	flipped := v3LineTransform(t, s.records[0], "\"product\":\"Pipelock\"", "\"product\":\"pipelock\"")
	recipes = append(recipes, v3Invalid(2, "payload-bit", "SIGNATURE_EQUATION", v3File{file.name, slices.Concat(flipped, s.records[1].line)}))
	first := s.records[0]
	wrong := ed25519.Sign(v3Key("other"), v3.PAE(first.payload))
	missing := v3SignWith(first.payload, v3.Digest(v3Public(v3Key("other"))), wrong)
	recipes = append(recipes, v3Invalid(2, "signer-missing", "SIGNER_MISSING", v3File{file.name, slices.Concat(missing.line, s.records[1].line)}))
	bad := v3SignWith(first.payload, v3.Digest(v3Public(s.key)), wrong)
	recipes = append(recipes, v3Invalid(2, "signer-wrong-key", "SIGNATURE_EQUATION", v3File{file.name, slices.Concat(bad.line, s.records[1].line)}))
	entry := fmt.Sprintf("{\"keyid\":\"sha256:%064x\",\"sig\":\"%s\"},", 0, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	extra := v3LineTransform(t, first, "\"signatures\":[", "\"signatures\":["+entry)
	// The all-zero compressed point is a small-order public key in the
	// Ed25519 conformance inputs. An ordinary signature cannot validate it.
	small := make([]byte, 32)
	id := v3.Digest(small)
	body := v3DefaultOpen(s.key, s.lineage)
	body["signer_key"].(v3Common)["public"] = base64.StdEncoding.EncodeToString(small)
	smallStream := v3New(t)
	smallStream.records = nil
	smallStream.add(t, "stream_open", body, func(p v3Common) { p["signer"] = id })
	payloadSmall := smallStream.records[0].payload
	opener := v3SignWith(payloadSmall, id, ed25519.Sign(s.key, v3.PAE(payloadSmall)))
	recipes = append(recipes, v3Invalid(2, "small-order-key", "SIGNATURE_KEY", v3File{file.name, opener.line}))
	return append(append(recipes, v3WycheproofRecipes(t)...),
		v3Recipe{group: 2, name: "valid-signature", verdict: "VALID", files: []v3File{file}},
		v3Recipe{group: 2, name: "ignore-extra-signature", verdict: "VALID", files: []v3File{{file.name, slices.Concat(extra, s.records[1].line)}}},
	)
}

// The raw suite tests its original signed messages. These receipts preserve
// each rejected key and signature, with the signed-message container changed
// to the receipt preimage. The positive control signs that new preimage.
func v3WycheproofRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	data, err := os.ReadFile("testdata/v3/wycheproof/ed25519.json")
	if err != nil {
		t.Fatal(err)
	}
	var suite struct {
		Vectors []struct {
			ID        int    `json:"tcId"`
			Public    string `json:"public_key"`
			Signature string `json:"sig"`
			Result    string
			Flags     []string
		}
	}
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	if len(suite.Vectors) == 0 {
		t.Fatal("no signature cases")
	}
	var recipes []v3Recipe
	for _, row := range suite.Vectors {
		name := fmt.Sprintf("wycheproof-%03d", row.ID)
		s := v3New(t)
		if row.Result == "valid" {
			recipes = append(recipes, v3Recipe{group: 2, name: name, verdict: "VALID", files: []v3File{s.finish(t)}})
			continue
		}
		public, keyErr := hex.DecodeString(row.Public)
		sig, sigErr := hex.DecodeString(row.Signature)
		if keyErr != nil || sigErr != nil || len(public) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			t.Fatalf("bad source vector %d: %v, %v", row.ID, keyErr, sigErr)
		}
		code := "SIGNATURE_EQUATION"
		switch {
		case slices.Contains(row.Flags, "SmallOrderPublicKey"), slices.Contains(row.Flags, "MixedOrderPublicKey"):
			code = "SIGNATURE_KEY"
		case slices.Contains(row.Flags, "SignatureMalleability"):
			code = "SIGNATURE_SCALAR"
		case !v3ConformancePoint(sig[:32]):
			code = "SIGNATURE_POINT"
		}
		s.records = nil
		body := v3DefaultOpen(s.key, s.lineage)
		body["signer_key"].(v3Common)["public"] = base64.StdEncoding.EncodeToString(public)
		id := v3.Digest(public)
		s.add(t, "stream_open", body, func(p v3Common) { p["signer"] = id })
		s.records[0] = v3SignWith(s.records[0].payload, id, sig)
		recipes = append(recipes, v3Invalid(2, name, code, s.file(0, 1)))
	}
	return recipes
}

func v3ConformancePoint(encoded []byte) bool {
	p, err := new(edwards25519.Point).SetBytes(encoded)
	return err == nil && bytes.Equal(p.Bytes(), encoded) && p.Equal(edwards25519.NewIdentityPoint()) == 0
}

func v3StreamRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	var recipes []v3Recipe
	for _, row := range []struct {
		name, code string
		change     func(*v3Stream)
	}{
		{"sequence-gap", "STREAM_ORDER", func(s *v3Stream) { s.add(t, "heartbeat", v3Heartbeat(), func(m v3Common) { m["seq"] = 2 }) }},
		{"repeated-sequence", "STREAM_ORDER", func(s *v3Stream) { s.add(t, "heartbeat", v3Heartbeat(), func(m v3Common) { m["seq"] = 0 }) }},
		{"wrong-previous", "STREAM_ORDER", func(s *v3Stream) {
			s.add(t, "heartbeat", v3Heartbeat(), func(m v3Common) { m["prev"] = v3.Digest([]byte("other")) })
		}},
		{"spliced-stream", "STREAM_ORDER", func(s *v3Stream) {
			s.add(t, "heartbeat", v3Heartbeat(), func(m v3Common) { m["stream"] = strings.Repeat("3", 32) })
		}},
		{"data-after-close", "DATA_AFTER_CLOSE", func(s *v3Stream) { s.close(t); s.add(t, "heartbeat", v3Heartbeat(), nil) }},
	} {
		s := v3New(t)
		row.change(s)
		file := s.finish(t)
		recipes = append(recipes, v3Invalid(4, row.name, row.code, file))
	}
	s := v3New(t)
	s.records = nil
	s.add(t, "stream_open", v3DefaultOpen(s.key, s.lineage), func(m v3Common) { m["prev"] = v3.Digest(nil) })
	recipes = append(recipes, v3Invalid(4, "wrong-genesis", "STREAM_ORDER", s.finish(t)))
	s = v3New(t)
	s.records = nil
	s.add(t, "heartbeat", v3Heartbeat(), nil)
	recipes = append(recipes, v3Invalid(4, "missing-open", "STREAM_ORDER", s.finish(t)))
	s = v3New(t)
	s.add(t, "heartbeat", v3Common{"beat": 2, "durability_blocks": 0, "fsync_errors_gated": 0}, func(m v3Common) { m["ts"] = "2025-01-01T00:00:00.000Z" })
	recipes = append(recipes, v3Recipe{group: 4, name: "clock-regression", code: "CLOCK_REGRESSION", verdict: "VALID", files: []v3File{s.finish(t)}})
	s = v3New(t)
	beat := v3Heartbeat()
	beat["beat"] = 2
	s.add(t, "heartbeat", beat, nil)
	recipes = append(recipes, v3Recipe{group: 4, name: "heartbeat-gap", code: "HEARTBEAT_GAP", verdict: "VALID", files: []v3File{s.finish(t)}})
	s = v3New(t)
	recipes = append(recipes, v3Recipe{group: 4, name: "open-end", code: "END_UNPROVEN", verdict: "VALID PREFIX, END UNPROVEN", files: []v3File{s.file(0, 1)}})
	s = v3New(t)
	torn := s.file(0, 1)
	torn.bytes = append(torn.bytes, []byte("{\"incomplete\"")...)
	recipes = append(recipes, v3Recipe{group: 4, name: "torn-tail", code: "TORN_TAIL", verdict: "VALID PREFIX, END UNPROVEN", files: []v3File{torn}})
	file := s.finish(t)
	duplicate := v3File{"copy/" + file.name, file.bytes}
	recipes = append(recipes, v3Recipe{group: 4, name: "copied-records", verdict: "VALID", files: []v3File{file, duplicate}})
	bad := v3File{"copy/" + file.name, slices.Concat([]byte{0xef, 0xbb, 0xbf}, file.bytes)}
	recipes = append(recipes, v3Recipe{group: 4, name: "damaged-copy", code: "LINE_LAYOUT", verdict: "INVALID", files: []v3File{file, bad}})
	return recipes
}
