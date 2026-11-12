// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// rawViewAccessKeyID has a valid AWS access key id prefix and length. It is
// not the published documentation example.
func rawViewAccessKeyID() string {
	return "AKIA" + "0123456789ABCDEF"
}

// rawViewMisorderedBase64Split cuts the standard base64 of secret into three
// pieces, each shorter than a decodable token, whose lexicographic order
// differs from source order. A sorted join cannot rebuild the token.
func rawViewMisorderedBase64Split(t *testing.T, secret string) []string {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	for i := 4; i <= len(encoded)-8; i++ {
		for j := i + 4; j <= len(encoded)-4; j++ {
			parts := []string{encoded[:i], encoded[i:j], encoded[j:]}
			if len(parts[0]) >= 32 || len(parts[1]) >= 32 || len(parts[2]) >= 32 {
				continue
			}
			sorted := slices.Clone(parts)
			slices.Sort(sorted)
			if strings.Join(sorted, "") != encoded {
				return parts
			}
		}
	}
	t.Fatal("no misordered split")
	return nil
}

func rawViewJSONUnicodeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		_, _ = fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

func rawViewScanJSONBody(t *testing.T, sc *scanner.Scanner, body string) BodyScanResult {
	t.Helper()
	_, result := scanRequestBody(t.Context(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    1 << 20,
		Scanner:     sc,
		Action:      config.ActionBlock,
		Target:      "https://api.vendor.example/upload",
	})
	return result
}

func rawViewHasPattern(matches []scanner.TextDLPMatch, name string) bool {
	for _, match := range matches {
		if match.PatternName == name {
			return true
		}
	}
	return false
}

// TestScanRequestBody_JSONStringSplitCredentialBlocks covers a credential
// encoded and split across several JSON strings. A receiver concatenates the
// strings in source order and decodes them. The extracted-field views scan
// each piece alone, and the sorted join puts them out of order, so only the
// raw document keeps the token whole.
func TestScanRequestBody_JSONStringSplitCredentialBlocks(t *testing.T) {
	secret := rawViewAccessKeyID()
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	misordered := rawViewMisorderedBase64Split(t, secret)
	hexEncoded := hex.EncodeToString([]byte(secret))
	inOrder := []string{encoded[:8], encoded[8:16], encoded[16:]}

	tests := []struct {
		name  string
		body  string
		parts []string
		// decode recovers the secret from the joined parts, as the receiver does.
		decode func(string) ([]byte, error)
	}{
		{
			name:   "base64 array, pieces out of sorted order",
			body:   `{"k":["` + misordered[0] + `","` + misordered[1] + `","` + misordered[2] + `"]}`,
			parts:  misordered,
			decode: base64.StdEncoding.DecodeString,
		},
		{
			// The key adds one base64-alphabet byte ahead of the payload, so a
			// view that joins every extracted string shifts the decode window.
			name:   "base64 array in sorted order after a one-letter key",
			body:   `{"k":["` + inOrder[0] + `","` + inOrder[1] + `","` + inOrder[2] + `"]}`,
			parts:  inOrder,
			decode: base64.StdEncoding.DecodeString,
		},
		{
			name:   "hex array",
			body:   `{"k":["` + hexEncoded[:12] + `","` + hexEncoded[12:24] + `","` + hexEncoded[24:] + `"]}`,
			parts:  []string{hexEncoded[:12], hexEncoded[12:24], hexEncoded[24:]},
			decode: hex.DecodeString,
		},
		{
			name:   "base64 array written as JSON unicode escapes",
			body:   `{"k":["` + rawViewJSONUnicodeEscape(misordered[0]) + `","` + rawViewJSONUnicodeEscape(misordered[1]) + `","` + rawViewJSONUnicodeEscape(misordered[2]) + `"]}`,
			parts:  misordered,
			decode: base64.StdEncoding.DecodeString,
		},
	}

	sc := scanner.MustNew(testScannerConfig())
	defer sc.Close()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := tt.decode(strings.Join(tt.parts, "")); err != nil || string(got) != secret {
				t.Fatalf("receiver recovery failed: %q %v", got, err)
			}
			result := rawViewScanJSONBody(t, sc, tt.body)
			if result.Clean || !rawViewHasPattern(result.DLPMatches, "AWS Access ID") {
				t.Fatalf("split credential passed the body scan: clean=%v reason=%q dlp=%+v", result.Clean, result.Reason, result.DLPMatches)
			}
			if result.Action != config.ActionBlock {
				t.Fatalf("action = %q, want block", result.Action)
			}
		})
	}
}

// TestScanRequestBody_JSONRawViewKeepsFieldFindings checks that the raw
// document view leaves the finding list unchanged, entry for entry, when the
// field views already found every value. The raw view sees every field
// again, often under another encoding label.
func TestScanRequestBody_JSONRawViewKeepsFieldFindings(t *testing.T) {
	secret := rawViewAccessKeyID()
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	sc := scanner.MustNew(testScannerConfig())
	defer sc.Close()

	for _, body := range []string{
		`{"token":"` + encoded + `"}`,
		`{"token":"` + secret + `"}`,
		`{"a":"` + secret + `","b":["` + encoded + `"]}`,
		`{"card":"4111 1111 1111 1111","n":[4111,1111,1111,1111]}`,
	} {
		extracted := extractBodyTextForDLP([]byte(body), BodyScanRequest{ContentType: "application/json"})
		if extracted.Err != "" || extracted.RawDocument != body {
			t.Fatalf("extraction: err=%q raw=%q", extracted.Err, extracted.RawDocument)
		}
		for _, sigv4 := range []bool{false, true} {
			views := bodyDLPExtractionViews([]byte(body), extracted, nil)[0]
			with := scanBodyTextViewsForDLPWithAudience(t.Context(), sc, views, "", nil, nil, sigv4, nil, "", nil)
			views.rawDocument = ""
			without := scanBodyTextViewsForDLPWithAudience(t.Context(), sc, views, "", nil, nil, sigv4, nil, "", nil)
			if len(without) == 0 {
				t.Fatalf("control body was clean: %s", body)
			}
			if fmt.Sprintf("%+v", with) != fmt.Sprintf("%+v", without) {
				t.Fatalf("raw view changed the findings for %s (sigv4=%v)\nwith:    %+v\nwithout: %+v", body, sigv4, with, without)
			}
		}
	}
}

// TestExtractBodyTextForDLP_RawDocumentOmitsProviderCiphertext checks that
// the raw view leaves out trusted provider ciphertext, which the field views
// scan only with provider-opaque provenance. The JSON spelling of the value
// may use escapes, so the span comes from decoder offsets, not a search.
func TestExtractBodyTextForDLP_RawDocumentOmitsProviderCiphertext(t *testing.T) {
	ciphertext := highEntropyFiller(260) + "/" + fakeGitHubToken() + "/" + highEntropyFiller(260)
	for _, spelled := range []string{ciphertext, strings.ReplaceAll(ciphertext, "/", `\/`)} {
		body := []byte(`{"input":[{"content":[{"type":"reasoning","encrypted_content":"` + spelled + `"},{"type":"text","text":"after"}]}]}`)
		extracted := extractBodyTextForDLP(body, BodyScanRequest{
			ContentType:                  "application/json",
			Host:                         testTrustedProviderHost,
			Path:                         testTrustedProviderPath,
			TrustedProviderOpaqueRequest: testTrustedProviderOpaqueRequest,
		})
		if extracted.Err != "" {
			t.Fatalf("Err = %q", extracted.Err)
		}
		if len(extracted.ProviderOpaqueTexts) != 1 {
			t.Fatalf("ProviderOpaqueTexts = %d, want 1", len(extracted.ProviderOpaqueTexts))
		}
		want := `{"input":[{"content":[{"type":"reasoning","encrypted_content":""},{"type":"text","text":"after"}]}]}`
		if extracted.RawDocument != want {
			t.Fatalf("RawDocument = %q\nwant %q", extracted.RawDocument, want)
		}
	}

	// An untrusted request keeps the value in the raw document.
	body := []byte(`{"input":[{"content":[{"encrypted_content":"` + ciphertext + `"}]}]}`)
	extracted := extractBodyTextForDLP(body, BodyScanRequest{ContentType: "application/json", Host: "api.vendor.example"})
	if extracted.RawDocument != string(body) {
		t.Fatalf("untrusted RawDocument = %q, want the body", extracted.RawDocument)
	}
}

// BenchmarkScanRequestBody_JSONChat measures the request-body scan of a
// chat-shaped JSON body, the common outbound body for agent traffic.
func BenchmarkScanRequestBody_JSONChat(b *testing.B) {
	sc := scanner.MustNew(testScannerConfig())
	defer sc.Close()
	paragraph := "The proxy reads `config.yaml` at start-up (see docs/guide.md, section 3.2) and reloads it on SIGHUP; " +
		"values such as max_body_bytes=1048576 or \"action\": \"block\" apply per request. Run `make test` before you push.\n"
	content := strings.Repeat(paragraph, (64<<10)/len(paragraph))
	msg, err := json.Marshal(map[string]any{
		"model": "m",
		"messages": []map[string]string{
			{"role": "system", "content": "Answer briefly."},
			{"role": "user", "content": content},
			{"role": "assistant", "content": content[:len(content)/2]},
			{"role": "user", "content": "Summarise the above."},
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	body := string(msg)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		_, result := scanRequestBody(b.Context(), BodyScanRequest{
			Body:        strings.NewReader(body),
			ContentType: "application/json",
			MaxBytes:    1 << 20,
			Scanner:     sc,
			Action:      config.ActionBlock,
		})
		if !result.Clean {
			b.Fatalf("benchmark body was not clean: %+v", result)
		}
	}
}
