// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func uploadArchive(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for name, data := range members {
		f, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func uploadMultipart(t *testing.T, data []byte) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="file"; filename="upload.bin"`)
	h.Set("Content-Type", "video/mp4")
	f, err := w.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return w.FormDataContentType(), buf.Bytes()
}

type uploadPolicy struct {
	action string
	audit  bool
}

// exerciseUpload uses a real upstream and counts actual deliveries. Hashing the
// full received request also verifies multipart framing is preserved on allow.
func exerciseUpload(t *testing.T, surface string, policy uploadPolicy, mediaType string, body []byte) (int, int32, bool, string) {
	t.Helper()
	var hits atomic.Int32
	var intact atomic.Bool
	original := sha256.Sum256(body)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		hits.Add(1)
		intact.Store(sha256.Sum256(data) == original)
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	var response *http.Response
	if surface == "reverse" {
		cfg := reverseTestConfig()
		cfg.RequestBodyScanning.Action = policy.action
		enforce := !policy.audit
		cfg.Enforce = &enforce
		cfg.AdaptiveEnforcement.Enabled = false
		// Isolate file inspection: existing opaque-content entropy independently
		// blocks base64 attachments, including clean Office documents.
		cfg.RequestBodyScanning.ContentEntropyEnabled = false
		server := reverseTestSetup(t, cfg, handler)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, server.URL+"/upload.bin", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", mediaType)
		response, err = server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		cache, pool, cfg, _, _, m := testInterceptSetup(t)
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = policy.action
		enforce := !policy.audit
		cfg.Enforce = &enforce
		cfg.AdaptiveEnforcement.Enabled = false
		// Isolate file inspection: existing opaque-content entropy independently
		// blocks base64 attachments, including clean Office documents.
		cfg.RequestBodyScanning.ContentEntropyEnabled = false
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
		cfg.Internal = nil
		cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		cfg.APIAllowlist = nil
		cfg.ForwardProxy.Enabled = true
		logger := audit.NewNop()
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		p, err := New(cfg, logger, sc, m)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		if surface == "intercept" {
			upstream := httptest.NewTLSServer(handler)
			defer upstream.Close()
			req, reqErr := http.NewRequestWithContext(t.Context(), http.MethodPut, upstream.URL+"/upload.bin", bytes.NewReader(body))
			if reqErr != nil {
				t.Fatal(reqErr)
			}
			req.Header.Set("Content-Type", mediaType)
			response = interceptAndRequestWithRecorder(t, interceptRequestOptions{Upstream: upstream, Cache: cache, Pool: pool, Config: cfg, Scanner: sc, Logger: logger, Metrics: m, Request: req, Proxy: p, Agent: "upload-test", ActorAuth: envelope.ActorAuthBound})
		} else {
			upstream := httptest.NewServer(handler)
			defer upstream.Close()
			server := httptest.NewServer(p.Handler())
			defer server.Close()
			proxyURL, parseErr := url.Parse(server.URL)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			req, reqErr := http.NewRequestWithContext(t.Context(), http.MethodPut, upstream.URL+"/upload.bin", bytes.NewReader(body))
			if reqErr != nil {
				t.Fatal(reqErr)
			}
			req.Header.Set("Content-Type", mediaType)
			response, err = client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	defer func() { _ = response.Body.Close() }()
	message, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, hits.Load(), intact.Load(), string(message)
}

func TestUploadInspectionProducerTransports(t *testing.T) {
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		for _, name := range []string{"libreoffice-clean.docx", "libreoffice-seeded.docx", "pandoc-clean.docx", "pandoc-seeded.docx", "split-run.docx", "clean.xlsx", "seeded.xlsx", "clean.pptx", "seeded.pptx", "clean.odt", "seeded.odt", "clean.ods", "seeded.ods", "clean.pdf", "seeded.pdf"} {
			for _, carrier := range []string{"raw", "multipart", "json"} {
				t.Run(surface+"/"+name+"/"+carrier, func(t *testing.T) {
					data, err := os.ReadFile(filepath.Clean(filepath.Join("..", "fileinspect", "testdata", name)))
					if err != nil {
						t.Fatal(err)
					}
					mediaType := "video/mp4"
					if carrier == "multipart" {
						mediaType, data = uploadMultipart(t, data)
					}
					if carrier == "json" {
						mediaType = contentTypeJSON
						data = []byte(`{"attachments":[{"contentBytes":"` + base64.StdEncoding.EncodeToString(data) + `"}]}`)
					}
					wantBlock := (strings.Contains(name, "seeded") || name == "split-run.docx") && !strings.HasSuffix(name, ".pdf")
					status, hits, intact, reason := exerciseUpload(t, surface, uploadPolicy{config.ActionBlock, false}, mediaType, data)
					if wantBlock {
						if status != http.StatusForbidden || hits != 0 {
							t.Fatalf("status=%d hits=%d body=%s", status, hits, reason)
						}
					} else if status != http.StatusCreated || hits != 1 || !intact {
						t.Fatalf("clean/raw-PDF: status=%d hits=%d intact=%t body=%s", status, hits, intact, reason)
					}
				})
			}
		}
	}
}

func TestUploadInspectionUnreadablePolicy(t *testing.T) {
	clean := uploadArchive(t, map[string][]byte{"ordinary.txt": []byte("ordinary text")})
	encrypted := bytes.Clone(clean)
	c := bytes.Index(encrypted, []byte("PK\x01\x02"))
	encrypted[c+8] |= 1
	encrypted[6] |= 1
	crc := bytes.Clone(clean)
	crc[c+16] ^= 1
	method := bytes.Clone(clean)
	binary.LittleEndian.PutUint16(method[c+10:], 99)
	deep := clean
	for range extractJSONMaxDepth {
		deep = uploadArchive(t, map[string][]byte{"nested.zip": deep})
	}
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		for _, policy := range []uploadPolicy{{config.ActionBlock, false}, {config.ActionWarn, false}, {config.ActionBlock, true}} {
			for _, tc := range []struct {
				name string
				data []byte
			}{
				{"encrypted", encrypted},
				{"CRC", crc},
				{"method", method},
				{"trailer", clean[:len(clean)-1]},
				{"bomb", uploadArchive(t, map[string][]byte{"large.txt": bytes.Repeat([]byte("a"), 2*1024*1024)})},
				{"depth", deep},
				{"7z", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}},
				{"RAR", []byte("Rar!\x1a\x07\x01\x00")},
			} {
				for _, carrier := range []string{"raw", "multipart"} {
					t.Run(fmt.Sprintf("%s/%s/audit=%t/%s/%s", surface, policy.action, policy.audit, tc.name, carrier), func(t *testing.T) {
						mediaType, data := "application/octet-stream", tc.data
						if carrier == "multipart" {
							mediaType, data = uploadMultipart(t, data)
						}
						status, hits, intact, message := exerciseUpload(t, surface, policy, mediaType, data)
						if policy.action == config.ActionBlock && !policy.audit {
							if status != http.StatusForbidden || hits != 0 {
								t.Fatalf("status=%d hits=%d body=%s", status, hits, message)
							}
						} else if status != http.StatusCreated || hits != 1 || !intact {
							t.Fatalf("delivery: status=%d hits=%d intact=%t body=%s", status, hits, intact, message)
						}
					})
				}
			}
		}
	}
}

func TestUploadInspectionOfficeLocations(t *testing.T) {
	key := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	for _, path := range []string{"word/header1.xml", "word/footer1.xml", "word/comments.xml", "word/footnotes.xml", "docProps/core.xml", "docProps/custom.xml", "xl/worksheets/sheet2.xml", "xl/comments1.xml", "ppt/notesSlides/notesSlide1.xml", "ppt/comments/comment1.xml", "meta.xml"} {
		t.Run(path, func(t *testing.T) {
			data := uploadArchive(t, map[string][]byte{path: []byte(`<root><p>` + key + `</p></root>`)})
			status, hits, _, message := exerciseUpload(t, "intercept", uploadPolicy{config.ActionBlock, false}, "video/mp4", data)
			if status != http.StatusForbidden || hits != 0 {
				t.Fatalf("status=%d hits=%d body=%s", status, hits, message)
			}
		})
	}
	data := uploadArchive(t, map[string][]byte{"word/embeddings/document.bin": uploadArchive(t, map[string][]byte{"word/document.xml": []byte(`<p>` + key + `</p>`)}), "Thumbnails/thumbnail.png": []byte("\x89PNG\r\n\x1a\n\xff")})
	status, hits, _, message := exerciseUpload(t, "intercept", uploadPolicy{config.ActionBlock, false}, "video/mp4", data)
	if status != http.StatusForbidden || hits != 0 {
		t.Fatalf("nested status=%d hits=%d body=%s", status, hits, message)
	}
}

func TestUploadInspectionProducerHiddenSheet(t *testing.T) {
	data, err := os.ReadFile(filepath.Clean(filepath.Join("..", "fileinspect", "testdata", "seeded.xlsx")))
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	w := zip.NewWriter(&output)
	changed := false
	for _, f := range z.File {
		r, openErr := f.Open()
		if openErr != nil {
			t.Fatal(openErr)
		}
		part, readErr := io.ReadAll(r)
		_ = r.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if f.Name == "xl/workbook.xml" {
			// ECMA-376 SpreadsheetML sheet state attribute. The producer's
			// shared strings and worksheet content are retained byte for byte.
			if bytes.Contains(part, []byte(` state="visible"`)) {
				part = bytes.Replace(part, []byte(` state="visible"`), []byte(` state="hidden"`), 1)
			} else {
				part = bytes.Replace(part, []byte(`<sheet `), []byte(`<sheet state="hidden" `), 1)
			}
			changed = bytes.Contains(part, []byte(`state="hidden"`))
		}
		file, writeErr := w.Create(f.Name)
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		if _, writeErr = file.Write(part); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("producer worksheet state was not changed")
	}
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		t.Run(surface, func(t *testing.T) {
			status, hits, _, message := exerciseUpload(t, surface, uploadPolicy{config.ActionBlock, false}, "video/mp4", output.Bytes())
			if status != http.StatusForbidden || hits != 0 {
				t.Fatalf("hidden sheet: status=%d hits=%d body=%s", status, hits, message)
			}
		})
	}
}

func TestUploadInspectionReasonAndFailClosed(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	for _, auditMode := range []bool{false, true} {
		for _, action := range []string{config.ActionBlock, config.ActionWarn} {
			data := []byte("Rar!\x1a\x07\x01\x00")
			body, result := scanRequestBody(context.Background(), BodyScanRequest{Body: bytes.NewReader(data), Scanner: sc, MaxBytes: 4096, ContentType: "video/mp4", Action: action, AuditMode: auditMode})
			want := action == config.ActionBlock && !auditMode
			if result.Clean || result.FileInspectionIncomplete == "" || !strings.Contains(result.Reason, "RAR upload not fully read") || !strings.Contains(result.Reason, "request_body_scanning.action") || isFailClosedBodyResult(result, body) != want || !bytes.Equal(body, data) {
				t.Fatalf("action=%s audit=%t result=%+v", action, auditMode, result)
			}
		}
	}
}

func TestUploadInspectionMultipartBoundaries(t *testing.T) {
	data, err := os.ReadFile(filepath.Clean(filepath.Join("..", "fileinspect", "testdata", "libreoffice-seeded.docx")))
	if err != nil {
		t.Fatal(err)
	}
	for _, transfer := range []string{"base64", "quoted-printable"} {
		t.Run(transfer, func(t *testing.T) {
			var buf bytes.Buffer
			w := multipart.NewWriter(&buf)
			h := textproto.MIMEHeader{}
			h.Set("Content-Disposition", `form-data; name="file"; filename="upload.bin"`)
			h.Set("Content-Type", "video/mp4")
			h.Set("Content-Transfer-Encoding", transfer)
			part, createErr := w.CreatePart(h)
			if createErr != nil {
				t.Fatal(createErr)
			}
			if transfer == "base64" {
				_, err = io.WriteString(part, base64.StdEncoding.EncodeToString(data))
			} else {
				q := quotedprintable.NewWriter(part)
				_, err = q.Write(data)
				if err == nil {
					err = q.Close()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = w.Close(); err != nil {
				t.Fatal(err)
			}
			status, hits, _, message := exerciseUpload(t, "intercept", uploadPolicy{config.ActionBlock, false}, w.FormDataContentType(), buf.Bytes())
			if status != http.StatusForbidden || hits != 0 {
				t.Fatalf("status=%d hits=%d body=%s", status, hits, message)
			}
		})
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	h := textproto.MIMEHeader{}
	// RFC 5987 filename metadata decodes to a signature while the wire header
	// remains valid ASCII. It must stay a metadata DLP view, not file input.
	h.Set("Content-Disposition", `form-data; name="ordinary"; filename*=UTF-8''PK%03%04label`)
	part, err := w.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(part, "ordinary text"); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	texts := extractBodyTextForDLP(buf.Bytes(), BodyScanRequest{ContentType: w.FormDataContentType(), MaxBytes: 4096})
	if texts.Err != "" {
		t.Fatalf("multipart fixture did not parse: %s", texts.Err)
	}
	metadataFound := false
	for _, text := range texts.GenericTexts {
		metadataFound = metadataFound || strings.HasPrefix(text, "PK\x03\x04")
	}
	if !metadataFound {
		t.Fatal("decoded filename signature is absent from metadata views")
	}
	_, incomplete := inspectUploadTextViews(t.Context(), buf.Bytes(), BodyScanRequest{ContentType: w.FormDataContentType(), MaxBytes: 4096}, texts)
	if incomplete != "" {
		t.Fatalf("multipart metadata interpreted as file bytes: %s", incomplete)
	}
}

func TestUploadInspectionIncompleteCredentialFloor(t *testing.T) {
	data := uploadArchive(t, map[string][]byte{"word/document.xml": []byte(`<p>` + "AKIA" + "Q9W8E7R6T5Y4U3I2")})
	status, hits, _, message := exerciseUpload(t, "intercept", uploadPolicy{config.ActionBlock, true}, "video/mp4", data)
	if status != http.StatusForbidden || hits != 0 || !strings.Contains(message, "AWS Access ID") || strings.Contains(message, "governed by request_body_scanning.action") {
		t.Fatalf("core-floor block must name governing credential control: status=%d hits=%d body=%s", status, hits, message)
	}
}

// A multipart parser skips its preamble, so a ZIP signature at offset zero must
// not replace the part decoding the receiver applies. The stored ZIP member
// makes the same bytes a complete archive and a valid multipart form.
func TestUploadInspectionMultipartZipPreamble(t *testing.T) {
	stored := func(form string) []byte {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		member, err := z.CreateHeader(&zip.FileHeader{Name: "note.txt", Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(member, form); err != nil {
			t.Fatal(err)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	form := "\r\n--B\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
		"AKIA=\r\nQ9W8=\r\nE7R6T5Y4U3I2\r\n--B--\r\n"
	polyglot := stored(form)
	seeded, err := os.ReadFile(filepath.Clean(filepath.Join("..", "fileinspect", "testdata", "libreoffice-seeded.docx")))
	if err != nil {
		t.Fatal(err)
	}
	documentPolyglot := stored("\r\n--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n\r\n" + string(seeded) + "\r\n--B--\r\n")
	part, err := multipart.NewReader(bytes.NewReader(polyglot), "B").NextPart()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(part)
	if err != nil || string(decoded) != "AKIA"+"Q9W8E7R6T5Y4U3I2" {
		t.Fatalf("receiver view of the polyglot: %q err=%v", decoded, err)
	}
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		for _, tc := range []struct {
			name   string
			body   []byte
			policy uploadPolicy
		}{
			{"complete archive enforce", polyglot, uploadPolicy{config.ActionBlock, false}},
			{"complete archive audit", polyglot, uploadPolicy{config.ActionWarn, true}},
			{"document part audit", documentPolyglot, uploadPolicy{config.ActionWarn, true}},
			{"damaged archive audit", append([]byte("PK\x03\x04"), form...), uploadPolicy{config.ActionWarn, true}},
		} {
			t.Run(surface+"/"+tc.name, func(t *testing.T) {
				status, hits, _, message := exerciseUpload(t, surface, tc.policy, "multipart/form-data; boundary=B", tc.body)
				if status != http.StatusForbidden || hits != 0 || !strings.Contains(message, "AWS Access ID") {
					t.Fatalf("decoded multipart credential delivered: status=%d hits=%d body=%s", status, hits, message)
				}
			})
		}
	}
}
