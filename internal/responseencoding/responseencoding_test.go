// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package responseencoding

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestParseRequestCoding(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		values  []string
		want    string
		wantErr error
	}{
		{name: "absent"},
		{name: "empty token", values: []string{"  "}},
		{name: "identity", values: []string{"identity"}},
		{name: "repeated identity", values: []string{"identity", " Identity "}},
		{name: "gzip", values: []string{"gzip"}, want: "gzip"},
		{name: "padded gzip", values: []string{" gzip "}, want: "gzip"},
		{name: "mixed case", values: []string{"GZip"}, want: "gzip"},
		{name: "x-gzip", values: []string{"x-gzip"}, want: "x-gzip"},
		{name: "deflate", values: []string{"deflate"}, want: "deflate"},
		{name: "gzip and identity", values: []string{"gzip, identity"}, wantErr: ErrStackedContentCoding},
		{name: "identity and gzip", values: []string{"identity", "gzip"}, wantErr: ErrStackedContentCoding},
		{name: "two header lines", values: []string{"gzip", "gzip"}, wantErr: ErrStackedContentCoding},
		{name: "stacked value", values: []string{"gzip, gzip"}, wantErr: ErrStackedContentCoding},
		{name: "brotli", values: []string{"br"}, wantErr: ErrUnsupportedContentCoding},
		{name: "zstd", values: []string{"zstd"}, wantErr: ErrUnsupportedContentCoding},
		{name: "compress", values: []string{"compress"}, wantErr: ErrUnsupportedContentCoding},
		{name: "unknown", values: []string{"mystery"}, wantErr: ErrUnsupportedContentCoding},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseRequestCoding(tt.values)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseRequestCoding(%q) error = %v, want %v", tt.values, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRequestCoding(%q) error = %v", tt.values, err)
			}
			if got != tt.want {
				t.Fatalf("ParseRequestCoding(%q) = %q, want %q", tt.values, got, tt.want)
			}
		})
	}
}

func TestReadDecodedGzipDeflateAndRefusals(t *testing.T) {
	t.Parallel()
	plain := []byte("scan this body")
	gzipped := gzipTestBody(t, plain)
	decoded, err := ReadDecoded("gzip", gzipped, len(plain))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	if !bytes.Equal(decoded, plain) {
		t.Fatalf("gzip decoded = %q, want %q", decoded, plain)
	}
	xGzip, err := ReadDecoded("x-gzip", gzipped, len(plain))
	if err != nil || !bytes.Equal(xGzip, plain) {
		t.Fatalf("x-gzip = %q, %v", xGzip, err)
	}
	deflated := deflateTestBody(t, plain)
	gotDeflate, err := ReadDecoded("deflate", deflated, len(plain))
	if err != nil || !bytes.Equal(gotDeflate, plain) {
		t.Fatalf("deflate = %q, %v", gotDeflate, err)
	}

	// A second gzip member is part of the decoded view.
	second := gzipTestBody(t, []byte(" plus more"))
	joined := append(append([]byte{}, gzipped...), second...)
	both, err := ReadDecoded("gzip", joined, 64)
	if err != nil {
		t.Fatalf("concatenated gzip: %v", err)
	}
	if !bytes.Equal(both, []byte("scan this body plus more")) {
		t.Fatalf("concatenated decoded = %q", both)
	}

	bomb := gzipTestBody(t, bytes.Repeat([]byte("A"), 64))
	over, err := ReadDecoded("gzip", bomb, 8)
	if err != nil {
		t.Fatalf("over-limit decode error = %v", err)
	}
	if len(over) != 9 {
		t.Fatalf("over-limit decoded length = %d, want 9", len(over))
	}

	if _, err := ReadDecoded("gzip", gzipped[:8], 64); err == nil {
		t.Fatal("truncated gzip decoded")
	}
	corrupt := append([]byte{}, gzipped...)
	corrupt[len(corrupt)-1] ^= 0xff
	if _, err := ReadDecoded("gzip", corrupt, 64); err == nil {
		t.Fatal("corrupt gzip checksum decoded")
	}
	trailingGzip := append(append([]byte{}, gzipped...), []byte("trailing")...)
	if _, err := ReadDecoded("gzip", trailingGzip, 64); err == nil {
		t.Fatal("gzip with trailing plaintext decoded")
	}
	trailingDeflate := append(append([]byte{}, deflated...), []byte("trailing")...)
	if _, err := ReadDecoded("deflate", trailingDeflate, 64); err == nil {
		t.Fatal("zlib stream with trailing bytes decoded")
	}
	if _, err := ReadDecoded("gzip", nil, 8); err == nil {
		t.Fatal("empty gzip input decoded")
	}
	if _, err := ReadDecoded("br", gzipped, 8); err == nil {
		t.Fatal("unsupported coding decoded")
	}
	if _, err := NewDecoder("compress", bytes.NewReader(gzipped)); err == nil {
		t.Fatal("NewDecoder accepted compress")
	}
	negative, err := ReadDecoded("gzip", gzipTestBody(t, nil), -1)
	if err != nil || len(negative) != 0 {
		t.Fatalf("negative limit = %q, %v", negative, err)
	}
}

func gzipTestBody(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func deflateTestBody(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("deflate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("deflate close: %v", err)
	}
	return buf.Bytes()
}

func TestRequestIdentity(t *testing.T) {
	header := http.Header{"Accept-Encoding": {"gzip", "deflate, br, zstd"}}
	RequestIdentity(header)
	if got := header.Values("Accept-Encoding"); len(got) != 1 || got[0] != "identity" {
		t.Fatalf("Accept-Encoding values = %q, want identity", got)
	}
}

func TestHasNonIdentityContentEncoding(t *testing.T) {
	for _, tt := range []struct {
		name   string
		values []string
		want   bool
	}{
		{name: "absent"},
		{name: "identity only", values: []string{"identity", "identity"}},
		{name: "identity before gzip", values: []string{"identity", "gzip"}, want: true},
		{name: "gzip before identity", values: []string{"gzip", "identity"}, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			header := make(http.Header)
			for _, value := range tt.values {
				header.Add("Content-Encoding", value)
			}
			if got := HasNonIdentityContentEncoding(header); got != tt.want {
				t.Fatalf("HasNonIdentityContentEncoding() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestDecodeResponse(t *testing.T) {
	const plain = "ordinary response body"

	tests := []struct {
		name     string
		encoding string
		body     func(*testing.T) []byte
		wantErr  string
		// wantReadErr marks a stream whose header is valid, so DecodeResponse
		// succeeds, and whose failure only surfaces when the caller reads it.
		wantReadErr bool
	}{
		{name: "identity", encoding: "identity", body: func(*testing.T) []byte { return []byte(plain) }},
		{name: "gzip", encoding: "gzip", body: func(t *testing.T) []byte { return gzipBody(t, plain) }},
		{name: "x-gzip", encoding: "x-gzip", body: func(t *testing.T) []byte { return gzipBody(t, plain) }},
		{name: "deflate", encoding: "deflate", body: func(t *testing.T) []byte { return deflateBody(t, plain) }},
		{name: "unsupported", encoding: "br", body: func(*testing.T) []byte { return []byte("encoded") }, wantErr: "unsupported content encoding"},
		{name: "stacked", encoding: "gzip, deflate", body: func(*testing.T) []byte { return []byte("encoded") }, wantErr: "unsupported stacked content encodings"},
		{name: "malformed gzip", encoding: "gzip", body: func(*testing.T) []byte { return []byte("not gzip") }, wantErr: "decode gzip response"},
		{name: "truncated gzip", encoding: "gzip", body: func(t *testing.T) []byte {
			body := gzipBody(t, plain)
			return body[:len(body)-1]
		}, wantReadErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: http.Header{
					"Content-Encoding": {tt.encoding},
					"Content-Length":   {"123"},
					"Content-MD5":      {"encoded-md5"},
					"Digest":           {"sha-256=encoded"},
					"ETag":             {`"encoded"`},
				},
				Body:          io.NopCloser(bytes.NewReader(tt.body(t))),
				ContentLength: 123,
			}
			err := DecodeResponse(resp)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("DecodeResponse() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeResponse() error = %v", err)
			}
			if tt.wantReadErr {
				// A gzip header is valid on its own, so the truncation is only
				// discovered mid-read. A caller that checks DecodeResponse and
				// then ignores the read error would treat a partial body as the
				// whole response and scan less than was delivered.
				if _, err := io.ReadAll(resp.Body); err == nil {
					t.Fatal("reading a truncated decoded body succeeded; the truncation must surface as a read error")
				}
				if err := resp.Body.Close(); err != nil {
					t.Fatalf("close decoded body: %v", err)
				}
				return
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read decoded body: %v", err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatalf("close decoded body: %v", err)
			}
			if string(got) != plain {
				t.Fatalf("decoded body = %q, want %q", got, plain)
			}
			if tt.encoding != "identity" {
				if got := resp.Header.Get("Content-Encoding"); got != "" {
					t.Fatalf("Content-Encoding = %q, want removed", got)
				}
				if got := resp.Header.Get("Content-Length"); got != "" || resp.ContentLength != -1 || !resp.Uncompressed {
					t.Fatalf("decoded metadata = header %q length %d uncompressed %v", got, resp.ContentLength, resp.Uncompressed)
				}
				for _, name := range []string{"Content-MD5", "Digest", "ETag"} {
					if got := resp.Header.Get(name); got != "" {
						t.Fatalf("%s = %q, want removed after decoding", name, got)
					}
				}
			}
		})
	}
}

func TestDecodeResponseNilAndEmpty(t *testing.T) {
	if err := DecodeResponse(nil); err != nil {
		t.Fatalf("nil response: %v", err)
	}
	if err := DecodeResponse(&http.Response{Header: make(http.Header)}); err != nil {
		t.Fatalf("empty response: %v", err)
	}
}

func TestDecodeResponseRejectsEncodedPartial(t *testing.T) {
	body := gzipBody(t, "range fragment")
	resp := &http.Response{
		StatusCode: http.StatusPartialContent,
		Header: http.Header{
			"Content-Encoding": {"gzip"},
			"Content-Range":    {"bytes 0-13/100"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}
	if err := DecodeResponse(resp); err == nil || !strings.Contains(err.Error(), "partial response") {
		t.Fatalf("encoded partial response error = %v, want refusal", err)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" || resp.Header.Get("Content-Range") == "" {
		t.Fatal("refusal changed upstream representation metadata")
	}
	if got, err := io.ReadAll(resp.Body); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("refusal changed upstream body: bytes=%d err=%v", len(got), err)
	}
}

func gzipBody(t *testing.T, text string) []byte {
	t.Helper()
	var body bytes.Buffer
	w := gzip.NewWriter(&body)
	if _, err := io.WriteString(w, text); err != nil {
		t.Fatalf("write gzip body: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close gzip body: %v", err)
	}
	return body.Bytes()
}

func deflateBody(t *testing.T, text string) []byte {
	t.Helper()
	var body bytes.Buffer
	w := zlib.NewWriter(&body)
	if _, err := io.WriteString(w, text); err != nil {
		t.Fatalf("write deflate body: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close deflate body: %v", err)
	}
	return body.Bytes()
}
