// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package responseencoding normalizes upstream response encodings before
// Pipelock scans response bodies.
package responseencoding

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	// ErrUnsupportedContentCoding is a content coding other than a single
	// gzip, x-gzip, or deflate token.
	ErrUnsupportedContentCoding = errors.New("unsupported content coding")
	// ErrStackedContentCoding is more than one content-coding token, including
	// a supported coding combined with identity.
	ErrStackedContentCoding = errors.New("stacked content coding")
	errTrailingContent      = errors.New("content remains after the compressed stream")
)

// RequestIdentity asks an upstream for uncompressed response bytes. Setting an
// explicit value is load-bearing: deleting Accept-Encoding lets net/http add
// gzip on transports where automatic compression is enabled.
func RequestIdentity(header http.Header) {
	header.Set("Accept-Encoding", "identity")
}

// HasNonIdentityContentEncoding reports whether any Content-Encoding header
// value contains an encoding other than identity. HTTP permits repeated header
// fields, so callers must inspect all values rather than Header.Get's first.
func HasNonIdentityContentEncoding(header http.Header) bool {
	return len(nonIdentityEncodings(header.Values("Content-Encoding"))) != 0
}

// DecodeResponse replaces a gzip- or deflate-encoded response body with a
// decoded stream and removes headers that describe the encoded representation.
// Callers retain their existing decoded-body size limits. Unsupported,
// malformed, and stacked encodings return an error so callers can fail closed.
func DecodeResponse(resp *http.Response) error {
	if resp == nil || resp.Body == nil {
		return nil
	}
	encodings := nonIdentityEncodings(resp.Header.Values("Content-Encoding"))
	if len(encodings) == 0 {
		return nil
	}
	if resp.StatusCode == http.StatusPartialContent {
		return fmt.Errorf("cannot decode a partial response without invalidating Content-Range")
	}
	if len(encodings) != 1 {
		return fmt.Errorf("unsupported stacked content encodings %q", strings.Join(encodings, ", "))
	}

	original := resp.Body
	var (
		decoded io.ReadCloser
		err     error
	)
	switch encodings[0] {
	case "gzip", "x-gzip", "deflate":
		decoded, err = NewDecoder(encodings[0], original)
	default:
		return fmt.Errorf("unsupported content encoding %q", encodings[0])
	}
	if err != nil {
		return fmt.Errorf("decode %s response: %w", encodings[0], err)
	}

	resp.Body = &decodedResponseBody{Reader: decoded, decoded: decoded, original: original}
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-MD5")
	resp.Header.Del("Digest")
	resp.Header.Del("ETag")
	resp.ContentLength = -1
	resp.Uncompressed = true
	return nil
}

// ParseRequestCoding classifies request Content-Encoding header values.
// Identity-only input, including a missing header, returns an empty coding.
// Exactly one gzip, x-gzip, or deflate token returns that token in lowercase.
// Tokens are trimmed and compared case-insensitively. A supported coding
// combined with identity, a repeated coding, or any other token returns an
// error. Unlike response decoding, identity tokens count toward the stack.
func ParseRequestCoding(values []string) (string, error) {
	var tokens []string
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			token = strings.ToLower(strings.TrimSpace(token))
			if token == "" {
				continue
			}
			tokens = append(tokens, token)
		}
	}
	if len(tokens) == 0 {
		return "", nil
	}
	identityOnly := true
	for _, token := range tokens {
		if token != "identity" {
			identityOnly = false
			break
		}
	}
	if identityOnly {
		return "", nil
	}
	if len(tokens) != 1 {
		return "", ErrStackedContentCoding
	}
	switch tokens[0] {
	case "gzip", "x-gzip", "deflate":
		return tokens[0], nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedContentCoding, tokens[0])
	}
}

// NewDecoder wraps r for one supported content coding. gzip and x-gzip use
// gzip.NewReader. deflate uses zlib.NewReader, so a raw deflate stream is an
// error. Constructor errors are returned unwrapped.
func NewDecoder(coding string, r io.Reader) (io.ReadCloser, error) {
	switch coding {
	case "gzip", "x-gzip":
		return gzip.NewReader(r)
	case "deflate":
		return zlib.NewReader(r)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedContentCoding, coding)
	}
}

// ReadDecoded reads one complete decoded body from original.
// original is the full compressed input. The decoded result is limited to
// maxDecoded+1 bytes so a caller can apply its existing size refusal without
// treating the limit as a decode error. A decoded length above maxDecoded is
// returned with a nil error. A decode error, a truncated stream, a checksum
// failure, or any byte after the compressed stream returns an error and no
// body. A gzip body is one member; a second member counts as trailing bytes.
// deflate is zlib-wrapped, and bytes after that stream are an error because
// the zlib reader leaves them unread.
func ReadDecoded(coding string, original []byte, maxDecoded int) ([]byte, error) {
	if maxDecoded < 0 {
		maxDecoded = 0
	}
	src := bytes.NewReader(original)
	dec, err := NewDecoder(coding, src)
	if err != nil {
		return nil, err
	}
	if gz, ok := dec.(*gzip.Reader); ok {
		// One member only. Receivers disagree on whether later members are
		// part of the body, so a second member is refused below as trailing
		// content instead of being scanned as a body the upstream may not see.
		gz.Multistream(false)
	}
	decoded, err := io.ReadAll(io.LimitReader(dec, int64(maxDecoded)+1))
	if err != nil {
		_ = dec.Close()
		return nil, err
	}
	// A checksum or truncation failure is returned by Read. After a full read
	// the gzip and zlib closers report a nil error, and an over-limit read
	// stops before the stream ends, so the close result is not a scan verdict.
	_ = dec.Close()
	if len(decoded) > maxDecoded {
		return decoded, nil
	}
	if src.Len() != 0 {
		return nil, errTrailingContent
	}
	return decoded, nil
}

func nonIdentityEncodings(values []string) []string {
	var encodings []string
	for _, value := range values {
		for _, encoding := range strings.Split(value, ",") {
			encoding = strings.ToLower(strings.TrimSpace(encoding))
			if encoding != "" && encoding != "identity" {
				encodings = append(encodings, encoding)
			}
		}
	}
	return encodings
}

type decodedResponseBody struct {
	io.Reader
	decoded  io.Closer
	original io.Closer
}

func (b *decodedResponseBody) Close() error {
	decodedErr := b.decoded.Close()
	originalErr := b.original.Close()
	if decodedErr != nil {
		return decodedErr
	}
	return originalErr
}
