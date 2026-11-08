// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync/atomic"
	"time"
)

// Upstream bytes cannot assert proxy decisions or decision evidence. Apply the
// boundary to each HTTP header phase, including trailers populated at EOF.
func stripWatchEvidenceHeaders(header http.Header) {
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "x-pipelock-") {
			delete(header, name)
		}
	}
	trailers := header.Values("Trailer")
	header.Del("Trailer")
	for _, value := range trailers {
		for _, name := range strings.Split(value, ",") {
			name = strings.TrimSpace(name)
			if name != "" && !strings.HasPrefix(strings.ToLower(name), "x-pipelock-") {
				header.Add("Trailer", name)
			}
		}
	}
}

// watchStallTransport applies the reverse and intercept paths' no-progress
// bound. That wrapper replaces every body, so a response the origin sent
// without one would stop looking empty to the inspection that follows; the
// bodyless response is restored.
type watchStallTransport struct {
	base  http.RoundTripper
	stall time.Duration
}

func (t watchStallTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyless atomic.Bool
	resp, err := (&upstreamBodyStallTransport{base: watchBodyProbe{base: t.base, bodyless: &bodyless}, stall: t.stall}).RoundTrip(req)
	if err == nil && bodyless.Load() && resp.Body != nil && resp.Body != http.NoBody {
		_ = resp.Body.Close()
		resp.Body = http.NoBody
	}
	return resp, err
}

type watchBodyProbe struct {
	base     http.RoundTripper
	bodyless *atomic.Bool
}

func (p watchBodyProbe) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := p.base.RoundTrip(req)
	if err == nil && (resp.Body == nil || resp.Body == http.NoBody) {
		p.bodyless.Store(true)
	}
	return resp, err
}

type watchEvidenceTransport struct {
	base http.RoundTripper
	// sign attaches the outbound mediation envelope after the evidence boundary
	// is applied; a failure is returned as the round-trip error.
	sign func(*http.Request) error
}

func (t watchEvidenceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	trace := &httptrace.ClientTrace{Got1xxResponse: func(_ int, h textproto.MIMEHeader) error { stripWatchEvidenceHeaders(http.Header(h)); return nil }}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if t.sign != nil {
		if err := t.sign(req); err != nil {
			return nil, err
		}
	}
	resp, err := base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	stripWatchEvidenceHeaders(resp.Header)
	stripWatchEvidenceHeaders(resp.Trailer)
	if resp.Body != nil && resp.Body != http.NoBody {
		resp.Body = &watchEvidenceBody{ReadCloser: resp.Body, trailer: resp.Trailer}
	}
	return resp, nil
}

type watchEvidenceBody struct {
	io.ReadCloser
	trailer http.Header
}

func (b *watchEvidenceBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	stripWatchEvidenceHeaders(b.trailer)
	return n, err
}

type watchDeliveryWriter struct {
	http.ResponseWriter
	bytes int64
	err   error
}

func (w *watchDeliveryWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil && w.err == nil {
		w.err = err
	}
	return n, err
}
func (w *watchDeliveryWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
