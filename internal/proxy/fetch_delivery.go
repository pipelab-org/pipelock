// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
)

// fetchDeliveryWriter observes the JSON representation accepted by the writer.
// Upstream capture sizes remain in the request budget and audit log. Neither
// count proves that the remote client consumed or persisted those bytes.
type fetchDeliveryWriter struct {
	http.ResponseWriter
	bytes     int64
	err       error
	frameJSON bool
}

func (w *fetchDeliveryWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	if n < len(b) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.err = err
	}
	return n, err
}

func (w *fetchDeliveryWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// encodeJSON returns the final encoding or delivery error after committing the
// status. Callers recording delivery must observe this result before completion.
func encodeJSON(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	for current := w; current != nil; {
		if delivery, ok := current.(*fetchDeliveryWriter); ok && delivery.frameJSON && status >= http.StatusOK &&
			status != http.StatusNoContent && status != http.StatusNotModified {
			// Encode the final JSON, including Encoder's trailing newline, before
			// committing headers so EOF readers can finish before outcome storage.
			var body bytes.Buffer
			if err := json.NewEncoder(&body).Encode(data); err != nil {
				return err
			}
			w.Header().Del("Transfer-Encoding")
			w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
			w.WriteHeader(status)
			_, err := w.Write(body.Bytes())
			return err
		}
		unwrapper, ok := current.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		current = unwrapper.Unwrap()
	}
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}
