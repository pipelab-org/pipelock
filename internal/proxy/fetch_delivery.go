// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"io"
	"net/http"
)

// fetchDeliveryWriter observes the JSON representation accepted by the writer.
// Upstream capture sizes remain in the request budget and audit log. Neither
// count proves that the remote client consumed or persisted those bytes.
type fetchDeliveryWriter struct {
	http.ResponseWriter
	bytes int64
	err   error
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
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}
