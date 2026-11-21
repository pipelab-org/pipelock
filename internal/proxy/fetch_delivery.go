// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"io"
	"net/http"
)

// httpDeliveryObservation records the final headers and body writes observed
// at the response writer. A write or flush cannot prove client consumption.
type httpDeliveryObservation struct {
	status        int
	contentLength int64
	bytes         int64
	err           error
}

func (o *httpDeliveryObservation) start(h http.Header, status int) {
	if o.status == 0 && (status >= http.StatusOK || status == http.StatusSwitchingProtocols) {
		o.status = status
		o.contentLength = responseContentLengthForReceipt(h)
	}
}

func (o *httpDeliveryObservation) write(w http.ResponseWriter, body []byte) (int, error) {
	o.start(w.Header(), http.StatusOK)
	n, err := w.Write(body)
	o.bytes += int64(n)
	if n < len(body) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		o.err = err
	}
	return n, err
}

type httpDeliveryWriter struct {
	http.ResponseWriter
	httpDeliveryObservation
}

func (w *httpDeliveryWriter) WriteHeader(status int) {
	w.start(w.Header(), status)
	w.ResponseWriter.WriteHeader(status)
}

func (w *httpDeliveryWriter) Write(body []byte) (int, error) {
	return w.write(w.ResponseWriter, body)
}

func (w *httpDeliveryWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// encodeJSON returns an encoding or delivery error. It commits headers only
// after encoding the complete synthetic body, including the trailing newline.
func encodeJSON(w http.ResponseWriter, status int, data any) error {
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	w.Header().Set("Content-Type", "application/json")
	_, err = writeSyntheticResponse(w, status, body)
	return err
}
