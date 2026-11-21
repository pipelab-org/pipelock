// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

type v3DeliveryWriter struct {
	http.ResponseWriter
	proxy    *Proxy
	cfg      *config.Config
	request  *http.Request
	options  receipt.EmitOpts
	token    *proxyEffectToken
	denied   error
	writeErr error
	status   int
	length   int64
	written  int64
	framed   bool
	hijacked bool
	cancel   context.CancelCauseFunc
}

func (p *Proxy) startReceiptDelivery(w http.ResponseWriter, r *http.Request, cfg *config.Config, source receipt.EmitOpts) (http.ResponseWriter, func()) {
	if p == nil || !p.receiptEffects.enabled {
		return w, func() {}
	}
	delivery := &v3DeliveryWriter{ResponseWriter: w, proxy: p, cfg: cfg, request: r, options: deliveryEffectOptions(source)}
	return delivery, delivery.finish
}

func deliveryEffectOptions(source receipt.EmitOpts) receipt.EmitOpts {
	source.ParentActionID = source.ActionID
	source.ActionID = receipt.NewActionID()
	return source
}

func (w *v3DeliveryWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *v3DeliveryWriter) admit(opts receipt.EmitOpts) (*proxyEffectToken, error) {
	return w.proxy.admitEffect(w.request.Context(), w.cfg, opts, boundaryDownstreamDelivery)
}

func (w *v3DeliveryWriter) deny(err error) {
	w.denied = err
	clear(w.Header())
	writeReceiptEffectRefusal(w.ResponseWriter, w.options.RequestID)
	if w.cancel != nil {
		w.cancel(err)
	}
}

func (w *v3DeliveryWriter) adaptiveRefused() bool {
	adaptive, ok := w.ResponseWriter.(*adaptiveRefusalWriter)
	if !ok || !adaptive.refuse() {
		return false
	}
	opts := w.options
	opts.Verdict, opts.Layer, opts.Pattern = config.ActionBlock, adaptive.Header().Get(blockreason.HeaderLayer), adaptiveBlockedReason
	w.proxy.refuseEffect(w.request.Context(), w.cfg, opts, boundaryDownstreamDelivery)
	w.denied = errReceiptAdaptiveRefusal
	if w.cancel != nil {
		w.cancel(w.denied)
	}
	return true
}

var errReceiptAdaptiveRefusal = errors.New("adaptive enforcement withheld proxy delivery")

func (w *v3DeliveryWriter) WriteHeader(status int) {
	if w.status != 0 || w.denied != nil || w.adaptiveRefused() {
		return
	}
	if status < http.StatusOK && status != http.StatusSwitchingProtocols {
		opts := w.options
		opts.ActionID = receipt.NewActionID()
		token, err := w.admit(opts)
		if err != nil {
			w.deny(err)
			return
		}
		w.ResponseWriter.WriteHeader(status)
		w.proxy.settleEffect(w.request.Context(), opts, token)
		return
	}
	w.status = status
	if w.Header().Get(blockreason.HeaderReason) == "" {
		token, err := w.admit(w.options)
		if err != nil {
			w.deny(err)
			return
		}
		w.token = token
		w.length, w.framed = responseFrameLength(w.request, status, w.Header())
	}
	w.ResponseWriter.WriteHeader(status)
}

func responseFrameLength(r *http.Request, status int, header http.Header) (int64, bool) {
	if r.ProtoMajor != 1 || status < http.StatusOK || len(header.Values("Trailer")) != 0 || len(header.Values("Transfer-Encoding")) != 0 {
		return 0, false
	}
	for name := range header {
		if strings.HasPrefix(name, http.TrailerPrefix) {
			return 0, false
		}
	}
	if r.Method == http.MethodHead || status == http.StatusNoContent || status == http.StatusNotModified {
		return 0, true
	}
	length, err := strconv.ParseInt(header.Get("Content-Length"), 10, 64)
	return length, err == nil && length >= 0
}

func (w *v3DeliveryWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.denied != nil {
		return 0, w.denied
	}
	n, err := w.ResponseWriter.Write(body)
	w.written += int64(n)
	if n != len(body) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.writeErr = err
	}
	return n, err
}

func (w *v3DeliveryWriter) Flush() { _ = w.FlushError() }

func (w *v3DeliveryWriter) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.denied != nil {
		return w.denied
	}
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if err != nil {
		w.writeErr = err
	}
	return err
}

func (w *v3DeliveryWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.status != 0 || w.hijacked {
		return nil, nil, http.ErrNotSupported
	}
	if w.denied != nil || w.adaptiveRefused() {
		return nil, nil, w.denied
	}
	token, err := w.admit(w.options)
	if err != nil {
		w.deny(err)
		return nil, nil, err
	}
	conn, buf, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil && conn == nil {
		if refuseErr := token.Refuse(w.request.Context()); refuseErr != nil {
			w.proxy.logReceiptEmissionFailure(w.options, refuseErr)
		}
		return nil, nil, err
	}
	w.token, w.hijacked = token, true
	return conn, buf, err
}

func (w *v3DeliveryWriter) finish() {
	if w.token == nil {
		return
	}
	ctx := w.request.Context()
	err := w.token.ConfirmDelivery(ctx, func() (bool, error) {
		if w.hijacked || w.writeErr != nil || ctx.Err() != nil {
			return false, w.writeErr
		}
		_, framed := responseFrameLength(w.request, w.status, w.Header())
		err := flushOutcomeResponse(w.ResponseWriter, w.request, w.cfg, true)
		return framed && w.framed && (w.request.Method == http.MethodHead || w.written == w.length), err
	})
	if err != nil {
		w.proxy.logReceiptEmissionFailure(w.options, err)
	}
}
