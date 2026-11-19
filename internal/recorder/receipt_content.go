// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ContentScan is a clean receipt content scan performed by one recorder with
// its own receipt detector. Its fields are private so a caller cannot
// manufacture one; BindReceiptContent turns it into a ReceiptScan for the
// exact final detail bytes.
type ContentScan struct {
	recorder *Recorder
	kind     string
	digest   [32]byte
	off      bool
}

// ReceiptDetector returns the detector this recorder applies to receipt
// content, or nil when receipt redaction is disabled. NewWithScanner binds the
// quiet variant of its scanner, so repeated views emit no warn telemetry. The
// detector is owned by the recorder for its whole lifetime: a request-scanner
// reload never replaces it, and closing a reloaded request scanner does not
// stop text DLP, which reads immutable compiled patterns.
func (r *Recorder) ReceiptDetector() receiptcontent.Detector {
	if r == nil || r.nop || !r.cfg.Redact {
		return nil
	}
	return r.contentDetector
}

// ScanReceiptContent projects detail with the producer's registered schema
// and scans the projection with this recorder's receipt detector. A clean
// projection returns a ContentScan. Detector hits are returned in the report
// with a nil scan, so the producer can redact redactable values before
// signing and scan again; projection or budget refusals return a
// *receiptcontent.RejectionError. With redaction disabled nothing is scanned
// and the returned scan binds no content.
func (r *Recorder) ScanReceiptContent(ctx context.Context, p *receiptcontent.Producer, detail []byte) (receiptcontent.Report, *ContentScan, error) {
	if p == nil {
		return receiptcontent.Report{}, nil, errors.New("recorder: receipt content scan requires a registered producer")
	}
	det := r.ReceiptDetector()
	if det == nil {
		return receiptcontent.Report{}, &ContentScan{recorder: r, kind: p.Kind(), off: true}, nil
	}
	if slots := r.contentScanSlots; slots != nil {
		// Receipt projections can spend very different amounts of CPU on
		// fragment views. Admit only as many active projections per recorder
		// as the process has CPUs, so a burst of short scans cannot keep a
		// longer scan sharing a CPU with the whole burst. The slot covers inspection
		// only and is returned before signing, appending or confirming.
		acquired := false
		select {
		case slots <- struct{}{}:
			acquired = true
		default:
			if wait := r.contentScanWait.Load(); wait != nil {
				(*wait)()
			}
			select {
			case slots <- struct{}{}:
				acquired = true
			case <-ctx.Done():
			}
		}
		if acquired {
			defer func() { <-slots }()
		}
		if err := ctx.Err(); err != nil {
			return receiptcontent.Report{}, nil, errors.Join(scanner.ErrTextDLPIncomplete, err)
		}
		// Different fragments can contain the same encoded segments. Reuse
		// their exact decoder results within this projection. Every candidate
		// still runs the detector with its own inspection budget.
		var release func()
		ctx, release = scanner.WithSharedDecodes(ctx)
		defer release()
	}
	proj, err := p.Project(detail)
	if err != nil {
		return receiptcontent.Report{}, nil, err
	}
	rep, err := receiptcontent.Scan(ctx, det, proj)
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, scanner.ErrTextDLPIncomplete) {
		err = errors.Join(err, ctxErr)
	}
	if err != nil || !rep.Clean() {
		return rep, nil, err
	}
	return rep, &ContentScan{recorder: r, kind: p.Kind(), digest: proj.Digest()}, nil
}

// recorderSessionProducer classifies a recorder session handle on its own.
// Every entry's SessionID must equal a session this recorder acquired, so the
// handle is validated once, when it is acquired, instead of on every entry.
var recorderSessionProducer = receiptcontent.Register(receiptcontent.Schema{
	Kind:   "pipelock.recorder_session.v1",
	Fields: map[string]receiptcontent.Class{"session_id": receiptcontent.RunSession},
})

// checkSessionContent validates a session handle before this recorder binds
// it. The operator base of a run session minted by this process is scanned
// as an identity and its generated suffix is excluded; any other handle is
// scanned whole. A hit is a typed rejection: a session handle names the
// evidence file and is never redacted.
func (r *Recorder) checkSessionContent(session string) error {
	det := r.ReceiptDetector()
	if det == nil {
		return nil
	}
	detail, err := json.Marshal(map[string]string{"session_id": session})
	if err != nil {
		return fmt.Errorf("recorder: marshal session handle: %w", err)
	}
	proj, err := recorderSessionProducer.Project(detail)
	if err != nil {
		return err
	}
	rep, err := receiptcontent.Scan(context.Background(), det, proj)
	if err != nil {
		return err
	}
	return rep.Err()
}

// ErrContentChanged means the final detail's content projection differs from
// the projection that was scanned. It indicates a producer bug: content must
// be frozen before the scan, and lock-owned stamps are generated fields.
var ErrContentChanged = errors.New("receipt content changed after scan")

// BindReceiptContent binds a clean ContentScan to the exact final detail
// bytes. It recomputes the content projection from those bytes and refuses a
// different digest, so generated fields stamped under a chain lock need no
// rescan while any content change does. The result is the ReceiptScan the
// write boundary checks byte for byte.
func (r *Recorder) BindReceiptContent(cs *ContentScan, p *receiptcontent.Producer, detail []byte) (ReceiptScan, error) {
	if cs == nil || cs.recorder != r || p == nil || cs.kind != p.Kind() {
		return ReceiptScan{}, errors.New("recorder: receipt content scan attestation is invalid")
	}
	if !cs.off {
		proj, err := p.Project(detail)
		if err != nil {
			return ReceiptScan{}, err
		}
		if proj.Digest() != cs.digest {
			return ReceiptScan{}, fmt.Errorf("recorder: %s: %w", p.Kind(), ErrContentChanged)
		}
	}
	// The mirror is derived from the exact bytes; the write boundary refuses
	// an entry whose unencrypted mirror differs from it.
	outer, err := p.Outer(detail)
	if err != nil {
		return ReceiptScan{}, &receiptcontent.RejectionError{Kind: p.Kind(), View: receiptcontent.ViewMalformed, Reason: "outer fields cannot be derived"}
	}
	return ReceiptScan{recorder: r, detail: append([]byte(nil), detail...), outer: &outer}, nil
}
