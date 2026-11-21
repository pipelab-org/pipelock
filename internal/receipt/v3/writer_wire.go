// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
)

const writerTimestampLayout = "2006-01-02T15:04:05.000Z"

// Generated wire structs declare members in canonical order. MarshalJSON on
// json.RawMessage preserves that order when the body goes into Common.
func encodeWriterJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, fmt.Errorf("encode receipt JSON: %w", err)
	}
	raw := buf.Bytes()[:buf.Len()-1]
	// encoding/json always escapes these two scalars. Leave a literal
	// backslash followed by "u2028" or "u2029" alone.
	out := raw[:0]
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) {
			suffix := raw[i+1:]
			if bytes.HasPrefix(suffix, []byte("u2028")) {
				out = append(out, '\xe2', '\x80', '\xa8')
				i += 5
				continue
			}
			if bytes.HasPrefix(suffix, []byte("u2029")) {
				out = append(out, '\xe2', '\x80', '\xa9')
				i += 5
				continue
			}
			out = append(out, raw[i], raw[i+1])
			i++
			continue
		}
		out = append(out, raw[i])
	}
	return out, nil
}

func (w *StreamWriter) encode(ctx context.Context, common Common, body any) ([]byte, string, error) {
	detail, err := encodeWriterJSON(body)
	if err != nil {
		return nil, "", err
	}
	common.Body = detail
	payload, err := encodeWriterJSON(common)
	if err != nil {
		return nil, "", err
	}
	framing := len(layoutPrefix) + len(layoutEntryPrefix) + len("sha256:") + sha256.Size*2 +
		len(layoutSignaturePrefix) + base64.StdEncoding.EncodedLen(layoutSignatureBytes) +
		len(layoutEntrySuffix) + len(layoutPayloadPrefix) + len(layoutSuffix)
	if len(payload)+framing > maxLineBytes {
		return nil, "", errors.New("receipt record exceeds the wire line limit")
	}
	parser := payloadParser{data: payload}
	values, parsed := parser.object(1)
	if !parsed || parser.pos != len(payload) {
		return nil, "", errors.New("receipt payload is outside the canonical wire layout")
	}
	if _, valid := matchObject(values, "Common"); !valid {
		return nil, "", errors.New("receipt common members are outside the wire schema")
	}
	if err := validateWriterBody(common, values["body"].(map[string]any)); err != nil {
		return nil, "", err
	}
	if w.open.Coverage.ContentScan {
		if err := scanWriterRecord(ctx, w.detector, common.Kind, detail); err != nil {
			return nil, "", err
		}
	}
	pae := PAE(payload)
	sig := ed25519.Sign(w.key, pae)
	line := make([]byte, 0, len(payload)+framing)
	line = append(line, layoutPrefix+layoutEntryPrefix+common.Signer+layoutSignaturePrefix...)
	line = base64.StdEncoding.AppendEncode(line, sig)
	line = append(line, layoutEntrySuffix+layoutPayloadPrefix...)
	line = append(line, payload...)
	line = append(line, layoutSuffix...)
	return line, Digest(pae), nil
}

func validateWriterBody(common Common, values map[string]any) error {
	if unknown, code := checkBody(Record{Common: common, values: values}, ""); unknown || code != "" {
		return fmt.Errorf("receipt %s body is outside the writer schema (%s)", common.Kind, code)
	}
	return nil
}

var openProjection = receiptcontent.Register(receiptcontent.Schema{
	Kind: "receipt_v3_stream_open",
	Fields: map[string]receiptcontent.Class{
		"coverage":                           receiptcontent.Content,
		"coverage.content_scan":              receiptcontent.Generated,
		"coverage.receipts_required":         receiptcontent.Generated,
		"coverage.redaction_ruleset":         receiptcontent.Content,
		"coverage.redaction_ruleset.id":      receiptcontent.Identity,
		"coverage.redaction_ruleset.hash":    receiptcontent.ComputedDigest,
		"coverage.redaction_ruleset.version": receiptcontent.Identity,
		"coverage.surfaces":                  receiptcontent.Content,
		"coverage.surfaces[]":                receiptcontent.Identity,
		"heartbeat_seconds":                  receiptcontent.Generated,
		"legacy_cutover":                     receiptcontent.Generated,
		"lineage":                            receiptcontent.Generated,
		"policy":                             receiptcontent.Content,
		"policy.hash":                        receiptcontent.ComputedDigest,
		"policy.source":                      receiptcontent.Enum,
		"posture":                            receiptcontent.Content,
		"posture.capsule_sha256":             receiptcontent.ComputedDigest,
		"posture.contained_uid":              receiptcontent.Identity,
		"posture.containment_nonce":          receiptcontent.Identity,
		"posture.signer_key_id":              receiptcontent.ComputedDigest,
		"previous":                           receiptcontent.Generated,
		"recorder_session":                   receiptcontent.RunSession,
		"signer_key":                         receiptcontent.Generated,
		"writer":                             receiptcontent.Content,
		"writer.binary_digest":               receiptcontent.ComputedDigest,
		"writer.instance":                    receiptcontent.Identity,
		"writer.product":                     receiptcontent.Identity,
		"writer.version":                     receiptcontent.Identity,
	},
	Enums: map[string][]string{"policy.source": {"writer_config"}},
})

var closeProjection = receiptcontent.Register(receiptcontent.Schema{
	Kind: "receipt_v3_stream_close",
	Fields: map[string]receiptcontent.Class{
		"durability":               receiptcontent.Generated,
		"reason":                   receiptcontent.Enum,
		"recorder":                 receiptcontent.Content,
		"recorder.entries":         receiptcontent.Generated,
		"recorder.session":         receiptcontent.RunSession,
		"recorder.transcript_root": receiptcontent.ComputedDigest,
		"records":                  receiptcontent.Generated,
	},
	Enums: map[string][]string{"reason": {"rollover", "shutdown"}},
})

var heartbeatProjection = receiptcontent.Register(receiptcontent.Schema{
	Kind: "receipt_v3_heartbeat",
	Fields: map[string]receiptcontent.Class{
		"beat":               receiptcontent.Generated,
		"durability_blocks":  receiptcontent.Generated,
		"fsync_errors_gated": receiptcontent.Generated,
	},
})

func scanWriterRecord(ctx context.Context, det receiptcontent.Detector, kind string, detail []byte) error {
	var producer *receiptcontent.Producer
	switch kind {
	case kindAction:
		producer = actionProjection
	case kindStreamOpen:
		producer = openProjection
	case kindStreamClose:
		producer = closeProjection
	case kindHeartbeat:
		producer = heartbeatProjection
	default:
		return errors.New("missing receipt content projection")
	}
	projection, err := producer.Project(detail)
	if err != nil {
		return fmt.Errorf("project %s receipt content: %w", kind, err)
	}
	report, err := receiptcontent.Scan(ctx, det, projection)
	if err != nil {
		return fmt.Errorf("scan %s receipt content: %w", kind, err)
	}
	if err := report.Err(); err != nil {
		return fmt.Errorf("scan %s receipt content: %w", kind, err)
	}
	return nil
}
