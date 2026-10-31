// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fileinspect

import (
	"bufio"
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

func (w *walk) preflight(data []byte) error {
	if len(data) > w.limits.MaxBytes {
		return fmt.Errorf("archive exceeds max_body_bytes")
	}
	arch, err := parseCanonicalZIP(data, w.entries)
	if err != nil {
		return err
	}
	w.parsed = &arch
	w.entries -= len(arch.members)
	return nil
}

func (w *walk) archive(data []byte, depth int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if depth >= w.limits.MaxDepth {
		return fmt.Errorf("nested archive exceeds extraction depth budget")
	}
	if err := w.preflight(data); err != nil {
		return err
	}
	arch := w.parsed
	for _, m := range arch.members {
		if m.name == "[Content_Types].xml" && depth == 0 {
			w.result.Type = "Office/ZIP"
		}
		if m.name == "META-INF/manifest.xml" && depth == 0 {
			w.result.Type = "OpenDocument/ZIP"
		}
	}
	w.result.Texts = append(w.result.Texts, arch.comment)

	type extracted struct {
		member  zipMember
		payload []byte
		dir     bool
	}
	// The first failure decides the reason, but every other member is still
	// read into the text views. An unread member placed first must not hide
	// a credential in the members after it from request DLP.
	var firstErr error
	fail := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	got := make([]extracted, 0, len(arch.members))
	for _, m := range arch.members {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		payload, dir, err := w.memberBytes(m)
		if err != nil {
			w.appendMemberLabels(m)
			fail(err)
			continue
		}
		got = append(got, extracted{member: m, payload: payload, dir: dir})
	}
	sort.SliceStable(got, func(i, j int) bool {
		return declarationPriority(got[i].member.name) < declarationPriority(got[j].member.name)
	})

	var parts packageParts
	decoded := make(map[string][]byte, len(got))
	var deferred []extracted
	for _, item := range got {
		m := item.member
		if item.dir {
			w.appendMemberLabels(m)
			continue
		}
		decoded[m.name] = item.payload
		w.appendMemberLabels(m)
		if kind := Kind(item.payload); kind != "" {
			if kind != "ZIP" {
				w.result.Texts = append(w.result.Texts, string(item.payload))
				fail(fmt.Errorf("embedded %s format has no upload reader", kind))
				continue
			}
			before := len(w.result.Texts)
			if err := w.archive(item.payload, depth+1); err != nil {
				// A nested archive that could not be parsed added nothing,
				// so its raw bytes are kept. One that was parsed has put
				// each member's recoverable bytes in the views;
				// appending its bytes again at every level would grow the
				// views with the nesting depth.
				if len(w.result.Texts) == before {
					w.result.Texts = append(w.result.Texts, string(item.payload))
				}
				fail(err)
			}
			continue
		}
		w.result.Texts = append(w.result.Texts, string(item.payload))
		// MS-CFB 2.2 compound-file header. A stream inside it can be
		// fragmented, and VBA source is compressed (MS-OVBA). The signature
		// decides, before any declared type or font deobfuscation.
		if bytes.HasPrefix(item.payload, compoundFileSignature) {
			fail(fmt.Errorf("OLE compound file member has no reader"))
			continue
		}
		if err := parts.metadata(m.name, item.payload); err != nil {
			fail(err)
			continue
		}
		if utf8.Valid(item.payload) {
			contentType := parts.contentType(m.name)
			if isXMLPart(m.name, contentType) {
				text, xmlErr := xmlText(item.payload, w.limits.MaxDepth, nil)
				if xmlErr != nil {
					fail(xmlErr)
					continue
				}
				w.result.Texts = append(w.result.Texts, text)
			}
			continue
		}
		if knownBinarySignature(item.payload) {
			if embeddedArchive(item.payload) {
				fail(fmt.Errorf("binary member contains an archive signature"))
			}
			continue
		}
		deferred = append(deferred, item)
	}
	keys := embeddedFontKeys(decoded)
	var still []extracted
	for _, item := range deferred {
		key := keys[item.member.name]
		if key == nil {
			still = append(still, item)
			continue
		}
		plain := deobfuscateEmbeddedFont(item.payload, key)
		if !knownFontSignature(plain) {
			still = append(still, item)
			continue
		}
		w.result.Texts = append(w.result.Texts, string(plain))
		// Deobfuscation changes only the first 32 bytes. The member is read
		// as both forms, so an archive signature in either leaves it unread,
		// as for any other signature-accepted member.
		if embeddedArchive(item.payload) || embeddedArchive(plain) {
			fail(fmt.Errorf("binary member contains an archive signature"))
		}
	}
	if firstErr != nil {
		return firstErr
	}
	if len(still) > 0 {
		return fmt.Errorf("non-text member has no reader")
	}
	return nil
}

// memberBytes inflates one canonical member. A directory is only a name that
// ends in '/' with both sizes zero (APPNOTE 4.3.8 plus the caller's slash
// rule). External attributes are host-dependent (APPNOTE 4.4.15) and are not
// consulted. A slash name with any other size is a file; when the recovered
// length disagrees with the claimed size the recovered bytes stay in the text
// views and the member is not fully read.
func (w *walk) appendMemberLabels(m zipMember) {
	w.result.Texts = append(w.result.Texts, m.name, m.comment)
	if len(m.localExtra) > 0 {
		w.result.Texts = append(w.result.Texts, string(m.localExtra))
	}
	if len(m.centralExtra) > 0 {
		w.result.Texts = append(w.result.Texts, string(m.centralExtra))
	}
}

func (w *walk) memberBytes(m zipMember) ([]byte, bool, error) {
	if strings.HasSuffix(m.name, "/") && m.compressed == 0 && m.uncompressed == 0 {
		return nil, true, nil
	}
	if m.uncompressed > 0 {
		if w.remaining < 0 || m.uncompressed > math.MaxInt32 || m.uncompressed > uint64(w.remaining) {
			// Not inflated, but the member's own bytes are already charged
			// input (the request or the parent member). Keeping them means
			// each member's recoverable bytes reach the views, so a parent
			// need not repeat a parsed nested archive's bytes.
			w.result.Texts = append(w.result.Texts, string(m.payload))
			return nil, false, fmt.Errorf("expanded member exceeds max_body_bytes / compression-ratio budget")
		}
		w.remaining -= int(m.uncompressed)
	}
	payload, err := w.inflateMember(m)
	if m.uncompressed == 0 && len(payload) > w.remaining {
		if w.remaining > 0 {
			w.result.Texts = append(w.result.Texts, string(payload[:w.remaining]))
		}
		w.remaining = 0
		return nil, false, fmt.Errorf("expanded member exceeds max_body_bytes / compression-ratio budget")
	}
	// The walk keeps reading after a failed member, so every inflated byte is
	// charged, read cleanly or not.
	if m.uncompressed == 0 {
		w.remaining -= len(payload)
	}
	if err != nil {
		// Go archive/zip, Python zipfile and Info-ZIP unzip stop at the end
		// of the deflate stream and extract these bytes even when compressed
		// data follows it.
		if len(payload) > 0 {
			w.result.Texts = append(w.result.Texts, string(payload))
		}
		return nil, false, err
	}
	if strings.HasSuffix(m.name, "/") && uint64(len(payload)) != m.uncompressed {
		if len(payload) > 0 {
			w.result.Texts = append(w.result.Texts, string(payload))
		}
		return nil, false, fmt.Errorf("directory member has unread data")
	}
	// Info-ZIP unzip still writes a member whose size or CRC is wrong, so the
	// recovered bytes stay in the text views.
	if uint64(len(payload)) != m.uncompressed {
		w.result.Texts = append(w.result.Texts, string(payload))
		return nil, false, fmt.Errorf("member size does not match ZIP directory")
	}
	if crc32.ChecksumIEEE(payload) != m.crc {
		w.result.Texts = append(w.result.Texts, string(payload))
		return nil, false, fmt.Errorf("local member checksum or size disagrees with directory")
	}
	return payload, false, nil
}

func (w *walk) inflateMember(m zipMember) ([]byte, error) {
	limit := w.remaining
	if m.uncompressed > 0 {
		if m.uncompressed > uint64(math.MaxInt) {
			return nil, fmt.Errorf("expanded member exceeds max_body_bytes / compression-ratio budget")
		}
		limit = int(m.uncompressed)
	}
	if limit < 0 {
		limit = 0
	}
	switch m.method {
	case zipMethodStore:
		if len(m.payload) > limit+1 {
			return m.payload[:limit+1], nil
		}
		return m.payload, nil
	case zipMethodDeflate:
		compressed := bufio.NewReader(bytes.NewReader(m.payload))
		inflater := flate.NewReader(compressed)
		payload, err := io.ReadAll(io.LimitReader(&contextReader{w.ctx, inflater}, int64(limit)+1))
		if err != nil {
			_ = inflater.Close()
			return payload, fmt.Errorf("reading member: %w", err)
		}
		// A short read hit the caller's byte ceiling. The trailing-byte check
		// would also fire, because the stream is not finished, and would hide
		// the budget or size failure.
		if len(payload) > limit {
			_ = inflater.Close()
			return payload, nil
		}
		if closeErr := inflater.Close(); closeErr != nil {
			return payload, fmt.Errorf("closing member: %w", closeErr)
		}
		if _, err = compressed.ReadByte(); !errors.Is(err, io.EOF) {
			return payload, fmt.Errorf("compressed member has data after its deflate stream")
		}
		return payload, nil
	default:
		return nil, fmt.Errorf("unsupported ZIP compression method %d", m.method)
	}
}
