// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fileinspect

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"path"
	"strings"
)

// deobfuscateEmbeddedFont applies the Office Open XML embedded-font transform
// from ECMA-376 Part 4 §2.8.1 (cited by [MS-OE376] Part 1 §15.2.12). The GUID
// is the printed hex form: strip braces and dashes, decode the 16 bytes, and
// reverse those bytes. That key is XORed with bytes 0-15 and again with 16-31.
// A result that does not start with a font signature is not a font.
func deobfuscateEmbeddedFont(data, key []byte) []byte {
	out := bytes.Clone(data)
	n := 32
	if len(out) < n {
		n = len(out)
	}
	for i := 0; i < n; i++ {
		out[i] ^= key[i%16]
	}
	return out
}

func obfuscationKey(guid string) ([]byte, bool) {
	s := strings.Trim(strings.TrimSpace(guid), "{}")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return nil, false
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 16 {
		return nil, false
	}
	for i, j := 0, len(raw)-1; i < j; i, j = i+1, j-1 {
		raw[i], raw[j] = raw[j], raw[i]
	}
	return raw, true
}

// embeddedFontKeys maps a ZIP member name to the key from word/fontTable.xml
// and word/_rels/fontTable.xml.rels. parts holds decompressed member bytes.
// Targets are resolved relative to word/ (OPC relationship target, ECMA-376 Part 2).
func embeddedFontKeys(parts map[string][]byte) map[string][]byte {
	table := parts["word/fontTable.xml"]
	rels := parts["word/_rels/fontTable.xml.rels"]
	if len(table) == 0 || len(rels) == 0 {
		return nil
	}
	ids := fontEmbedIDs(table)
	targets := fontRelTargets(rels)
	if len(ids) == 0 || len(targets) == 0 {
		return nil
	}
	out := make(map[string][]byte)
	for id, key := range ids {
		target, ok := targets[id]
		if !ok || target == "" {
			continue
		}
		name := resolvePartTarget("word/fontTable.xml", target)
		if name == "" {
			continue
		}
		if _, exists := out[name]; !exists {
			out[name] = key
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func fontEmbedIDs(data []byte) map[string][]byte {
	out := make(map[string][]byte)
	d := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) || err != nil {
			return out
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "embedRegular", "embedBold", "embedItalic", "embedBoldItalic":
		default:
			continue
		}
		var id, guid string
		for _, a := range se.Attr {
			switch a.Name.Local {
			case "id":
				id = a.Value
			case "fontKey":
				guid = a.Value
			}
		}
		key, ok := obfuscationKey(guid)
		if !ok || id == "" {
			continue
		}
		if _, exists := out[id]; !exists {
			out[id] = key
		}
	}
}

func fontRelTargets(data []byte) map[string]string {
	out := make(map[string]string)
	d := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) || err != nil {
			return out
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Relationship" {
			continue
		}
		var id, target string
		for _, a := range se.Attr {
			switch a.Name.Local {
			case "Id":
				id = a.Value
			case "Target":
				target = a.Value
			}
		}
		if id != "" && target != "" {
			out[id] = target
		}
	}
}

// resolvePartTarget joins an OPC relationship target onto the directory of
// the source part. An absolute-path target is used as a package name.
func resolvePartTarget(source, target string) string {
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	if decoded, err := url.PathUnescape(target); err == nil {
		target = decoded
	}
	if strings.Contains(target, ":") {
		return ""
	}
	var joined string
	if strings.HasPrefix(target, "/") {
		joined = strings.TrimPrefix(path.Clean(target), "/")
	} else {
		joined = path.Clean(path.Join(path.Dir(source), target))
	}
	if joined == "." || strings.HasPrefix(joined, "../") || joined == ".." {
		return ""
	}
	return joined
}
