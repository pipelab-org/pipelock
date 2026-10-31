// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fileinspect

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
)

// packageParts follows ECMA-376 Part 2 OPC content-type declarations and ODF
// 1.3 Part 2 manifest:file-entry media types. Every text-bearing declared XML
// part is read, including parts not named *.xml and unreferenced/hidden parts.
// Relationships are text views, never instructions to access another resource.
type packageParts struct {
	byName      map[string]string
	byExtension map[string]string
}

func (p *packageParts) contentType(name string) string {
	decoded, err := url.PathUnescape(name)
	if err == nil {
		name = decoded
	}
	if t := p.byName[strings.TrimPrefix(name, "/")]; t != "" {
		return t
	}
	return p.byExtension[strings.ToLower(strings.TrimPrefix(path.Ext(name), "."))]
}

func (p *packageParts) metadata(name string, data []byte) error {
	if name != "[Content_Types].xml" && name != "META-INF/manifest.xml" {
		return nil
	}
	if p.byName == nil {
		p.byName = make(map[string]string)
		p.byExtension = make(map[string]string)
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	for {
		t, err := d.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("malformed package declarations XML")
		}
		e, ok := t.(xml.StartElement)
		if !ok {
			continue
		}
		attrs := make(map[string]string, len(e.Attr))
		for _, a := range e.Attr {
			attrs[a.Name.Local] = a.Value
		}
		if name == "[Content_Types].xml" && e.Name.Space == "http://schemas.openxmlformats.org/package/2006/content-types" {
			switch e.Name.Local {
			case "Override":
				// OPC PartName is a URI reference (ECMA-376 Part 2).
				// Match its RFC 3986 percent-encoded path to the ZIP item.
				partName, decodeErr := url.PathUnescape(attrs["PartName"])
				if decodeErr != nil {
					return fmt.Errorf("invalid OPC part URI")
				}
				p.byName[strings.TrimPrefix(partName, "/")] = strings.ToLower(attrs["ContentType"])
			case "Default":
				p.byExtension[strings.ToLower(attrs["Extension"])] = strings.ToLower(attrs["ContentType"])
			}
		}
		if name == "META-INF/manifest.xml" && e.Name.Space == "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" {
			switch e.Name.Local {
			case "file-entry":
				p.byName[attrs["full-path"]] = attrs["media-type"]
			case "encryption-data":
				return fmt.Errorf("encrypted OpenDocument member")
			}
		}
	}
}

// declaredNonTextBinary is a package-declared member whose bytes are not a
// text or embedded-object container. The raw decompressed bytes are already
// in the text views, so request DLP sees them the same way it sees a raw
// upload. OLE and other containers that can hold text are absent here and
// stay unread.
//
// Declarations come from OPC [Content_Types].xml (ECMA-376 Part 2) and the
// ODF manifest:media-type (ODF 1.3 Part 2 §4.16.10). The type strings are:
//   - image/, audio/, video/ top-level types (RFC 6838; IANA media type registry)
//   - font/ plus the deprecated application/font-sfnt and application/font-woff (RFC 8081)
//   - application/x-font-ttf and application/x-fontdata (ECMA-376 Part 1 §15.2.12)
//   - application/vnd.openxmlformats-officedocument.obfuscatedFont (MS-OE376 2.1.34, that section)
//   - application/vnd.ms-office.activeX, not the +xml part (MS-XLSB 2.1.7.2)
func declaredNonTextBinary(contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	switch {
	case strings.HasPrefix(contentType, "image/"),
		strings.HasPrefix(contentType, "audio/"),
		strings.HasPrefix(contentType, "video/"),
		strings.HasPrefix(contentType, "font/"):
		return true
	}
	switch contentType {
	case "application/x-font-ttf",
		"application/x-fontdata",
		"application/font-sfnt",
		"application/font-woff",
		"application/vnd.openxmlformats-officedocument.obfuscatedfont",
		"application/vnd.ms-office.activex":
		return true
	default:
		return false
	}
}

func isXMLPart(name, contentType string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".xml") || strings.HasSuffix(strings.ToLower(name), ".rels") ||
		contentType == "application/xml" || contentType == "text/xml" || strings.HasSuffix(contentType, "+xml")
}

func declarationPriority(name string) int {
	if name == "[Content_Types].xml" || name == "META-INF/manifest.xml" {
		return 0
	}
	return 1
}
