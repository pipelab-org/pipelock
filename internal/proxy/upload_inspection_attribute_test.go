// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A credential held only in an XML attribute value reaches request DLP,
// including when every character is written as a character reference.
func TestUploadInspectionXMLAttributeCredential(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	key := "sk_live_" + "abcdefghijklmnopqrstuvwx"
	encode := func(format string) string {
		var b strings.Builder
		for _, r := range key {
			fmt.Fprintf(&b, format, r)
		}
		return b.String()
	}
	for _, value := range map[string]string{"plain": key, "decimal": encode("&#%d;"), "hex": encode("&#x%x;")} {
		for name, members := range map[string]map[string][]byte{
			"docx": {
				"[Content_Types].xml": []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>`),
				"word/document.xml":   []byte(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:bookmarkStart w:id="0" w:name="` + value + `"/><w:r><w:t>ordinary</w:t></w:r></w:p></w:body></w:document>`),
			},
			"odt": {
				"mimetype":    []byte("application/vnd.oasis.opendocument.text"),
				"content.xml": []byte(`<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:body><office:text><text:p text:style-name="` + value + `">ordinary</text:p></office:text></office:body></office:document-content>`),
			},
		} {
			data := uploadArchive(t, members)
			_, result := scanRequestBody(context.Background(), BodyScanRequest{Body: bytes.NewReader(data), Scanner: sc, MaxBytes: 1 << 20, ContentType: "application/octet-stream", Action: config.ActionBlock})
			if result.Clean || len(result.DLPMatches) == 0 {
				t.Errorf("%s attribute %q: %+v", name, value[:12], result)
			}
		}
	}
}
