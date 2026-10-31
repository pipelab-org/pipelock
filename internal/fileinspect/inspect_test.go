// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fileinspect

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func archiveFixture(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for name, data := range members {
		f, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestInspectArchive(t *testing.T) {
	plain := archiveFixture(t, map[string][]byte{"data.txt": []byte("ordinary text")})
	crc := bytes.Clone(plain)
	central := bytes.Index(crc, []byte("PK\x01\x02"))
	crc[central+16] ^= 1
	encrypted := bytes.Clone(plain)
	encrypted[central+8] |= 1
	encrypted[6] |= 1
	method := bytes.Clone(plain)
	binary.LittleEndian.PutUint16(method[central+10:], 99)
	binary.LittleEndian.PutUint16(method[8:], 99)
	localFlags := bytes.Clone(plain)
	localFlags[6] |= 1
	count := bytes.Clone(plain)
	end := len(count) - endHeaderBytes
	binary.LittleEndian.PutUint16(count[end+8:], 65534)
	binary.LittleEndian.PutUint16(count[end+10:], 65534)
	for _, tc := range []struct {
		name   string
		data   []byte
		limits Limits
		reason string
		kind   string
	}{
		{"text", []byte("hello"), Limits{4096, 8}, "", ""},
		{"PDF raw", []byte("%PDF-1.7 arbitrary"), Limits{4096, 8}, "", ""},
		{"zip", plain, Limits{4096, 8}, "", "ZIP"},
		{"empty", archiveFixture(t, nil), Limits{4096, 8}, "", "ZIP"},
		{"encrypted", encrypted, Limits{4096, 8}, "encrypted", "ZIP"},
		{"checksum", crc, Limits{4096, 8}, "checksum", "ZIP"},
		{"method", method, Limits{4096, 8}, "compression method", "ZIP"},
		{"local flags", localFlags, Limits{4096, 8}, "flags", "ZIP"},
		{"member count", count, Limits{4096, 8}, "member count", "ZIP"},
		{"trailer", plain[:len(plain)-1], Limits{4096, 8}, "trailer", "ZIP"},
		{"tail", append(bytes.Clone(plain), 'x'), Limits{4096, 8}, "trailer", "ZIP"},
		{"size", plain, Limits{12, 8}, "max_body_bytes", "ZIP"},
		{"bomb", archiveFixture(t, map[string][]byte{"data.txt": bytes.Repeat([]byte("a"), 8192)}), Limits{4096, 8}, "compression-ratio", "ZIP"},
		{"depth", archiveFixture(t, map[string][]byte{"nested.bin": plain}), Limits{4096, 1}, "depth", "ZIP"},
		{"invalid budget", plain, Limits{}, "budget", "ZIP"},
		{"7z", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, Limits{4096, 8}, "no upload reader", "7z"},
		{"RAR4", []byte("Rar!\x1a\x07\x00"), Limits{4096, 8}, "no upload reader", "RAR"},
		{"RAR5", []byte("Rar!\x1a\x07\x01\x00"), Limits{4096, 8}, "no upload reader", "RAR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Inspect(t.Context(), tc.data, tc.limits)
			if r.Type != tc.kind {
				t.Fatalf("type %q want %q", r.Type, tc.kind)
			}
			if tc.kind == "" {
				if r.Recognized {
					t.Fatal("unexpected reader")
				}
				return
			}
			if (tc.reason == "") != r.Complete || (tc.reason != "" && !strings.Contains(r.Reason, tc.reason)) {
				t.Fatalf("complete=%t reason=%q want=%q", r.Complete, r.Reason, tc.reason)
			}
		})
	}
}

func TestInspectPackageDeclarations(t *testing.T) {
	key := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	for _, tc := range []struct {
		name         string
		members      map[string][]byte
		wantComplete bool
		wantText     string
	}{
		{"OPC declared XML", map[string][]byte{
			"[Content_Types].xml": []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/opaque.part" ContentType="application/xml"/></Types>`),
			"word/opaque.part":    []byte(`<p><t>AKIAQ9W8E7</t><t>R6T5Y4U3I2</t></p>`),
		}, true, key},
		{"ODF encrypted", map[string][]byte{
			"META-INF/manifest.xml": []byte(`<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"><manifest:encryption-data/></manifest:file-entry></manifest:manifest>`),
			"content.xml":           []byte("ciphertext"),
		}, false, ""},
		{"malformed XML", map[string][]byte{"word/document.xml": []byte(`<p>unclosed`)}, false, ""},
		{"XML depth", map[string][]byte{"word/document.xml": []byte(strings.Repeat(`<p>`, 65) + strings.Repeat(`</p>`, 65))}, false, ""},
		{"directive", map[string][]byte{"word/document.xml": []byte(`<!DOCTYPE p [<!ENTITY e SYSTEM "https://api.vendor.example/private">]><p>&e;</p>`)}, false, ""},
		// PDF is not a published image, font, or media signature. The raw bytes
		// stay in the text views; the archive is not fully read.
		{"nested PDF raw", map[string][]byte{"document.bin": []byte("%PDF-1.7\xff\x00 compressed")}, false, "%PDF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Inspect(t.Context(), archiveFixture(t, tc.members), Limits{8192, 64})
			if r.Complete != tc.wantComplete || (tc.wantText != "" && !strings.Contains(strings.Join(r.Texts, "\n"), tc.wantText)) {
				t.Fatalf("complete=%t reason=%s", r.Complete, r.Reason)
			}
		})
	}
}

func TestInspectOfficeViews(t *testing.T) {
	secret := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	for _, tc := range []struct {
		name, xml string
		image     bool
	}{
		{"word/document.xml", `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>AKIAQ9W8E7</w:t></w:r><w:r><w:t>R6T5Y4U3I2</w:t></w:r></w:p></w:body></w:document>`, false},
		{"ppt/notesSlides/notesSlide1.xml", `<a:p xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:r><a:t>` + secret + `</a:t></a:r></a:p>`, false},
		{"content.xml", `<text:p xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><text:span>AKIAQ9W8E7</text:span><text:span>R6T5Y4U3I2</text:span></text:p>`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			members := map[string][]byte{tc.name: []byte(tc.xml)}
			if tc.image {
				members["Thumbnails/thumbnail.png"] = []byte("\x89PNG\r\n\x1a\n\xff")
			}
			data := archiveFixture(t, members)
			r := Inspect(t.Context(), data, Limits{4096, 64})
			if !r.Complete || !strings.Contains(strings.Join(r.Texts, "\n"), secret) {
				t.Fatalf("complete=%t reason=%q missing joined text", r.Complete, r.Reason)
			}
		})
	}
}

func TestInspectCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r := Inspect(ctx, archiveFixture(t, map[string][]byte{"x": []byte("a")}), Limits{4096, 64})
	if r.Complete || !strings.Contains(r.Reason, "canceled") {
		t.Fatalf("%+v", r)
	}
}

func TestInspectArchiveMetadataFailures(t *testing.T) {
	plain := archiveFixture(t, map[string][]byte{"data.txt": []byte("ordinary text")})
	c := bytes.Index(plain, []byte("PK\x01\x02"))
	e := len(plain) - endHeaderBytes
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"multi-volume", func(b []byte) { b[e+4] = 1 }},
		{"ZIP64", func(b []byte) {
			binary.LittleEndian.PutUint16(b[e+8:], 65535)
			binary.LittleEndian.PutUint16(b[e+10:], 65535)
		}},
		{"directory offset", func(b []byte) { b[e+16]++ }},
		{"directory record", func(b []byte) { b[c] = 0 }},
		{"directory length", func(b []byte) { binary.LittleEndian.PutUint16(b[c+28:], 65535) }},
		{"local offset", func(b []byte) { binary.LittleEndian.PutUint32(b[c+42:], 0xffffffff) }},
		{"local name", func(b []byte) { b[30] ^= 1 }},
		{"local length", func(b []byte) { binary.LittleEndian.PutUint16(b[26:], 65535) }},
		{"compressed overlap", func(b []byte) { binary.LittleEndian.PutUint32(b[c+20:], 65535) }},
		{"unread directory", func(b []byte) { binary.LittleEndian.PutUint16(b[e+8:], 0); binary.LittleEndian.PutUint16(b[e+10:], 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := bytes.Clone(plain)
			tc.mutate(data)
			r := Inspect(t.Context(), data, Limits{4096, 64})
			if r.Complete || r.Reason == "" {
				t.Fatalf("malformed archive reported complete: %+v", r)
			}
		})
	}
}

func TestInspectAdditionalMembers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		members  map[string][]byte
		complete bool
	}{
		{"directory", map[string][]byte{"directory/": nil, "directory/file.txt": []byte("ordinary")}, true},
		{"nested 7z", map[string][]byte{"nested.bin": {'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}}, false},
		{"binary", map[string][]byte{"unknown.bin": {0xff, 0xfe, 0xff}}, false},
		{"macro", map[string][]byte{"word/vbaProject.bin": {0xff, 0xfe, 0xff}}, false},
		{"printer settings", map[string][]byte{"word/printerSettings/printerSettings1.bin": {0xff, 0xfe, 0xff}}, false},
		{"spreadsheet printer settings", map[string][]byte{"xl/printerSettings/printerSettings1.bin": {0xff, 0xfe, 0xff}}, false},
		{"presentation printer settings", map[string][]byte{"ppt/printerSettings/printerSettings1.bin": {0xff, 0xfe, 0xff}}, false},
		{"printer settings elsewhere", map[string][]byte{"docProps/printerSettings/printerSettings1.bin": {0xff, 0xfe, 0xff}}, false},
		{"malformed declarations", map[string][]byte{"[Content_Types].xml": []byte(`<Types`)}, false},
		{"default XML", map[string][]byte{"[Content_Types].xml": []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="part" ContentType="text/xml"/></Types>`), "custom.part": []byte(`<p>ordinary</p>`)}, true},
		{"ODF metadata", map[string][]byte{"META-INF/manifest.xml": []byte(`<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/></manifest:manifest>`), "meta.xml": []byte(`<meta>ordinary</meta>`)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Inspect(t.Context(), archiveFixture(t, tc.members), Limits{8192, 64})
			if r.Complete != tc.complete {
				t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r := contextReader{ctx, bytes.NewReader([]byte("data"))}
	if _, err := r.Read(make([]byte, 4)); err == nil {
		t.Fatal("canceled member read succeeded")
	}
}

func TestInspectPreflightEntryBudget(t *testing.T) {
	data := archiveFixture(t, map[string][]byte{"one": nil, "two": nil})
	w := walk{ctx: t.Context(), limits: Limits{4096, 64}, entries: 1}
	if err := w.preflight(data); err == nil || !strings.Contains(err.Error(), "member count") {
		t.Fatalf("entry budget: %v", err)
	}
}

func TestInspectOPCPartURIs(t *testing.T) {
	key := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	for _, tc := range []struct {
		name, declaration, member string
		complete                  bool
	}{
		{"escaped", `<Override PartName="/word/custom%20text.part" ContentType="application/xml"/>`, "word/custom text.part", true},
		{"extension case", `<Default Extension="PART" ContentType="application/xml"/>`, "word/custom.part", true},
		{"invalid URI", `<Override PartName="/word/bad%escape.part" ContentType="application/xml"/>`, "word/custom.part", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			members := map[string][]byte{"[Content_Types].xml": []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` + tc.declaration + `</Types>`), tc.member: []byte(`<p><t>AKIAQ9W8E7</t><t>R6T5Y4U3I2</t></p>`)}
			r := Inspect(t.Context(), archiveFixture(t, members), Limits{8192, 64})
			if r.Complete != tc.complete || (r.Complete && !strings.Contains(strings.Join(r.Texts, "\n"), key)) {
				t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
			}
		})
	}
}

func TestInspectXMLFailurePrivacy(t *testing.T) {
	const privateMarker = "private-document-element"
	for _, name := range []string{"word/document.xml", "[Content_Types].xml"} {
		t.Run(name, func(t *testing.T) {
			r := Inspect(t.Context(), archiveFixture(t, map[string][]byte{name: []byte(`<` + privateMarker + `></mismatch>`)}), Limits{8192, 64})
			if r.Complete || r.Reason == "" || strings.Contains(r.Reason, privateMarker) {
				t.Fatalf("reason must name failure without document text: %q", r.Reason)
			}
		})
	}
}

// A local record the central directory omits is extracted by streaming readers
// but skipped by a directory walk, so it must leave the file incomplete.
func TestInspectUnlistedMemberBytes(t *testing.T) {
	key := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	archiveAt := func(offset int64, name, text string) []byte {
		var b bytes.Buffer
		z := zip.NewWriter(&b)
		z.SetOffset(offset)
		f, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(text)); err != nil {
			t.Fatal(err)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	hidden := archiveAt(0, "secret.txt", "key="+key+strings.Repeat(" padding", 32))
	hiddenRecord := hidden[:bytes.Index(hidden, []byte("PK\x01\x02"))]
	if bytes.Contains(hiddenRecord, []byte(key)) {
		t.Fatal("hidden record must be compressed")
	}
	plain := archiveFixture(t, map[string][]byte{"data.txt": []byte("ordinary text")})
	central := bytes.Index(plain, []byte("PK\x01\x02"))
	duplicate := append(bytes.Clone(plain[:central]), plain[central:len(plain)-endHeaderBytes]...)
	duplicate = append(duplicate, plain[central:len(plain)-endHeaderBytes]...)
	duplicate = append(duplicate, plain[len(plain)-endHeaderBytes:]...)
	e := len(duplicate) - endHeaderBytes
	binary.LittleEndian.PutUint16(duplicate[e+8:], 2)
	binary.LittleEndian.PutUint16(duplicate[e+10:], 2)
	binary.LittleEndian.PutUint32(duplicate[e+12:], 2*binary.LittleEndian.Uint32(plain[len(plain)-endHeaderBytes+12:]))
	gap := append(bytes.Clone(plain[:central]), "unlisted bytes"...)
	gap = append(gap, plain[central:]...)
	binary.LittleEndian.PutUint32(gap[len(gap)-endHeaderBytes+16:], binary.LittleEndian.Uint32(plain[len(plain)-endHeaderBytes+16:])+uint32(len("unlisted bytes")))
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"gap before directory", gap},
		{"unlisted local record", append(bytes.Clone(hiddenRecord), archiveAt(int64(len(hiddenRecord)), "a.txt", "hello")...)},
		{"bytes after signature", append([]byte("PK\x03\x04stub"), archiveAt(8, "a.txt", "hello")...)},
		{"duplicate directory reference", duplicate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Inspect(t.Context(), tc.data, Limits{1 << 20, 64})
			if r.Complete || !strings.Contains(r.Reason, "outside listed members") {
				t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
			}
		})
	}
	raw := func() []byte {
		var b bytes.Buffer
		z := zip.NewWriter(&b)
		f, err := z.CreateRaw(&zip.FileHeader{Name: "a.txt", Method: zip.Store, CRC32: 0x3610a686, CompressedSize64: 5, UncompressedSize64: 5})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}()
	if r := Inspect(t.Context(), raw, Limits{4096, 64}); !r.Complete {
		t.Fatalf("member without a data descriptor: %q", r.Reason)
	}
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, readErr := os.ReadFile(filepath.Join("testdata", entry.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if Kind(data) != "ZIP" {
			continue
		}
		if r := Inspect(t.Context(), data, Limits{1 << 22, 64}); !r.Complete {
			t.Fatalf("%s: producer file reported incomplete: %q", entry.Name(), r.Reason)
		}
	}
}

// archive/zip stops at the end of a deflate stream; compressed bytes after it
// lie inside a listed member's span, so coverage alone can't detect them.
func TestInspectDeflateTrailingBytes(t *testing.T) {
	text := []byte("ordinary text")
	var compressed bytes.Buffer
	fw, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fw.Write(text); err != nil {
		t.Fatal(err)
	}
	if err = fw.Close(); err != nil {
		t.Fatal(err)
	}
	build := func(raw []byte) []byte {
		var b bytes.Buffer
		z := zip.NewWriter(&b)
		f, createErr := z.CreateRaw(&zip.FileHeader{Name: "data.txt", Method: zip.Deflate, CRC32: crc32.ChecksumIEEE(text), CompressedSize64: uint64(len(raw)), UncompressedSize64: uint64(len(text))})
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, createErr = f.Write(raw); createErr != nil {
			t.Fatal(createErr)
		}
		if createErr = z.Close(); createErr != nil {
			t.Fatal(createErr)
		}
		return b.Bytes()
	}
	if r := Inspect(t.Context(), build(compressed.Bytes()), Limits{4096, 64}); !r.Complete {
		t.Fatalf("exact deflate member: %q", r.Reason)
	}
	trailing := append(bytes.Clone(compressed.Bytes()), "PK\x03\x04 hidden record"...)
	if r := Inspect(t.Context(), build(trailing), Limits{4096, 64}); r.Complete || !strings.Contains(r.Reason, "after its deflate stream") {
		t.Fatalf("trailing compressed bytes: complete=%t reason=%q", r.Complete, r.Reason)
	}
}

// A StarView metafile is accepted from its VCLMTF signature, referenced or not.
// A draw:image href does not accept a member that has no published signature.
func TestInspectODFReplacementImages(t *testing.T) {
	metafile := []byte("VCLMTF\x01\x00\xff\xfe\x00")
	blob := []byte{0xff, 0xfe, 0x00, 0x11}
	frame := func(href string) []byte {
		return []byte(`<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:xlink="http://www.w3.org/1999/xlink"><draw:frame><draw:object xlink:href="./Object 1"/><draw:image xlink:href="` + href + `"/></draw:frame></office:document-content>`)
	}
	ordered := func(members ...[2][]byte) []byte {
		var b bytes.Buffer
		z := zip.NewWriter(&b)
		for _, m := range members {
			f, err := z.Create(string(m[0]))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.Write(m[1]); err != nil {
				t.Fatal(err)
			}
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	member := func(name string, data []byte) [2][]byte { return [2][]byte{[]byte(name), data} }
	for _, tc := range []struct {
		name     string
		data     []byte
		complete bool
	}{
		{"replacement after image", ordered(member("ObjectReplacements/Object 1", metafile), member("content.xml", frame("./ObjectReplacements/Object 1"))), true},
		{"percent-encoded reference", ordered(member("content.xml", frame("./ObjectReplacements/Object%201")), member("ObjectReplacements/Object 1", metafile)), true},
		{"sub-document reference", ordered(member("Object 1/ObjectReplacements/chart", metafile), member("Object 1/content.xml", frame("./ObjectReplacements/chart"))), true},
		{"unreferenced metafile", ordered(member("ObjectReplacements/Object 1", metafile), member("content.xml", frame("./ObjectReplacements/Other"))), true},
		{"referenced blob", ordered(member("ObjectReplacements/Object 1", blob), member("content.xml", frame("./ObjectReplacements/Object 1"))), false},
		{"unreferenced blob", ordered(member("ObjectReplacements/Object 1", blob), member("content.xml", frame("./ObjectReplacements/Other"))), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Inspect(t.Context(), tc.data, Limits{8192, 64})
			if r.Complete != tc.complete || (!tc.complete && !strings.Contains(r.Reason, "non-text member")) {
				t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
			}
		})
	}
}

// APPNOTE 4.3.9.2: a member whose local header carries a ZIP64 extended
// information field (header ID 0x0001) has 8-byte data-descriptor sizes,
// whatever its actual size. Streaming producers may always write this form.
func TestInspectZIP64DataDescriptor(t *testing.T) {
	const name, text = "data.txt", "ordinary text"
	const nameLen, textLen uint32 = 8, 13
	sum := crc32.ChecksumIEEE([]byte(text))
	le16 := binary.LittleEndian.AppendUint16
	le32 := binary.LittleEndian.AppendUint32
	le64 := binary.LittleEndian.AppendUint64
	build := func(zip64 bool) []byte {
		var extra []byte
		descriptor := uint32(16)
		if zip64 {
			extra = le64(le64(le16(le16(nil, 0x0001), 16), 0), 0)
			descriptor = 24
		}
		extraLen := uint16(0)
		if zip64 {
			extraLen = 20 // 4-byte record header plus two 8-byte sizes.
		}
		var b []byte
		b = le32(b, 0x04034b50)
		b = le16(le16(le16(b, 20), 0x0008), 0)
		b = le32(le16(le16(b, 0), 0), 0)
		b = le32(le32(b, 0), 0)
		b = le16(le16(b, uint16(nameLen)), extraLen)
		b = append(append(append(b, name...), extra...), text...)
		b = le32(le32(b, 0x08074b50), sum)
		if zip64 {
			b = le64(le64(b, uint64(textLen)), uint64(textLen))
		} else {
			b = le32(le32(b, textLen), textLen)
		}
		directory := 30 + nameLen + uint32(extraLen) + textLen + descriptor
		b = le32(b, 0x02014b50)
		b = le16(le16(le16(le16(b, 20), 20), 0x0008), 0)
		b = le32(le16(le16(b, 0), 0), sum)
		b = le32(le32(b, textLen), textLen)
		b = le16(le16(le16(b, uint16(nameLen)), 0), 0)
		b = le32(le16(le16(b, 0), 0), 0)
		b = le32(b, 0)
		b = append(b, name...)
		b = le32(b, 0x06054b50)
		b = le16(le16(le16(le16(b, 0), 0), 1), 1)
		b = le32(le32(b, 46+nameLen), directory)
		return le16(b, 0)
	}
	for _, zip64 := range []bool{false, true} {
		if r := Inspect(t.Context(), build(zip64), Limits{4096, 64}); !r.Complete {
			t.Fatalf("zip64=%t: %q", zip64, r.Reason)
		}
	}
}

// A declared content type does not make a non-text member readable. The raw
// bytes stay in the text views. OLE containers stay unread.
func TestInspectDeclaredBinaryMembers(t *testing.T) {
	key := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	payload := append([]byte{0xff, 0xfe}, []byte("key="+key)...)
	opc := func(part, contentType string) map[string][]byte {
		return map[string][]byte{
			"[Content_Types].xml": []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/` + part + `" ContentType="` + contentType + `"/></Types>`),
			part:                  payload,
		}
	}
	odf := func(part, mediaType string) map[string][]byte {
		return map[string][]byte{
			"META-INF/manifest.xml": []byte(`<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/><manifest:file-entry manifest:full-path="` + part + `" manifest:media-type="` + mediaType + `"/></manifest:manifest>`),
			part:                    payload,
		}
	}
	for _, tc := range []struct {
		name     string
		members  map[string][]byte
		complete bool
	}{
		{"obfuscated font", opc("word/fonts/font1.odttf", "application/vnd.openxmlformats-officedocument.obfuscatedFont"), false},
		{"odf truetype", odf("Fonts/Font_Sample_1.ttf", "application/x-font-ttf"), false},
		{"font data", opc("word/fonts/font1.fntdata", "application/x-fontdata"), false},
		{"audio", opc("word/media/audio1.mp3", "audio/mpeg"), false},
		{"video", opc("ppt/media/video1.mp4", "video/mp4"), false},
		{"font top-level", odf("Fonts/face.ttf", "font/ttf"), false},
		{"activex binary", opc("xl/activeX/activeX1.bin", "application/vnd.ms-office.activeX"), false},
		{"ole object", opc("word/embeddings/oleObject1.bin", "application/vnd.openxmlformats-officedocument.oleObject"), false},
		{"octet stream", opc("word/embeddings/unknown.bin", "application/octet-stream"), false},
		{"undeclared", map[string][]byte{"word/fonts/font1.odttf": payload}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Inspect(t.Context(), archiveFixture(t, tc.members), Limits{1 << 20, 64})
			joined := strings.Join(r.Texts, "\n")
			if r.Complete != tc.complete || !strings.Contains(joined, key) || (!tc.complete && !strings.Contains(r.Reason, "non-text member")) {
				t.Fatalf("complete=%t reason=%q haskey=%t", r.Complete, r.Reason, strings.Contains(joined, key))
			}
		})
	}
	// activeX+xml stays an XML part (MS-XLSB 2.1.7.1), so character data is joined.
	xmlKey := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	members := map[string][]byte{
		"[Content_Types].xml":     []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/activeX/activeX1.xml" ContentType="application/vnd.ms-office.activeX+xml"/></Types>`),
		"xl/activeX/activeX1.xml": []byte(`<ocx xmlns="http://schemas.microsoft.com/office/2006/activeX"><a>AKIAQ9W8E7</a><b>R6T5Y4U3I2</b></ocx>`),
	}
	r := Inspect(t.Context(), archiveFixture(t, members), Limits{1 << 20, 64})
	if !r.Complete || !strings.Contains(strings.Join(r.Texts, "\n"), xmlKey) {
		t.Fatalf("activex xml: complete=%t reason=%q", r.Complete, r.Reason)
	}
}

// archive/zip Open returns EOF for a directory whose uncompressed size is 0
// without reading its compressed bytes (APPNOTE directories are zero-length;
// some writers still store a deflate stream). Those bytes sit inside the
// listed member span, so coverage does not see them, and a deflate stream
// hides plaintext from the raw body.
func TestInspectDirectoryCompressedPayload(t *testing.T) {
	key := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	deflated := func(payload []byte) []byte {
		t.Helper()
		var b bytes.Buffer
		w, err := flate.NewWriter(&b, flate.BestCompression)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	build := func(method uint16, payload []byte) []byte {
		t.Helper()
		raw := payload
		uncompressed := uint64(len(payload))
		if method == zip.Deflate {
			raw = deflated(payload)
		}
		var b bytes.Buffer
		z := zip.NewWriter(&b)
		// archive/zip refuses a trailing slash. Write a same-length name, then
		// mark it as a directory and claim uncompressed size 0.
		f, err := z.CreateRaw(&zip.FileHeader{
			Name:               "secretX",
			Method:             method,
			CRC32:              crc32.ChecksumIEEE(payload),
			CompressedSize64:   uint64(len(raw)),
			UncompressedSize64: uncompressed,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(raw); err != nil {
			t.Fatal(err)
		}
		plain, err := z.Create("visible.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = plain.Write([]byte("ordinary text")); err != nil {
			t.Fatal(err)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		data := b.Bytes()
		local := bytes.Index(data, []byte("secretX"))
		central := bytes.LastIndex(data, []byte("secretX"))
		if local < 0 || central == local {
			t.Fatal("member name missing")
		}
		copy(data[local:], "secret/")
		copy(data[central:], "secret/")
		binary.LittleEndian.PutUint32(data[local-8:], 0) // local uncompressed size
		binary.LittleEndian.PutUint32(data[central-22:], 0)
		return data
	}
	for _, tc := range []struct {
		name    string
		data    []byte
		wantKey bool
		reason  string
	}{
		{"stored secret", build(zip.Store, []byte("key="+key)), true, "directory member has unread data"},
		{"deflated secret", build(zip.Deflate, []byte("key="+key)), true, "directory member has unread data"},
		{"empty deflate directory", build(zip.Deflate, nil), false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Inspect(t.Context(), tc.data, Limits{1 << 20, 64})
			joined := strings.Join(r.Texts, "\n")
			if tc.reason == "" {
				if !r.Complete || strings.Contains(joined, key) {
					t.Fatalf("empty directory: complete=%t reason=%q", r.Complete, r.Reason)
				}
				return
			}
			if r.Complete || !strings.Contains(r.Reason, tc.reason) || !strings.Contains(joined, key) {
				t.Fatalf("complete=%t reason=%q haskey=%t", r.Complete, r.Reason, strings.Contains(joined, key))
			}
		})
	}
	bomb := build(zip.Deflate, bytes.Repeat([]byte("A"), 100000))
	if r := Inspect(t.Context(), bomb, Limits{len(bomb) + 32, 64}); r.Complete || !strings.Contains(r.Reason, "max_body_bytes") {
		t.Fatalf("directory expansion: complete=%t reason=%q", r.Complete, r.Reason)
	}
}

type rawMember struct {
	name    string
	data    []byte
	flags   uint16
	creator uint16
	attrs   uint32
	extra   []byte
}

// rawArchive stores members with caller-chosen header fields. CreateRaw keeps
// the flag bits, host byte, external attributes and extra field as given.
func rawArchive(t *testing.T, members ...rawMember) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, m := range members {
		f, err := z.CreateRaw(&zip.FileHeader{
			Name: m.name, Method: zip.Store, Flags: m.flags, CreatorVersion: m.creator, ExternalAttrs: m.attrs, Extra: m.extra,
			CRC32: crc32.ChecksumIEEE(m.data), CompressedSize64: uint64(len(m.data)), UncompressedSize64: uint64(len(m.data)),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(m.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// archive/zip reads none of APPNOTE's encryption indicators and returns stored
// ciphertext as the member. Each case would otherwise read complete: a declared
// image passes the non-text rule and hex ciphertext is valid UTF-8.
func TestInspectEncryptionIndicators(t *testing.T) {
	declarations := rawMember{name: "[Content_Types].xml", data: []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="png" ContentType="image/png"/></Types>`)}
	ciphertext := []byte{0x9c, 0x13, 0xf7, 0x02, 0xaa, 0x51, 0xe8, 0x7d, 0x00, 0xc4, 0x3b, 0x91}
	hexCiphertext := []byte("9c13f702aa51e87d00c43b91")
	for _, tc := range []struct {
		name   string
		member rawMember
		reason string
	}{
		{"strong encryption bit 6 declared image", rawMember{name: "word/media/image1.png", data: ciphertext, flags: 1 << 6}, "encrypted member"},
		{"strong encryption bit 6 text", rawMember{name: "notes.txt", data: hexCiphertext, flags: 1 << 6}, "encrypted member"},
		{"masked local header bit 13", rawMember{name: "notes.txt", data: hexCiphertext, flags: 1 << 13}, "encrypted member"},
		{"compressed patched data bit 5", rawMember{name: "notes.txt", data: hexCiphertext, flags: 1 << 5}, "patched data member"},
		{"strong encryption header extra", rawMember{name: "notes.txt", data: hexCiphertext, extra: []byte{0x17, 0x00, 0x04, 0x00, 2, 0, 0, 0}}, "encrypted member"},
		{"AE-x extra", rawMember{name: "word/media/image1.png", data: ciphertext, extra: []byte{0x01, 0x99, 0x07, 0x00, 2, 0, 'A', 'E', 3, 8, 0}}, "encrypted member"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Inspect(t.Context(), rawArchive(t, declarations, tc.member), Limits{1 << 20, 64})
			if r.Complete || !strings.Contains(r.Reason, tc.reason) {
				t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
			}
		})
	}
	// Bits outside the indicators, such as EFS (bit 11), stay readable.
	r := Inspect(t.Context(), rawArchive(t, declarations, rawMember{name: "notes.txt", data: hexCiphertext, flags: 1 << 11}), Limits{1 << 20, 64})
	if !r.Complete {
		t.Fatalf("EFS member: complete=%t reason=%q", r.Complete, r.Reason)
	}
}

// MS-CFB compound files are sector-allocated containers and VBA source inside
// them is compressed (MS-OVBA), so none of the allow routes may complete one.
func TestInspectCompoundFileMembers(t *testing.T) {
	cfb := append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, bytes.Repeat([]byte{0}, 504)...)
	opc := `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="png" ContentType="image/png"/>` +
		`<Override PartName="/xl/activeX/activeX1.bin" ContentType="application/vnd.ms-office.activeX"/>` +
		`<Override PartName="/word/fonts/font1.odttf" ContentType="application/vnd.openxmlformats-officedocument.obfuscatedFont"/>` +
		`<Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>`
	manifest := func(entry string) string {
		return `<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>` + entry + `</manifest:manifest>`
	}
	content := `<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:xlink="http://www.w3.org/1999/xlink"><draw:frame><draw:image xlink:href="./ObjectReplacements/Obj"/></draw:frame></office:document-content>`
	for _, tc := range []struct {
		name    string
		members map[string][]byte
	}{
		{"vba project", map[string][]byte{"[Content_Types].xml": []byte(opc), "xl/vbaProject.bin": cfb}},
		{"declared image", map[string][]byte{"[Content_Types].xml": []byte(opc), "word/media/image1.png": cfb}},
		{"declared activex", map[string][]byte{"[Content_Types].xml": []byte(opc), "xl/activeX/activeX1.bin": cfb}},
		{"declared font", map[string][]byte{"[Content_Types].xml": []byte(opc), "word/fonts/font1.odttf": cfb}},
		{"odf manifest image", map[string][]byte{"META-INF/manifest.xml": []byte(manifest(`<manifest:file-entry manifest:full-path="Pictures/a.png" manifest:media-type="image/png"/>`)), "Pictures/a.png": cfb}},
		{"odf replacement image", map[string][]byte{"META-INF/manifest.xml": []byte(manifest("")), "content.xml": []byte(content), "ObjectReplacements/Obj": cfb}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Inspect(t.Context(), archiveFixture(t, tc.members), Limits{1 << 20, 64})
			if r.Complete || r.Reason != "OLE compound file member has no reader" {
				t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
			}
		})
	}
}

// archive/zip Open decides a directory by its trailing slash, while
// FileInfo().IsDir also honours host-dependent external attributes. A slashless
// member marked as a directory is read as a file by Open, Python zipfile,
// Info-ZIP and LibreOffice, so it must get the file member checks.
func TestInspectDirectoryAttributeOnFile(t *testing.T) {
	key := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write([]byte(strings.Repeat("ordinary text ", 200) + "key=" + key + strings.Repeat(" more text", 200))); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	split := []byte(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>AKIAQ9W8E7</w:t></w:r><w:r><w:t>R6T5Y4U3I2</w:t></w:r></w:p></w:body></w:document>`)
	const unixHost, fatHost = 3 << 8, 0
	unixDir, fatDir := uint32(0o040755)<<16, uint32(0x10)
	t.Run("unread binary", func(t *testing.T) {
		r := Inspect(t.Context(), rawArchive(t, rawMember{name: "notes.bin", data: gz.Bytes(), creator: fatHost, attrs: fatDir}), Limits{1 << 20, 64})
		if r.Complete || r.Reason != "non-text member has no reader" {
			t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
		}
	})
	t.Run("split runs joined", func(t *testing.T) {
		r := Inspect(t.Context(), rawArchive(t, rawMember{name: "word/document.xml", data: split, creator: unixHost, attrs: unixDir}), Limits{1 << 20, 64})
		if !r.Complete || !strings.Contains(strings.Join(r.Texts, "\n"), key) {
			t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
		}
	})
	t.Run("slash directory", func(t *testing.T) {
		r := Inspect(t.Context(), rawArchive(t, rawMember{name: "word/", creator: unixHost, attrs: unixDir}, rawMember{name: "word/document.xml", data: split}), Limits{1 << 20, 64})
		if !r.Complete {
			t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
		}
	})
}
