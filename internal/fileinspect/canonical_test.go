// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fileinspect

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectPublishedSignatures(t *testing.T) {
	key := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	tail := []byte(" key=" + key)
	png := append([]byte("\x89PNG\r\n\x1a\n"), tail...)
	jpeg := append([]byte{0xff, 0xd8, 0xff}, tail...)
	font := append([]byte("\x00\x01\x00\x00"), tail...)
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"png", png},
		{"jpeg", jpeg},
		{"truetype", font},
		{"starview", append([]byte("VCLMTF"), tail...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := archiveFixture(t, map[string][]byte{"member.bin": tc.payload})
			r := Inspect(t.Context(), data, Limits{1 << 20, 64})
			if !r.Complete || !strings.Contains(strings.Join(r.Texts, "\n"), key) {
				t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
			}
		})
	}
	declared := archiveFixture(t, map[string][]byte{
		"[Content_Types].xml":   []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/media/image1.png" ContentType="image/png"/></Types>`),
		"word/media/image1.png": append([]byte{0xff, 0xfe}, tail...),
	})
	r := Inspect(t.Context(), declared, Limits{1 << 20, 64})
	if r.Complete || !strings.Contains(r.Reason, "non-text member") || !strings.Contains(strings.Join(r.Texts, "\n"), key) {
		t.Fatalf("declared image without signature: complete=%t reason=%q", r.Complete, r.Reason)
	}
}

func TestInspectObfuscatedFont(t *testing.T) {
	const guid = "{001B70DC-AA60-4AD5-90EC-18A0948E1EAE}"
	key, ok := obfuscationKey(guid)
	if !ok {
		t.Fatal("font key")
	}
	// ECMA-376 Part 4 §2.8.1 example reverses this GUID to
	// AE1E8E94-A018-EC90-D54A-60AADC701B00.
	want := []byte{0xae, 0x1e, 0x8e, 0x94, 0xa0, 0x18, 0xec, 0x90, 0xd5, 0x4a, 0x60, 0xaa, 0xdc, 0x70, 0x1b, 0x00}
	if !bytes.Equal(key, want) {
		t.Fatalf("key %x", key)
	}
	secret := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	plain := append([]byte{0x00, 0x01, 0x00, 0x00}, bytes.Repeat([]byte{0x11}, 28)...)
	plain = append(plain, []byte(" key="+secret)...)
	obfuscated := deobfuscateEmbeddedFont(plain, key)
	if knownFontSignature(obfuscated) {
		t.Fatal("obfuscated bytes must not already be a font")
	}
	table := `<w:fonts xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:font w:name="Sample"><w:embedRegular r:id="rId1" w:fontKey="` + guid + `"/></w:font></w:fonts>`
	rels := `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/font" Target="fonts/font1.odttf"/></Relationships>`
	members := map[string][]byte{
		"word/fontTable.xml":            []byte(table),
		"word/_rels/fontTable.xml.rels": []byte(rels),
		"word/fonts/font1.odttf":        obfuscated,
	}
	r := Inspect(t.Context(), archiveFixture(t, members), Limits{1 << 20, 64})
	joined := strings.Join(r.Texts, "\n")
	if !r.Complete || !strings.Contains(joined, secret) || !bytes.Contains([]byte(joined), plain) {
		t.Fatalf("complete=%t reason=%q clear=%t", r.Complete, r.Reason, bytes.Contains([]byte(joined), plain))
	}
	members["word/fontTable.xml"] = []byte(strings.ReplaceAll(table, guid, "{00000000-0000-0000-0000-000000000000}"))
	r = Inspect(t.Context(), archiveFixture(t, members), Limits{1 << 20, 64})
	if r.Complete || !strings.Contains(r.Reason, "non-text member") {
		t.Fatalf("wrong key: complete=%t reason=%q", r.Complete, r.Reason)
	}
}

func TestInspectFlagAndDuplicateName(t *testing.T) {
	r := Inspect(t.Context(), rawArchive(t, rawMember{name: "notes.txt", data: []byte("ordinary"), flags: 1 << 1}), Limits{1 << 20, 64})
	if r.Complete || !strings.Contains(r.Reason, "unsupported general purpose flag") {
		t.Fatalf("deflate flag on store: complete=%t reason=%q", r.Complete, r.Reason)
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, name := range []string{"aaaa.txt", "bbbb.txt"} {
		f, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte("ordinary")); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	data := b.Bytes()
	local := bytes.Index(data, []byte("bbbb.txt"))
	central := bytes.LastIndex(data, []byte("bbbb.txt"))
	copy(data[local:], "aaaa.txt")
	copy(data[central:], "aaaa.txt")
	r = Inspect(t.Context(), data, Limits{1 << 20, 64})
	if r.Complete || !strings.Contains(r.Reason, "duplicate member name") {
		t.Fatalf("duplicate: complete=%t reason=%q", r.Complete, r.Reason)
	}
}

func TestInspectDescriptorMismatch(t *testing.T) {
	plain := archiveFixture(t, map[string][]byte{"data.txt": []byte("ordinary text")})
	sig := bytes.LastIndex(plain, []byte("PK\x07\x08"))
	if sig < 0 || sig+8 > len(plain) {
		t.Fatal("data descriptor missing")
	}
	plain[sig+4] ^= 1
	r := Inspect(t.Context(), plain, Limits{1 << 20, 64})
	if r.Complete || !strings.Contains(r.Reason, "checksum") {
		t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
	}
}

func TestInspectUnicodePathExtra(t *testing.T) {
	secret := "sk_live_" + strings.Repeat("a", 24)
	data := unicodePathArchive(t, secret)
	r := Inspect(t.Context(), data, Limits{1 << 20, 64})
	if !r.Complete || !strings.Contains(strings.Join(r.Texts, "\n"), secret) {
		t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
	}
}

func unicodePathArchive(t *testing.T, secret string) []byte {
	t.Helper()
	// Info-ZIP Unicode Path extra, header ID 0x7075: version, CRC-32 of the
	// central name, then the UTF-8 name receivers display.
	payload := append([]byte{1, 0, 0, 0, 0}, secret...)
	if len(payload) != 37 {
		t.Fatalf("unicode path payload length %d", len(payload))
	}
	extra := append([]byte{0x75, 0x70, 37, 0}, payload...)
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	f, err := z.CreateRaw(&zip.FileHeader{
		Name: "a.txt", Method: zip.Store, Extra: extra,
		CRC32: 0x3610a686, CompressedSize64: 5, UncompressedSize64: 5,
	})
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
}

func TestInspectProducerBytes(t *testing.T) {
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
		r := Inspect(t.Context(), data, Limits{1 << 22, 64})
		if !r.Complete {
			t.Fatalf("%s: %s", entry.Name(), r.Reason)
		}
		z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		joined := []byte(strings.Join(r.Texts, "\n"))
		for _, f := range z.File {
			rc, openErr := f.Open()
			if openErr != nil {
				t.Fatal(openErr)
			}
			body, readErr := io.ReadAll(rc)
			closeErr := rc.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("%s %s: %v %v", entry.Name(), f.Name, readErr, closeErr)
			}
			if len(body) > 0 && !bytes.Contains(joined, body) {
				t.Fatalf("%s: delivered bytes for %s are not in the text views", entry.Name(), f.Name)
			}
		}
	}
}
