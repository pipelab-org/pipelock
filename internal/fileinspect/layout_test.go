// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fileinspect

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"hash/crc32"
	"math"
	"strings"
	"testing"
)

// Layout fixtures are written field by field (APPNOTE 4.3.7, 4.3.12, 4.3.16)
// because zip.Writer cannot place records where these receivers look.
type layoutEntry struct {
	name    string
	method  uint16
	flags   uint16
	data    []byte // bytes stored after the local header
	plain   []byte // decompressed member, for the CRC and size
	comment []byte
}

// u16 and u32 keep fixture lengths inside the header field widths.
func u16(n int) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic("fixture field exceeds 16 bits")
	}
	return uint16(n)
}

func u32(n int) uint32 {
	if n < 0 || n > math.MaxUint32 {
		panic("fixture field exceeds 32 bits")
	}
	return uint32(n)
}

func putFields(b *bytes.Buffer, fields ...any) {
	for _, f := range fields {
		_ = binary.Write(b, binary.LittleEndian, f)
	}
}

func layoutLocal(e layoutEntry) []byte {
	var b bytes.Buffer
	crc, csize, usize := crc32.ChecksumIEEE(e.plain), u32(len(e.data)), u32(len(e.plain))
	if e.flags&zipFlagDescriptor != 0 {
		crc, csize, usize = 0, 0, 0
	}
	putFields(&b, uint32(0x04034b50), uint16(20), e.flags, e.method, uint32(0), crc, csize, usize, u16(len(e.name)), uint16(0))
	b.WriteString(e.name)
	b.Write(e.data)
	if e.flags&zipFlagDescriptor != 0 {
		putFields(&b, uint32(0x08074b50), crc32.ChecksumIEEE(e.plain), u32(len(e.data)), u32(len(e.plain)))
	}
	return b.Bytes()
}

func layoutCentral(e layoutEntry, offset int) []byte {
	var b bytes.Buffer
	putFields(&b, uint32(0x02014b50), uint16(20), uint16(20), e.flags, e.method, uint32(0),
		crc32.ChecksumIEEE(e.plain), u32(len(e.data)), u32(len(e.plain)), u16(len(e.name)), uint16(0), u16(len(e.comment)),
		uint16(0), uint16(0), uint32(0), u32(offset))
	b.WriteString(e.name)
	b.Write(e.comment)
	return b.Bytes()
}

func layoutEnd(count, size, offset int, comment []byte) []byte {
	var b bytes.Buffer
	putFields(&b, uint32(0x06054b50), uint16(0), uint16(0), u16(count), u16(count), u32(size), u32(offset), u16(len(comment)))
	b.Write(comment)
	return b.Bytes()
}

// huffmanOnly compresses without stored blocks, so no plaintext survives in
// the archive bytes and only an inflating reader can see the secret.
func huffmanOnly(t *testing.T, plain []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, flate.HuffmanOnly)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(plain)
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.Bytes(), []byte("sk_live_")) {
		t.Fatal("compressed fixture still carries the plaintext")
	}
	return b.Bytes()
}

func layoutSecret() []byte {
	return []byte(strings.Repeat("quarterly notes ", 8) + "token=sk_live_" + strings.Repeat("b", 24))
}

func goArchiveNames(t *testing.T, data []byte) []string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	return names
}

// Go archive/zip, Python zipfile, Info-ZIP unzip and libarchive take the last
// end record signature. One hidden in the comment of the record this reader
// selects names a different archive.
func TestInspectTrailingEndRecord(t *testing.T) {
	secret := layoutSecret()
	visible := layoutEntry{name: "a.txt", data: []byte("hello"), plain: []byte("hello")}
	head := append(layoutLocal(visible), layoutCentral(visible, 0)...)
	commentAt := len(head) + endHeaderBytes
	hidden := layoutEntry{name: "b.txt", method: zipMethodDeflate, data: huffmanOnly(t, secret), plain: secret}
	hiddenLocal := layoutLocal(hidden)
	hiddenCentral := layoutCentral(hidden, commentAt)
	comment := append(append(append([]byte{}, hiddenLocal...), hiddenCentral...), layoutEnd(1, len(hiddenCentral), commentAt+len(hiddenLocal), nil)...)
	comment = append(comment, 0, 0) // the hidden record's comment does not reach EOF
	data := append(append([]byte{}, head...), layoutEnd(1, len(head)-len(layoutLocal(visible)), len(layoutLocal(visible)), comment)...)
	if names := goArchiveNames(t, data); len(names) != 1 || names[0] != "b.txt" {
		t.Fatalf("fixture must be read as the hidden archive by archive/zip, got %v", names)
	}
	r := Inspect(t.Context(), data, Limits{1 << 20, 64})
	if r.Complete || r.Reason != "multiple end-of-central-directory records" {
		t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
	}

	// A signature that begins in the comment-length field: length 0x4b50
	// ("PK") and a comment that starts with 05 06.
	straddle := append([]byte{0x05, 0x06}, make([]byte, 0x4b50-2)...)
	data = append(append([]byte{}, head...), layoutEnd(1, len(head)-len(layoutLocal(visible)), len(layoutLocal(visible)), straddle)...)
	r = Inspect(t.Context(), data, Limits{1 << 20, 64})
	if r.Complete || r.Reason != "multiple end-of-central-directory records" {
		t.Fatalf("straddling signature: complete=%t reason=%q", r.Complete, r.Reason)
	}

	// Control: the same archive with a plain comment stays complete.
	data = append(append([]byte{}, head...), layoutEnd(1, len(head)-len(layoutLocal(visible)), len(layoutLocal(visible)), []byte("note"))...)
	if r = Inspect(t.Context(), data, Limits{1 << 20, 64}); !r.Complete {
		t.Fatalf("plain comment: reason=%q", r.Reason)
	}
}

// Python zipfile and libarchive follow a ZIP64 locator that sits right before
// the end record even when the end record is not saturated.
func TestInspectZIP64LocatorBeforeEnd(t *testing.T) {
	secret := layoutSecret()
	hidden := layoutEntry{name: "b.txt", method: zipMethodDeflate, data: huffmanOnly(t, secret), plain: secret}
	png := []byte("\x89PNG\r\n\x1a\n")
	hiddenAt := 30 + len("img.png") + len(png)
	payload := append(append([]byte{}, png...), layoutLocal(hidden)...)
	carrier := layoutEntry{name: "img.png", data: payload, plain: payload}
	local := layoutLocal(carrier)
	cd := len(local)
	hiddenCentral := layoutCentral(hidden, hiddenAt)
	commentAt := cd + centralHeaderBytes + len(carrier.name)
	record64At := commentAt + len(hiddenCentral)
	var tail bytes.Buffer
	tail.Write(hiddenCentral)
	putFields(&tail, uint32(0x06064b50), uint64(44), uint16(45), uint16(45), uint32(0), uint32(0),
		uint64(1), uint64(1), uint64(len(hiddenCentral)), uint64(commentAt))
	putFields(&tail, uint32(0x07064b50), uint32(0), uint64(record64At), uint32(1))
	carrier.comment = tail.Bytes()
	central := layoutCentral(carrier, 0)
	data := append(append(append([]byte{}, local...), central...), layoutEnd(1, len(central), cd, nil)...)
	r := Inspect(t.Context(), data, Limits{1 << 20, 64})
	if r.Complete || r.Reason != "ZIP64 archive is not readable" {
		t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
	}
}

// A stored member with a data descriptor ends, for a streaming reader, at the
// first descriptor signature in its data. libarchive then reads the bytes
// after it as another member.
func TestInspectStoredDescriptorSignature(t *testing.T) {
	secret := layoutSecret()
	hidden := layoutEntry{name: "b.txt", method: zipMethodDeflate, data: huffmanOnly(t, secret), plain: secret}
	png := []byte("\x89PNG\r\n\x1a\n")
	var split bytes.Buffer
	split.Write(png)
	putFields(&split, uint32(0x08074b50), crc32.ChecksumIEEE(png), u32(len(png)), u32(len(png)))
	split.Write(layoutLocal(hidden))
	// Data that ends in "PK" ahead of an unsigned descriptor whose CRC-32
	// starts 07 08 also puts a signature where a streaming reader looks.
	straddle := append(append([]byte{}, png...), 0, 0, 0, 0, 'P', 'K')
	for n := uint32(0); crc32.ChecksumIEEE(straddle)&0xffff != 0x0807; n++ {
		binary.LittleEndian.PutUint32(straddle[len(png):], n)
	}
	for _, tc := range []struct {
		name     string
		payload  []byte
		unsigned bool
		complete bool
	}{
		{"planted descriptor", split.Bytes(), false, false},
		{"signature into unsigned descriptor", straddle, true, false},
		{"plain image", append(append([]byte{}, png...), "IHDR"...), false, true},
		{"plain image, unsigned descriptor", append(append([]byte{}, png...), "IHDR"...), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := layoutEntry{name: "img.png", flags: zipFlagDescriptor, data: tc.payload, plain: tc.payload}
			local := layoutLocal(e)
			if tc.unsigned {
				at := 30 + len(e.name) + len(e.data)
				local = append(local[:at:at], local[at+4:]...)
			}
			central := layoutCentral(e, 0)
			data := append(append(append([]byte{}, local...), central...), layoutEnd(1, len(central), len(local), nil)...)
			r := Inspect(t.Context(), data, Limits{1 << 20, 64})
			if r.Complete != tc.complete || (!tc.complete && r.Reason != "stored member data contains a data descriptor signature") {
				t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
			}
		})
	}
}

// The first unread member decides the reason. The members after it are still
// read, so a credential behind it reaches request DLP (and the core floor
// under warn, where the unread file itself is delivered).
func TestInspectKeepsTextAfterUnreadMember(t *testing.T) {
	secret := layoutSecret()
	brokenZip := archiveFixture(t, map[string][]byte{"inner.txt": []byte("x")})
	brokenZip = brokenZip[:len(brokenZip)-1]
	for _, tc := range []struct {
		name   string
		first  layoutEntry
		reason string
		inText string
	}{
		{"compound file", layoutEntry{name: "x.bin", plain: append(append([]byte{}, compoundFileSignature...), make([]byte, 64)...)}, "OLE compound file member has no reader", ""},
		{"embedded 7z", layoutEntry{name: "x.7z", plain: []byte("7z\xbc\xaf\x27\x1c" + strings.Repeat("copy method data ", 8) + "copy=sk_live_" + strings.Repeat("c", 24))}, "embedded 7z format has no upload reader", "sk_live_cccc"},
		{"malformed xml", layoutEntry{name: "a.xml", plain: []byte("<a><b></a>")}, "malformed package XML", ""},
		{"damaged nested zip", layoutEntry{name: "inner.zip", plain: brokenZip}, "missing or damaged ZIP trailer", ""},
		{"checksum", layoutEntry{name: "c.txt", plain: []byte("bad crc text")}, "local member checksum or size disagrees with directory", "bad crc text"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := tc.first
			first.method = zipMethodDeflate
			first.data = huffmanOnly(t, first.plain)
			second := layoutEntry{name: "notes.txt", method: zipMethodDeflate, data: huffmanOnly(t, secret), plain: secret}
			firstLocal := layoutLocal(first)
			central := layoutCentral(first, 0)
			if tc.name == "checksum" {
				binary.LittleEndian.PutUint32(firstLocal[14:], crc32.ChecksumIEEE(first.plain)^1)
				binary.LittleEndian.PutUint32(central[16:], crc32.ChecksumIEEE(first.plain)^1)
			}
			body := append(append([]byte{}, firstLocal...), layoutLocal(second)...)
			central = append(central, layoutCentral(second, len(firstLocal))...)
			data := append(append(append([]byte{}, body...), central...), layoutEnd(2, len(central), len(body), nil)...)
			r := Inspect(t.Context(), data, Limits{1 << 20, 64})
			joined := strings.Join(r.Texts, "\n")
			if r.Complete || r.Reason != tc.reason || !strings.Contains(joined, "sk_live_bbbb") {
				t.Fatalf("complete=%t reason=%q later secret kept=%t", r.Complete, r.Reason, strings.Contains(joined, "sk_live_bbbb"))
			}
			if tc.inText != "" && !strings.Contains(joined, tc.inText) {
				t.Fatalf("recovered bytes of the unread member are missing: %q", tc.inText)
			}
		})
	}
}

// Receivers stop at the end of the deflate stream and extract the member even
// when compressed bytes follow it. Those bytes stay in the text views.
func TestInspectKeepsInflatedBytesOnError(t *testing.T) {
	secret := layoutSecret()
	e := layoutEntry{name: "a.txt", method: zipMethodDeflate, data: append(huffmanOnly(t, secret), 0, 'x'), plain: secret}
	local := layoutLocal(e)
	central := layoutCentral(e, 0)
	data := append(append(append([]byte{}, local...), central...), layoutEnd(1, len(central), len(local), nil)...)
	r := Inspect(t.Context(), data, Limits{1 << 20, 64})
	if r.Complete || r.Reason != "compressed member has data after its deflate stream" || !strings.Contains(strings.Join(r.Texts, "\n"), "sk_live_bbbb") {
		t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
	}
}

// Reading on after a failed member must not let failed members escape the
// byte budget: each one claims no size, expands, and then fails.
func TestInspectFailedMembersShareBudget(t *testing.T) {
	plain := bytes.Repeat([]byte("A"), 100_000)
	var body, central bytes.Buffer
	for i := range 20 {
		var compressed bytes.Buffer
		w, err := flate.NewWriter(&compressed, flate.BestCompression)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(plain)
		_ = w.Close()
		e := layoutEntry{name: "m" + string(rune('a'+i)) + ".txt", method: zipMethodDeflate, data: append(compressed.Bytes(), 0), plain: nil}
		central.Write(layoutCentral(e, body.Len()))
		body.Write(layoutLocal(e))
	}
	data := append(append(append([]byte{}, body.Bytes()...), central.Bytes()...), layoutEnd(20, central.Len(), body.Len(), nil)...)
	const budget = 300_000
	r := Inspect(t.Context(), data, Limits{budget, 64})
	total := 0
	for _, text := range r.Texts {
		total += len(text)
	}
	if r.Complete || r.ReadBytes > budget || total > budget+central.Len() {
		t.Fatalf("complete=%t reason=%q read=%d text bytes=%d", r.Complete, r.Reason, r.ReadBytes, total)
	}
}
