// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fileinspect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
)

// zipMember is one central-directory entry whose local header, data and
// optional data descriptor were checked against PKWARE APPNOTE 6.3.10.
type zipMember struct {
	name         string
	comment      string
	method       uint16
	flags        uint16
	crc          uint32
	compressed   uint64
	uncompressed uint64
	payload      []byte
	localExtra   []byte
	centralExtra []byte
}

type zipArchive struct {
	comment string
	members []zipMember
}

// APPNOTE 6.3.10 4.4.4. Bit 3 is the data descriptor, bit 11 is UTF-8.
// Bits 1 and 2 are deflate options and are defined only for method 8 (and 9,
// which this reader does not accept).
const (
	zipFlagDescriptor = 1 << 3
	zipFlagUTF8       = 1 << 11
	zipFlagDeflateOpt = 1<<1 | 1<<2
	zipMethodStore    = 0
	zipMethodDeflate  = 8
	dataDescriptorSig = "PK\x07\x08"
)

// parseCanonicalZIP accepts one archive only when local file records tile the
// bytes from offset 0 through the central directory, every central entry
// matches its local header, and the single end-of-central-directory record
// accounts for those entries.
//
// APPNOTE 6.3.10 sections used here:
//   - 4.3.1 / 4.3.16: one end-of-central-directory record ends the archive
//   - 4.3.2 / 4.3.6: every local record has a central header and the records
//     precede that directory (a self-extractor stub is 4.1.9, not a gap)
//   - 4.3.7 / 4.3.12: local and central headers name the same member
//   - 4.3.8: file data follows the local header; a zero-length member has none
//   - 4.3.9 through 4.3.9.4: data descriptor, including 8-byte ZIP64 sizes
//   - 4.4.4 / 4.4.5: flag and method allowlists below
//   - 4.4.7 through 4.4.9: with bit 3 set, local CRC and sizes are zero
//   - 4.5.1 / 4.5.3 / 4.5.12 / 4.6.1: extra fields, ZIP64, strong encryption, AE-x
func parseCanonicalZIP(data []byte, entryBudget int) (zipArchive, error) {
	for i := len(data) - endHeaderBytes; i >= max(0, len(data)-endHeaderBytes-65535); i-- {
		if !bytes.HasPrefix(data[i:], []byte("PK\x05\x06")) {
			continue
		}
		e := data[i:]
		if int(binary.LittleEndian.Uint16(e[20:])) != len(e)-endHeaderBytes {
			continue
		}
		// Go archive/zip, Python zipfile, Info-ZIP unzip and libarchive take
		// the last end record signature in the tail, not the one whose
		// comment reaches EOF. A later signature, here inside this record's
		// comment, names a central directory those receivers read instead.
		if bytes.Contains(data[i+1:], []byte("PK\x05\x06")) {
			return zipArchive{}, fmt.Errorf("multiple end-of-central-directory records")
		}
		// APPNOTE 4.3.15: a ZIP64 end of central directory locator sits
		// immediately before this record. Python zipfile and libarchive
		// follow it even when no field below is 0xFFFF or 0xFFFFFFFF.
		if i >= 20 && bytes.HasPrefix(data[i-20:], []byte("PK\x06\x07")) {
			return zipArchive{}, fmt.Errorf("ZIP64 archive is not readable")
		}
		count := int(binary.LittleEndian.Uint16(e[10:]))
		if binary.LittleEndian.Uint32(e[4:]) != 0 || int(binary.LittleEndian.Uint16(e[8:])) != count {
			return zipArchive{}, fmt.Errorf("multi-volume archive is not readable")
		}
		size := int64(binary.LittleEndian.Uint32(e[12:]))
		offset := int64(binary.LittleEndian.Uint32(e[16:]))
		if count == 65535 || size == 0xffffffff || offset == 0xffffffff {
			return zipArchive{}, fmt.Errorf("ZIP64 archive is not readable")
		}
		if count > entryBudget || int64(count)*centralHeaderBytes > size {
			return zipArchive{}, fmt.Errorf("member count exceeds metadata budget")
		}
		if offset+size != int64(i) {
			return zipArchive{}, fmt.Errorf("invalid central directory trailer")
		}
		if offset > math.MaxInt32 {
			return zipArchive{}, fmt.Errorf("ZIP directory exceeds addressable index")
		}
		cd := int(offset)
		p := cd
		spans := make([][2]int, 0, count)
		members := make([]zipMember, 0, count)
		for range count {
			if p > i-centralHeaderBytes || !bytes.HasPrefix(data[p:], []byte("PK\x01\x02")) {
				return zipArchive{}, fmt.Errorf("invalid central directory record")
			}
			nameLen := int(binary.LittleEndian.Uint16(data[p+28:]))
			extraLen := int(binary.LittleEndian.Uint16(data[p+30:]))
			commentLen := int(binary.LittleEndian.Uint16(data[p+32:]))
			n := centralHeaderBytes + nameLen + extraLen + commentLen
			if n < centralHeaderBytes || n > i-p {
				return zipArchive{}, fmt.Errorf("truncated central directory record")
			}
			member, local, end, err := canonicalMember(data, p, cd, nameLen, extraLen, commentLen)
			if err != nil {
				return zipArchive{}, err
			}
			members = append(members, member)
			spans = append(spans, [2]int{local, end})
			p += n
		}
		if p != i {
			return zipArchive{}, fmt.Errorf("unread central directory data")
		}
		// APPNOTE 4.3.6: the local records tile [0, central directory).
		// A repeated directory entry for one local overlaps and is reported
		// here, before the distinct-name check.
		sort.Slice(spans, func(a, b int) bool { return spans[a][0] < spans[b][0] })
		next := 0
		for _, s := range spans {
			if s[0] != next {
				return zipArchive{}, fmt.Errorf("ZIP data outside listed members")
			}
			next = s[1]
		}
		if next != cd {
			return zipArchive{}, fmt.Errorf("ZIP data outside listed members")
		}
		seen := make(map[string]struct{}, len(members))
		for _, m := range members {
			if _, ok := seen[m.name]; ok {
				return zipArchive{}, fmt.Errorf("duplicate member name")
			}
			seen[m.name] = struct{}{}
		}
		return zipArchive{comment: string(e[endHeaderBytes:]), members: members}, nil
	}
	return zipArchive{}, fmt.Errorf("missing or damaged ZIP trailer")
}

func canonicalMember(data []byte, p, cd, nameLen, extraLen, commentLen int) (zipMember, int, int, error) {
	flags := binary.LittleEndian.Uint16(data[p+8:])
	method := binary.LittleEndian.Uint16(data[p+10:])
	crc := binary.LittleEndian.Uint32(data[p+16:])
	comp32 := binary.LittleEndian.Uint32(data[p+20:])
	uncomp32 := binary.LittleEndian.Uint32(data[p+24:])
	local64 := int64(binary.LittleEndian.Uint32(data[p+42:]))
	if local64 > math.MaxInt32 || local64+30 > int64(cd) {
		return zipMember{}, 0, 0, fmt.Errorf("invalid local member header")
	}
	local := int(local64)
	if !bytes.HasPrefix(data[local:], []byte("PK\x03\x04")) ||
		binary.LittleEndian.Uint16(data[local+6:]) != flags ||
		binary.LittleEndian.Uint16(data[local+8:]) != method {
		return zipMember{}, 0, 0, fmt.Errorf("local member flags or method disagree with directory")
	}
	localNameLen := int(binary.LittleEndian.Uint16(data[local+26:]))
	localExtraLen := int(binary.LittleEndian.Uint16(data[local+28:]))
	headerEnd64 := int64(local) + 30 + int64(localNameLen) + int64(localExtraLen)
	if headerEnd64 > int64(cd) || localNameLen != nameLen || localNameLen < 0 ||
		!bytes.Equal(data[local+30:local+30+localNameLen], data[p+centralHeaderBytes:p+centralHeaderBytes+nameLen]) {
		return zipMember{}, 0, 0, fmt.Errorf("local member name or length disagrees with directory")
	}
	headerEnd := int(headerEnd64)
	centralExtra := data[p+centralHeaderBytes+nameLen : p+centralHeaderBytes+nameLen+extraLen]
	localExtra := data[local+30+localNameLen : headerEnd]
	// APPNOTE 7.2.3 places the strong-encryption header in the central extra
	// field. AE-x (4.6.1) records appear in either header. Either one means
	// the member bytes are not the plaintext.
	if hasExtra(centralExtra, strongEncryptionExtraID, aexEncryptionExtraID) ||
		hasExtra(localExtra, strongEncryptionExtraID, aexEncryptionExtraID) {
		return zipMember{}, 0, 0, fmt.Errorf("encrypted member")
	}
	if flags&encryptionFlags != 0 {
		return zipMember{}, 0, 0, fmt.Errorf("encrypted member")
	}
	if flags&patchedDataFlag != 0 {
		return zipMember{}, 0, 0, fmt.Errorf("patched data member has no reader")
	}
	if method != zipMethodStore && method != zipMethodDeflate {
		return zipMember{}, 0, 0, fmt.Errorf("unsupported ZIP compression method %d", method)
	}
	allowed := uint16(zipFlagDescriptor | zipFlagUTF8)
	if method == zipMethodDeflate {
		allowed |= zipFlagDeflateOpt
	}
	if flags&^allowed != 0 {
		return zipMember{}, 0, 0, fmt.Errorf("unsupported general purpose flag")
	}
	comp := uint64(comp32)
	uncomp := uint64(uncomp32)
	// Compressed size is a uint32. Reject a size that does not fit in an index
	// or that runs past the central directory.
	compLen := int(comp32)
	if headerEnd < 0 || compLen < 0 || headerEnd > cd || cd-headerEnd < compLen {
		return zipMember{}, 0, 0, fmt.Errorf("compressed member overlaps ZIP directory")
	}
	dataEnd := headerEnd + compLen
	end := dataEnd
	if flags&zipFlagDescriptor == 0 {
		if binary.LittleEndian.Uint32(data[local+14:]) != crc ||
			uint64(binary.LittleEndian.Uint32(data[local+18:])) != comp ||
			uint64(binary.LittleEndian.Uint32(data[local+22:])) != uncomp {
			return zipMember{}, 0, 0, fmt.Errorf("local member checksum or size disagrees with directory")
		}
	} else {
		// APPNOTE 4.4.7-4.4.9: bit 3 forces the local CRC and sizes to zero.
		// The descriptor carries the real values and must match the directory.
		if binary.LittleEndian.Uint32(data[local+14:]) != 0 ||
			binary.LittleEndian.Uint32(data[local+18:]) != 0 ||
			binary.LittleEndian.Uint32(data[local+22:]) != 0 {
			return zipMember{}, 0, 0, fmt.Errorf("local member checksum or size disagrees with directory")
		}
		// APPNOTE 4.3.9.3: readers look for the 0x08074b50 signature to find
		// a descriptor. A stored member's length is not in its local header,
		// so a streaming reader ends it at the first signature inside the
		// data (libarchive does when the CRC of the bytes before it matches)
		// and reads what follows as further members. The search runs three
		// bytes past the data, so a signature that starts in the data and
		// continues into an unsigned descriptor also counts.
		if method == zipMethodStore && bytes.Contains(data[headerEnd:min(dataEnd+3, len(data))], []byte(dataDescriptorSig)) {
			return zipMember{}, 0, 0, fmt.Errorf("stored member data contains a data descriptor signature")
		}
		body := 12
		if hasExtra(localExtra, zip64ExtraID) {
			body = 20 // APPNOTE 4.3.9.1-4.3.9.2: 8-byte sizes.
		}
		desc := data[dataEnd:]
		if len(desc) >= 4 && bytes.HasPrefix(desc, []byte(dataDescriptorSig)) {
			desc = desc[4:]
			end += 4
		}
		if len(desc) < body || end+body > len(data) {
			return zipMember{}, 0, 0, fmt.Errorf("local member checksum or size disagrees with directory")
		}
		end += body
		gotCRC := binary.LittleEndian.Uint32(desc)
		var gotComp, gotUncomp uint64
		if body == 20 {
			gotComp = binary.LittleEndian.Uint64(desc[4:])
			gotUncomp = binary.LittleEndian.Uint64(desc[12:])
		} else {
			gotComp = uint64(binary.LittleEndian.Uint32(desc[4:]))
			gotUncomp = uint64(binary.LittleEndian.Uint32(desc[8:]))
		}
		if gotCRC != crc || gotComp != comp || gotUncomp != uncomp {
			return zipMember{}, 0, 0, fmt.Errorf("local member checksum or size disagrees with directory")
		}
		if end > cd {
			return zipMember{}, 0, 0, fmt.Errorf("ZIP data outside listed members")
		}
	}
	name := string(data[p+centralHeaderBytes : p+centralHeaderBytes+nameLen])
	comment := string(data[p+centralHeaderBytes+nameLen+extraLen : p+centralHeaderBytes+nameLen+extraLen+commentLen])
	return zipMember{
		name: name, comment: comment, method: method, flags: flags, crc: crc,
		compressed: comp, uncompressed: uncomp, payload: data[headerEnd:dataEnd],
		// Extra fields are member metadata. Info-ZIP, Python zipfile and bsdtar
		// may take the member name from the Unicode Path extra (0x7075) instead
		// of the central name, so those bytes are part of what was read.
		localExtra: localExtra, centralExtra: centralExtra,
	}, local, end, nil
}

// hasExtra walks APPNOTE 4.5.1 extra-field records (2-byte header ID, 2-byte
// data size) for any of the given header IDs. A matching ID is reported even
// when its data is truncated: a short encryption record is still encryption.
func hasExtra(extra []byte, ids ...uint16) bool {
	for len(extra) >= 4 {
		id, size := binary.LittleEndian.Uint16(extra), int(binary.LittleEndian.Uint16(extra[2:]))
		for _, want := range ids {
			if id == want {
				return true
			}
		}
		if 4+size > len(extra) {
			return false
		}
		extra = extra[4+size:]
	}
	return false
}
