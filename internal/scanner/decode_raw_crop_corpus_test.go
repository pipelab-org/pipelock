// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
)

// rawCropCase is one named decode input. The corpus is deterministic so a
// capture taken before a change and a comparison taken after it see the same
// bytes.
type rawCropCase struct {
	name string
	text string
}

const (
	rawCropHexDigits    = "0123456789abcdefABCDEF"
	rawCropBase32Std    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	rawCropBase32Hex    = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	rawCropBase64Std    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	rawCropBase64URL    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	rawCropFuzzSeed     = 0x70697065
	rawCropFuzzPerShape = 40
)

// rawCropInvalid holds the single bytes the fuzz inserts: bytes outside every
// codec alphabet, both padding sentinels, line breaks, and a multi-byte rune.
var rawCropInvalid = []string{"!", " ", "\x00", "\xff", "=", "\r", "\n", "{", "\"", "é", ".", "%", "&"}

// rawCropLengths straddle the quantum, scratch, carrier-bound and size edges.
var rawCropLengths = []int{0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 40, 64, 100, 255, 256, 257, 1000, 4095, 4096, 4097, 9000}

func rawCropCorpus() []rawCropCase {
	var cases []rawCropCase
	add := func(name, text string) { cases = append(cases, rawCropCase{name: name, text: text}) }

	secret := "ordinary-credential-shaped-value-0123456789"
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	b64Raw := base64.RawStdEncoding.EncodeToString([]byte(secret))
	b64URL := base64.URLEncoding.EncodeToString([]byte("\xfb\xff\xfe" + secret))
	b32 := base32.StdEncoding.EncodeToString([]byte(secret))
	b32Raw := strings.TrimRight(b32, "=")
	b32Hex := base32.HexEncoding.EncodeToString([]byte(secret))
	hx := hex.EncodeToString([]byte(secret))

	named := map[string]string{
		"empty": "", "bang": "!", "brace": "{", "json": `{"a":"` + b64 + `"}`,
		"b64": b64, "b64raw": b64Raw, "b64url": b64URL, "b32": b32, "b32raw": b32Raw, "b32hex": b32Hex, "hex": hx,
		"b64lower": strings.ToLower(b64), "b32lower": strings.ToLower(b32), "b32hexlower": strings.ToLower(b32Hex),
		"hexodd": hx + "a", "hexbad": hx[:10] + "g" + hx[11:], "hexinvalidlast": hx + "z",
		"b64wrapped": b64[:20] + "\r\n" + b64[20:], "b64newlineonly": "\r\n\r\n\r\n",
		"b32wrapped": b32[:16] + "\n" + b32[16:], "hexwrapped": hx[:20] + "\r\n" + hx[20:],
		"b64padmid": b64[:8] + "==" + b64[8:], "b32padmid": b32[:16] + "=" + b32[16:],
		"b32paddedtrail": b32 + "!", "b32rawsentinel": b32Raw[:11] + "\xff" + b32Raw[11:],
		"mixedlate":    strings.Repeat("A", 40) + "-_" + strings.Repeat("B", 40) + "+/" + strings.Repeat("C", 20),
		"mixedprefix":  "-_" + strings.Repeat("A", 40) + "+/" + strings.Repeat("B", 40),
		"mixedinvalid": strings.Repeat("A", 40) + "-" + "!" + strings.Repeat("B", 40) + "+" + strings.Repeat("C", 20),
		"mixedshort":   "ab-_+/cd",
		"shortinvalid": "!" + strings.Repeat("A", 1<<16), "shortinvalidsp": "A!" + strings.Repeat("0123456789abcdef", 1<<12),
		"prefixthenjunk": b64 + "!" + strings.Repeat("A", 4096), "hexthenjunk": hx + "!" + hx,
		"b32thenjunk": b32Raw + "!" + b32Raw, "b32thenpad": b32Raw + "=" + strings.Repeat("A", 20),
		"segments":   "token: " + b64 + ", other " + hx + "; " + b32 + " end",
		"separators": strings.Join(strings.Split(b64, ""), " "),
		"hexsep":     strings.Join([]string{hx[:8], hx[8:16], hx[16:]}, ":"),
		"longvalid":  base64.StdEncoding.EncodeToString([]byte(strings.Repeat(secret, 600))),
		"longhex":    hex.EncodeToString([]byte(strings.Repeat(secret, 400))),
		"longb32":    base32.StdEncoding.EncodeToString([]byte(strings.Repeat(secret, 400))),
		"longlatebad": base64.StdEncoding.EncodeToString([]byte(strings.Repeat(secret, 300))) + "!" +
			base64.StdEncoding.EncodeToString([]byte(secret)),
		"nestedhex": hex.EncodeToString([]byte(hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(secret)))))),
		"nestedb64": base64.StdEncoding.EncodeToString([]byte(base32.StdEncoding.EncodeToString([]byte(hx)))),
		"lateseg":   strings.Repeat("{\"k\":\"plain\"},", 3000) + "Authorization: " + b64,
		"unicode":   "café " + b64 + " ☃",
	}
	// Map order is random; sort so captures line up between runs.
	names := make([]string, 0, len(named))
	for name := range named {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		add(name, named[name])
	}

	rng := rand.New(rand.NewPCG(rawCropFuzzSeed, rawCropFuzzSeed^0xdecade)) // #nosec G404 -- reproducible decode corpus.
	shapes := []struct {
		name  string
		alpha string
	}{
		{"hex", rawCropHexDigits},
		{"b32", rawCropBase32Std},
		{"b32h", rawCropBase32Hex},
		{"b64", rawCropBase64Std},
		{"b64u", rawCropBase64URL},
		{"b64mix", rawCropBase64Std + "-_"},
		{"any", rawCropBase64Std + "-_=\r\n!{ "},
	}
	for _, shape := range shapes {
		for i := 0; i < rawCropFuzzPerShape; i++ {
			length := rawCropLengths[rng.IntN(len(rawCropLengths))]
			if length > 4097 && i%4 != 0 {
				length = 64 + rng.IntN(200)
			}
			var b strings.Builder
			for j := 0; j < length; j++ {
				b.WriteByte(shape.alpha[rng.IntN(len(shape.alpha))])
			}
			text := b.String()
			if length > 0 {
				// Up to two injected bytes, at least one near an edge sometimes.
				for k := rng.IntN(3); k > 0; k-- {
					at := rng.IntN(length)
					if rng.IntN(3) == 0 {
						at = min(length-1, (rng.IntN(5)+1)*8-rng.IntN(3))
					}
					text = text[:at] + rawCropInvalid[rng.IntN(len(rawCropInvalid))] + text[at+1:]
				}
				if rng.IntN(3) == 0 {
					text += strings.Repeat("=", rng.IntN(4))
				}
				if rng.IntN(4) == 0 {
					text = strings.ToLower(text)
				}
			}
			add(fmt.Sprintf("fuzz-%s-%d", shape.name, i), text)
		}
	}
	return cases
}

// rawCropMinPrefixes are the prefix lengths exercised: ordinary decoding,
// the smallest known value, and the known-value floor with its neighbours.
var rawCropMinPrefixes = []int{0, 1, minKnownSecretSubstringLen - 1, minKnownSecretSubstringLen, minKnownSecretSubstringLen + 1}
