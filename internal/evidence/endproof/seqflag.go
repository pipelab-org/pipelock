// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package endproof

import (
	"errors"
	"strconv"
)

// ParseSeq parses an operator-supplied final sequence as ASCII decimal
// digits. Signs, base prefixes, separators, and spaces are refused so every
// verifier implementation reads the same number from the same text.
func ParseSeq(text string) (uint64, error) {
	if text == "" {
		return 0, errors.New("expected sequence must be decimal digits")
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, errors.New("expected sequence must be decimal digits")
		}
	}
	seq, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, errors.New("expected sequence exceeds the unsigned 64-bit range")
	}
	return seq, nil
}

// SeqFlag is a pflag value that parses with ParseSeq. The standard uint64
// flag accepts octal and hexadecimal prefixes, so "010" would pin seq 8.
type SeqFlag struct{ Seq *uint64 }

// String implements pflag.Value.
func (f SeqFlag) String() string {
	if f.Seq == nil {
		return "0"
	}
	return strconv.FormatUint(*f.Seq, 10)
}

// Set implements pflag.Value.
func (f SeqFlag) Set(text string) error {
	seq, err := ParseSeq(text)
	if err != nil {
		return err
	}
	*f.Seq = seq
	return nil
}

// Type implements pflag.Value.
func (SeqFlag) Type() string { return "uint64" }
