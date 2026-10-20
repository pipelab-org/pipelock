// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// decodeProperty accepts one busctl --json=short property with its exact
// D-Bus signature. Errors must not include payloads or decoder errors: both
// can contain environment values.
func decodeProperty(body []byte, signature string, dst any) error {
	if len(body) == 0 || len(body) > maxObservationBytes || !utf8.Valid(body) || jsonscan.RejectDuplicateKeys(body) != nil || jsonscan.RejectCaseFoldedAliases(body, "type", "data") != nil {
		return errors.New("invalid typed service property")
	}
	var envelope struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&envelope) != nil || envelope.Type != signature || len(envelope.Data) == 0 {
		return errors.New("unexpected typed service property")
	}
	if dec.Decode(new(any)) != io.EOF || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
		return errors.New("invalid typed service property data")
	}
	if json.Unmarshal(envelope.Data, dst) != nil {
		return errors.New("invalid typed service property value")
	}
	return nil
}

type environmentFile struct {
	Path     string
	Optional bool
}

func decodeEnvironmentFiles(body []byte) ([]environmentFile, error) {
	var rows [][]json.RawMessage
	if err := decodeProperty(body, "a(sb)", &rows); err != nil {
		return nil, err
	}
	files := make([]environmentFile, 0, len(rows))
	for _, row := range rows {
		if len(row) != 2 || bytes.Equal(bytes.TrimSpace(row[0]), []byte("null")) || !bytes.Equal(bytes.TrimSpace(row[1]), []byte("true")) && !bytes.Equal(bytes.TrimSpace(row[1]), []byte("false")) {
			return nil, errors.New("invalid environment-file tuple")
		}
		var file environmentFile
		if json.Unmarshal(row[0], &file.Path) != nil || json.Unmarshal(row[1], &file.Optional) != nil {
			return nil, errors.New("invalid environment-file tuple value")
		}
		files = append(files, file)
	}
	return files, nil
}

func decodeStringList(body []byte) ([]string, error) {
	// Decoding through RawMessage rejects null elements, which encoding/json
	// would otherwise silently turn into empty strings.
	var raw []json.RawMessage
	if err := decodeProperty(body, "as", &raw); err != nil {
		return nil, err
	}
	out := make([]string, len(raw))
	for i, value := range raw {
		if len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &out[i]) != nil {
			return nil, errors.New("invalid service string list")
		}
	}
	return out, nil
}
