// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
	"strings"
	"testing"
)

func TestTypedEnvironmentFiles(t *testing.T) {
	files, err := decodeEnvironmentFiles([]byte(`{"type":"a(sb)","data":[["/run/service env",false],["/optional",true]]}`))
	if err != nil || len(files) != 2 || files[0].Path != "/run/service env" || files[0].Optional || !files[1].Optional {
		t.Fatal("typed environment files were not decoded")
	}
	for _, body := range []string{
		`{"type":"a(sb)","data":[["/x",null]]}`, `{"type":"a(sb)","data":[[null,false]]}`,
		`{"type":"a(sb)","data":[["/x",false,0]]}`, `{"type":"a(sb)","data":[["/x","false"]]}`,
		`{"type":"a(sb)","data":[[0,false]]}`, `{"type":"as","data":[]}`,
	} {
		if _, err := decodeEnvironmentFiles([]byte(body)); err == nil {
			t.Fatal("invalid typed environment files accepted")
		}
	}
}

func TestTypedPropertyRejectsAmbiguity(t *testing.T) {
	for _, body := range []string{
		``, `null`, `{}`, `{"type":"as","type":"as","data":[]}`, `{"type":"as","Type":"as","data":[]}`,
		`{"type":"as","data":[],"extra":0}`, `{"type":"as","data":[]} {}`, `{"type":"s","data":[]}`,
		`{"type":"as","data":null}`, `{"type":"as","data":[null]}`, `{"type":"as","data":[1]}`,
		`{"type":"as","data":["secret-sentinel",]}`, strings.Repeat(" ", maxObservationBytes+1),
		"{\"type\":\"as\",\"data\":[\"\xff\"]}",
	} {
		_, err := decodeStringList([]byte(body))
		if err == nil {
			t.Fatal("invalid typed property accepted")
		}
		if strings.Contains(err.Error(), "secret-sentinel") {
			t.Fatal("decoder error exposed a value")
		}
	}
	values, err := decodeStringList([]byte(`{"type":"as","data":["A=one two","B=a=b","C=line\nbreak"]}`))
	if err != nil || len(values) != 3 || values[2] != "C=line\nbreak" {
		t.Fatal("typed strings lost framing")
	}
}
