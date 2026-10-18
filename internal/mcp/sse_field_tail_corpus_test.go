// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"
)

// benignStreamTranscripts are ordinary assistant replies of the kind token
// streams carry. Several deliberately contain phrasing that is close to, but
// is not, an instruction override, plus code, numbers, ids and URLs.
var benignStreamTranscripts = []string{
	"The quarterly report is ready for your review and the numbers look fine.",
	"Here is a short summary of the meeting notes from today.",
	"You are now ready to deploy the service to the staging cluster.",
	"From now on the build uses Go 1.26, so update your local toolchain.",
	"To reset your password, open Settings, choose Security, and follow the prompts.",
	"The function returns an error when the input slice is empty.",
	"I would suggest splitting the migration into two smaller pull requests.",
	"Sure! Here is the corrected SQL: SELECT id, name FROM users WHERE active = true ORDER BY name;",
	"The forecast for tomorrow is sunny with a high of 24 degrees.",
	"Your order #48213 has shipped and should arrive on Thursday.",
	"Step 1: install the dependencies. Step 2: run the tests. Step 3: open a pull request.",
	"The previous version ignored trailing whitespace; the new parser keeps it.",
	"Please disregard the draft I sent earlier; the final version is attached.",
	"As a reminder, the system maintenance window starts at 02:00 UTC on Sunday.",
	"The model achieved 91.4 percent accuracy on the held-out test set.",
	"Use `git rebase -i HEAD~3` to squash the last three commits before merging.",
	"The API returns HTTP 429 when you exceed 100 requests per minute.",
	"An unrestricted grant lets the research team use the funds for any project.",
	"The new filter is unfiltered for admins and filtered for everyone else.",
	"Translate the following into French: Good morning, how are you today?",
	"The recipe needs two cups of flour, one egg, and a pinch of salt.",
	"Remember to rotate the access keys every ninety days per the policy.",
	"The token count for this request was 1532 prompt and 288 completion tokens.",
	"I cannot find a file named config.yaml in the repository root.",
	"Here are three options: a cache in front of the database, a read replica, or both.",
	"Act as the reviewer for this change and leave comments on anything unclear.",
	"The assistant role in the transcript is shown on the right side of the screen.",
	"The phone settings page lists the build number under About.",
	"The instructions in the README explain how to run the integration suite locally.",
	"The JSON field named content holds the text of each streamed delta.",
	"Ignore the warning about the deprecated flag; it is removed in the next release.",
	"The new hire starts on Monday and will join the platform team.",
	"Latency improved from 180 ms to 95 ms after enabling connection pooling.",
	"Visit https://docs.vendor.example/guides/start for the getting started guide.",
	"The hexadecimal value 0x1f4 equals 500 in decimal.",
	"The UUID for the test tenant is 123e4567-e89b-12d3-a456-426614174000.",
	"Pretend for a moment that the outage happened on a Friday: who would be on call?",
	"Override the default timeout by setting REQUEST_TIMEOUT to 30 seconds.",
	"New instructions for the kitchen: clean the counters before closing.",
	"The base64 string aGVsbG8gd29ybGQ= decodes to hello world.",
	"Below is the stack trace; the panic comes from a nil map write in handler.go line 88.",
	"I have updated the ticket and assigned it to the on-call engineer.",
}

func benignToolCallChunk(t *testing.T, s string) string {
	return `data: {"id":"chatcmpl-2","object":"chat.completion.chunk","created":2,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"arguments":` +
		jsonString(t, s) + `}}]},"finish_reason":null}]}` + "\n\n"
}

// logprobsChunk is a chat chunk with logprobs and top alternatives, whose
// numeric leaves outnumber the old 128-leaf partition limit at top=20.
func logprobsChunk(t *testing.T, token string, top int) string {
	alts := make([]string, 0, top)
	for i := range top {
		alts = append(alts, `{"token":"alt`+strconv.Itoa(i)+`","logprob":-1.5,"bytes":[97,108,116]}`)
	}
	return `data: {"id":"chatcmpl-3","object":"chat.completion.chunk","created":4,"model":"m","choices":[{"index":0,"delta":{"content":` + jsonString(t, token) +
		`},"logprobs":{"content":[{"token":` + jsonString(t, token) + `,"logprob":-0.1,"bytes":[116,101,115,116],"top_logprobs":[` + strings.Join(alts, ",") + `]}]},"finish_reason":null}]}` + "\n\n"
}

// characterDeltas splits s into fixed-size chunks, the way some providers
// stream partial tokens.
func characterDeltas(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

func TestStreamFieldTailsBenignCorpusHasNoFindings(t *testing.T) {
	t.Parallel()
	sc, cfg := defaultStreamScanner(t)
	sse := cfg.ResponseScanning.SSEStreaming
	a2a := cfg.A2AScanning
	a2a.Enabled = true

	type shape struct {
		name  string
		event sseShape
		a2a   bool
	}
	shapes := []shape{
		{name: "chat chunk", event: chatCompletionChunk},
		{name: "content block", event: contentBlockDelta},
		{name: "artifact update", event: artifactUpdate},
		{name: "minimal text", event: minimalTextEvent},
		{name: "a2a artifact update", event: artifactUpdate, a2a: true},
		{name: "a2a minimal text", event: minimalTextEvent, a2a: true},
	}
	toolArgs := `{"location":"Boston, MA","unit":"celsius","days":3,"include_hourly":false}`
	// Precondition: each transcript is clean as one whole event, so any
	// finding below comes from joining deltas.
	for _, text := range benignStreamTranscripts {
		var out bytes.Buffer
		body := sseStream(t, chatCompletionChunk, text)
		if err := ScanGenericSSEStreamWithOptions(context.Background(), strings.NewReader(body), &out, nil, sc, &sse, GenericSSEScanOptions{}); err != nil {
			t.Fatalf("corpus transcript %q is not clean as a single event: %v", text, err)
		}
	}
	streams := 0
	for _, sh := range shapes {
		for i, text := range benignStreamTranscripts {
			for _, split := range []string{"words", "chars"} {
				parts := wordDeltas(text)
				if split == "chars" {
					parts = characterDeltas(text, 3+i%5)
				}
				var body string
				if sh.a2a {
					body = a2aStream(t, sh.event, parts...)
				} else {
					body = sseStream(t, sh.event, parts...)
				}
				name := sh.name + "/" + split + "/" + strconv.Itoa(i)
				var out bytes.Buffer
				var err error
				if sh.a2a {
					err = ScanA2AStream(context.Background(), strings.NewReader(body), &out, nil, sc, &a2a)
				} else {
					err = ScanGenericSSEStreamWithOptions(context.Background(), strings.NewReader(body), &out, nil, sc, &sse, GenericSSEScanOptions{})
				}
				if err != nil {
					t.Errorf("%s: benign stream %q blocked: %v", name, text, err)
				}
				streams++
			}
		}
	}
	var out bytes.Buffer
	body := sseStream(t, benignToolCallChunk, characterDeltas(toolArgs, 4)...)
	if err := ScanGenericSSEStreamWithOptions(context.Background(), strings.NewReader(body), &out, nil, sc, &sse, GenericSSEScanOptions{}); err != nil {
		t.Errorf("benign tool call arguments blocked: %v", err)
	}
	streams++

	// Producer shapes that exercise interleaving, envelope repeats, wide
	// events and non-string leaves.
	for i, text := range benignStreamTranscripts[:12] {
		var b strings.Builder
		// Two parallel tool calls whose argument deltas interleave.
		for j, part := range characterDeltas(toolArgs, 5) {
			b.WriteString(toolCallDelta(t, 0, part))
			if j < 6 {
				b.WriteString(toolCallDelta(t, 1, characterDeltas(`{"query":"status page"}`, 4)[j%6]))
			}
		}
		// A wide metadata event, then the reply with logprobs.
		b.WriteString(wideEvent("metadata", 300))
		for _, w := range wordDeltas(text) {
			b.WriteString(logprobsChunk(t, w, []int{0, 5, 20}[i%3]))
		}
		b.WriteString("data: [DONE]\n\n")
		var out bytes.Buffer
		if err := ScanGenericSSEStreamWithOptions(context.Background(), strings.NewReader(b.String()), &out, nil, sc, &sse, GenericSSEScanOptions{}); err != nil {
			t.Errorf("producer shapes/%d: benign stream blocked: %v", i, err)
		}
		streams++
	}
	// An envelope id that repeats on every event must not be joined with
	// itself: two copies of it would read as a credential.
	var repeated strings.Builder
	for _, w := range wordDeltas(benignStreamTranscripts[0]) {
		repeated.WriteString(`data: {"id":"AKIAQ7ZS3XW2","choices":[{"index":0,"delta":{"content":` + jsonString(t, w) + `}}]}` + "\n\n")
	}
	repeated.WriteString("data: [DONE]\n\n")
	out.Reset()
	if err := ScanGenericSSEStreamWithOptions(context.Background(), strings.NewReader(repeated.String()), &out, nil, sc, &sse, GenericSSEScanOptions{}); err != nil {
		t.Errorf("repeated envelope id blocked: %v", err)
	}
	streams++
	if streams < 48 {
		t.Fatalf("corpus too small: %d streams", streams)
	}
}
