// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const groupInvalid = "LEGACY_INVALID"

func v3GroupRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	archive, err := zip.OpenReader("../verifiers/python/tests/fixtures/receipt-groups.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = archive.Close() }()
	ordinary := v3OrdinaryGroupNeighbor(t)
	valid, validKeys := v3ReadGroupFiles(t, archive, "group-valid")
	successor, successorKeys := v3ReadGroupFiles(t, archive, "group-successor")

	complete := v3GroupRecipe(t, "group-with-ordinary", valid, validKeys, ordinary, false)
	restart := v3GroupRecipe(t, "group-shards-excluded-from-restart", successor, successorKeys, ordinary, true)

	claimed := complete
	claimed.name, claimed.verdict, claimed.code = "group-with-malformed-v3-claim", "INVALID", "FILE_LAYOUT"
	// This name also parses as the first shard of a legacy recorder session.
	claimed.files = slices.Clone(complete.files)
	for _, name := range []string{
		"evidence-proxy.run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0.receipt-v3.jsonl",
		"evidence-proxy.run.1806d08396effa4a8f31e45aa8165c84-0.receipt-v3.jsonl",
	} {
		claimed.files = append(claimed.files, v3File{name, []byte("malformed\n")})
	}

	unclaimed := complete
	unclaimed.name, unclaimed.verdict, unclaimed.code = "group-with-unclaimed-v3-content", "INVALID", "V3_CONTENT_UNCLAIMED"
	unclaimed.files = slices.Clone(complete.files)
	const unclaimedContent = `{"payloadType":"application/vnd.pipelock.receipt.v3+json"}` + "\n"
	for _, name := range []string{
		"evidence-proxy.run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-content.jsonl",
		"receipt-group-unclaimed.json",
	} {
		unclaimed.files = append(unclaimed.files, v3File{name, []byte(unclaimedContent)})
	}

	tampered := complete
	tampered.name, tampered.verdict, tampered.code = "group-with-tampered-shard", "INVALID", groupInvalid
	tampered.files = slices.Clone(complete.files)
	for i, file := range tampered.files {
		if strings.HasPrefix(file.name, "evidence-proxy.run.") && file.name != ordinary.files[0].name {
			const marker = `"hash":"`
			iHash := bytes.Index(file.bytes, []byte(marker))
			if iHash == -1 {
				t.Fatal("group fixture has no recorder hash to alter")
			}
			data := bytes.Clone(file.bytes)
			iHash += len(marker)
			if data[iHash] == '0' {
				data[iHash] = '1'
			} else {
				data[iHash] = '0'
			}
			tampered.files[i].bytes = data
			break
		}
	}

	files := slices.Clone(ordinary.files)
	for _, file := range valid {
		if strings.HasSuffix(file.name, "-close.json") {
			files = append(files, file)
			break
		}
	}
	orphan := v3GroupCutover(t, "group-orphan-close", files,
		[]v3.InventoryChain{ordinary.row}, append(slices.Clone(validKeys), ordinary.key))
	orphan.verdict, orphan.code = "INVALID", groupInvalid
	orphan.extraInvalid = []string{"LEGACY_CHAIN_UNLISTED"}
	return []v3Recipe{complete, claimed, unclaimed, tampered, orphan, restart}
}

func v3ReadGroupFiles(t *testing.T, archive *zip.ReadCloser, scenario string) ([]v3File, []string) {
	t.Helper()
	var files []v3File
	var keys []string
	for _, entry := range archive.File {
		name, found := strings.CutPrefix(entry.Name, scenario+"/")
		if !found || entry.FileInfo().IsDir() {
			continue
		}
		handle, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(handle)
		closeErr := handle.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("read %s: %v, close: %v", entry.Name, err, closeErr)
		}
		if name == "trust.json" {
			var trust struct {
				Keys []string `json:"trusted_keys"`
			}
			if err := json.Unmarshal(data, &trust); err != nil {
				t.Fatal(err)
			}
			keys = trust.Keys
		} else {
			files = append(files, v3File{name, data})
		}
	}
	if len(files) == 0 || len(keys) == 0 {
		t.Fatalf("group scenario %s is missing files or trust pins", scenario)
	}
	return files, keys
}

type v3GroupNeighbor struct {
	files []v3File
	row   v3.InventoryChain
	key   string
}

func v3OrdinaryGroupNeighbor(t *testing.T) v3GroupNeighbor {
	t.Helper()
	const (
		session   = "proxy.run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		run       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		openNonce = "ordinary-open"
		transport = "receipt_session"
	)
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := v3Key("ordinary-group-neighbor")
	pub := v3Public(key)
	keyHex := hex.EncodeToString(pub)
	policy := v3.Digest(nil)
	open := actionreceipt.SessionOpen{
		RunNonce: run, OpenNonce: openNonce, RecorderSession: session,
		PolicyHash: policy, SignerKeyEpoch: keyHex,
	}
	open.GenesisHash = actionreceipt.ComputeSessionOpenGenesis(open)
	first := actionreceipt.ActionRecord{
		Version: actionreceipt.ActionRecordVersion, ActionID: "ordinary-open",
		ActionType: actionreceipt.ActionUnclassified, Timestamp: ts,
		Transport: transport, Target: "receipt-session:open", PolicyHash: policy,
		Verdict: "allow", RunNonce: run, ChainPrevHash: open.GenesisHash,
		SessionControl: &actionreceipt.SessionControl{Kind: actionreceipt.SessionControlOpen, Open: &open},
	}
	signedOpen, err := actionreceipt.Sign(first, key)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := actionreceipt.ReceiptHash(signedOpen)
	if err != nil {
		t.Fatal(err)
	}
	last := first
	last.ActionID, last.Target, last.Timestamp = "ordinary-close", "receipt-session:close", ts.Add(time.Second)
	last.ChainPrevHash, last.ChainSeq = prior, 1
	last.SessionControl = &actionreceipt.SessionControl{Kind: actionreceipt.SessionControlClose, Close: &actionreceipt.SessionClose{
		RunNonce: run, OpenNonce: openNonce, FinalSeq: 1, RootHash: prior, ReceiptCount: 2, CloseReason: "graceful_shutdown",
	}}
	signedClose, err := actionreceipt.Sign(last, key)
	if err != nil {
		t.Fatal(err)
	}
	var ordinary bytes.Buffer
	prev := recorder.GenesisHash
	for seq, signed := range []actionreceipt.Receipt{signedOpen, signedClose} {
		detail, err := actionreceipt.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		entry := recorder.Entry{
			Version: recorder.CurrentWriteEntryVersion, Sequence: uint64(seq), SessionID: session,
			Timestamp: signed.ActionRecord.Timestamp, Type: "action_receipt", Transport: transport,
			Summary: "ordinary action receipt", Detail: json.RawMessage(detail), RawDetail: detail, PrevHash: prev,
		}
		entry.Hash = recorder.ComputeHash(entry)
		if err := json.NewEncoder(&ordinary).Encode(entry); err != nil {
			t.Fatal(err)
		}
		prev = entry.Hash
	}
	head, err := last.Hash()
	if err != nil {
		t.Fatal(err)
	}
	files := []v3File{{"evidence-" + session + "-0.jsonl", ordinary.Bytes()}}
	files = append(files, v3NeighborAEL(t, run, key, ts)...)
	return v3GroupNeighbor{
		files: files, key: keyHex,
		row: v3.InventoryChain{Format: "action_v1", Chain: run, Record: "sha256:" + head, Seq: 1},
	}
}

// v3NeighborAEL records the matching closed native AEL run for the ordinary
// session. The frozen group inventory checks every recorder session's claim.
func v3NeighborAEL(t *testing.T, run string, key ed25519.PrivateKey, ts time.Time) []v3File {
	t.Helper()
	const recorderID = "pipelock"
	const recorderPath = "recorders/pipelock.jsonl"
	pub := v3Public(key)
	keyID := strings.TrimPrefix(v3.Digest(pub), "sha256:")
	manifest := v3Canonical(t, v3Common{
		"ael_format": 1, "runs": []string{run},
		"recorders": []v3Common{{"id": recorderID, "run": run, "key": keyID, "file": recorderPath}},
		"coverage":  "mediated-only", "custody": "same-process",
	})
	var records bytes.Buffer
	prev := strings.Repeat("0", 64)
	for seq, kind := range []string{"open", "close"} {
		fields := v3Common{
			"v": 1, "seq": seq, "key": keyID, "prev": prev, "recorder": recorderID, "run": run,
			"ts": ts.Add(time.Duration(seq) * time.Second).Format(time.RFC3339Nano), "type": kind,
		}
		if seq == 0 {
			fields["hmax"], fields["htol"] = 0, 0
		} else {
			fields["count"], fields["head"] = 2, prev
		}
		payload := v3Canonical(t, fields)
		sig := ed25519.Sign(key, payload)
		records.WriteString(base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig) + "\n")
		prev = strings.TrimPrefix(v3.Digest(payload), "sha256:")
	}
	root := "ael/" + run + "/"
	return []v3File{
		{root + "manifest.json", manifest},
		{root + "keys/" + keyID + ".pub", []byte(base64.StdEncoding.EncodeToString(pub))},
		{root + recorderPath, records.Bytes()},
	}
}

func v3GroupRecipe(t *testing.T, name string, groupFiles []v3File, groupKeys []string, ordinary v3GroupNeighbor, checkRestart bool) v3Recipe {
	t.Helper()
	dir := t.TempDir()
	files := append(slices.Clone(groupFiles), ordinary.files...)
	for _, file := range files {
		target := filepath.Join(dir, file.name)
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, file.bytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	keys := append(slices.Clone(groupKeys), ordinary.key)
	if checkRestart {
		without, withoutErr := actionreceipt.VerifyBase(dir, "proxy", actionreceipt.BaseVerifyOptions{TrustedKeys: keys})
		with, withErr := actionreceipt.VerifyBase(dir, "proxy", actionreceipt.BaseVerifyOptions{TrustedKeys: keys, ExcludeReceiptGroupSessions: true})
		if withoutErr != nil || without.Healthy() || withErr != nil || !with.Healthy() {
			t.Fatalf("restart fixture must depend on excluding group shards: without=%+v (%v), with=%+v (%v)", without, withoutErr, with, withErr)
		}
	}
	rows := []v3.InventoryChain{ordinary.row}
	_, err := actionreceipt.VerifyReceiptGroups(dir, keys, func(result actionreceipt.ReceiptGroupResult) error {
		if result.Verdict != actionreceipt.GroupValid {
			t.Fatalf("invalid frozen group fixture: %+v", result)
		}
		rows = append(rows, v3.InventoryChain{
			Format: "receipt_group", Chain: result.GroupID,
			Record: "sha256:" + result.CloseManifestSHA, Seq: int64(result.ShardCount),
		})
		return nil
	})
	if err != nil || len(rows) == 1 {
		t.Fatalf("verify frozen group fixture: %v", err)
	}
	slices.SortFunc(rows[1:], func(a, b v3.InventoryChain) int { return strings.Compare(a.Chain, b.Chain) })
	return v3GroupCutover(t, name, files, rows, keys)
}

func v3GroupCutover(t *testing.T, name string, files []v3File, rows []v3.InventoryChain, keys []string) v3Recipe {
	t.Helper()
	inventory := v3Canonical(t, v3.Inventory{V: 1, Chains: rows})
	digest := v3.Digest(inventory)
	s := v3New(t)
	s.records = nil
	open := v3DefaultOpen(s.key, s.lineage)
	open["legacy_cutover"] = v3Common{"chains": len(rows), "inventory": digest}
	s.add(t, "stream_open", open, nil)
	files = append(files, s.finish(t), v3File{v3.InventoryFilename(digest), inventory})
	return v3Recipe{
		group: 9, name: name, verdict: "VALID", files: files,
		request: v3Request{Directory: true, Keys: append(keys, hex.EncodeToString(v3Public(s.key)))},
	}
}
