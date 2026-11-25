// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! Receipt v3 verification as specified in `docs/specs/receipt-v3.md`.

mod decision;
mod history;
mod legacy;
mod result;
mod store;
mod wire;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::util::{open_verifier_file, sha256_hex, Result, VerifierError};
use history::Stream;
use result::Document;
pub use result::VerificationResult;
use store::Store;
use wire::{
    check_signature, embedded_key, parse_line, read_line, validated_key, Record, FILE_SUFFIX,
    PROFILE_PREFIX,
};

const MAX_INTEGER: u64 = (1 << 53) - 1;
const OPEN: &str = "stream_open";
const CLOSE: &str = "stream_close";

/// Caller-supplied trust and evidence requirements.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Options {
    pub keys: Vec<String>,
    pub expect_heads: Vec<Head>,
    pub expect_sequences: Vec<Sequence>,
    pub expect_lineage: String,
    pub accept_discontinuities: Vec<String>,
    pub allow_partial_histories: Vec<String>,
    pub allow_prefix: bool,
    pub allow_unpinned: bool,
    pub directory: bool,
    /// Treat one explicitly selected file as v3 regardless of its name.
    pub explicit_v3: bool,
}

/// An independent expected endpoint.
#[derive(Debug, Deserialize)]
pub struct Head {
    pub stream: String,
    pub position: Position,
}

/// An independent expected endpoint sequence.
#[derive(Debug, Deserialize)]
pub struct Sequence {
    pub stream: String,
    pub seq: u64,
}

/// A position identifies the signed record and its sequence.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Position {
    pub record: String,
    pub seq: u64,
}

impl Options {
    fn validate(&self, paths: &[PathBuf]) -> Result<()> {
        if self.explicit_v3 && (self.directory || paths.len() != 1) {
            return Err(input_error("explicit v3 format requires exactly one file"));
        }
        if self.directory && paths.len() != 1 {
            return Err(input_error(
                "directory scope requires exactly one directory",
            ));
        }
        if !self.expect_lineage.is_empty() && !lower_hex(&self.expect_lineage, 32) {
            return Err(input_error(
                "expected lineage must be 32 lowercase hexadecimal characters",
            ));
        }
        if self
            .allow_partial_histories
            .iter()
            .any(|id| !lower_hex(id, 32))
        {
            return Err(input_error(
                "partial history must name a 32-character stream ID",
            ));
        }
        if self.accept_discontinuities.iter().any(|id| !is_digest(id)) {
            return Err(input_error("accepted discontinuity must be a record ID"));
        }
        for head in &self.expect_heads {
            if !lower_hex(&head.stream, 32)
                || head.position.seq > MAX_INTEGER
                || !is_digest(&head.position.record)
            {
                return Err(input_error(
                    "expected head must be stream:seq:sha256:digest",
                ));
            }
        }
        for sequence in &self.expect_sequences {
            if !lower_hex(&sequence.stream, 32) || sequence.seq > MAX_INTEGER {
                return Err(input_error("expected sequence must be stream:seq"));
            }
        }
        Ok(())
    }
}

fn parse_sequence(text: &str) -> Option<Sequence> {
    let (stream, number) = text.split_once(':')?;
    let seq: u64 = number.parse().ok()?;
    (lower_hex(stream, 32) && seq <= MAX_INTEGER && number == seq.to_string()).then(|| Sequence {
        stream: stream.into(),
        seq,
    })
}

fn parse_head(text: &str) -> Option<Head> {
    let (sequence, digest) = text.split_once(":sha256:")?;
    let sequence = parse_sequence(sequence)?;
    let record = format!("sha256:{digest}");
    is_digest(&record).then_some(Head {
        stream: sequence.stream,
        position: Position {
            record,
            seq: sequence.seq,
        },
    })
}

fn registry() -> &'static Value {
    // Runtime sections of sdk/receipt-v3/registry.json, vendored for cargo
    // install. The conformance test compares every section with its source.
    static REGISTRY: OnceLock<Value> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        serde_json::from_str(include_str!("registry.json")).expect("embedded v3 registry")
    })
}

fn input_error(message: impl Into<String>) -> VerifierError {
    VerifierError::Runtime(message.into())
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn lower_hex(text: &str, width: usize) -> bool {
    text.len() == width
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

fn is_digest(id: &str) -> bool {
    id.strip_prefix("sha256:")
        .is_some_and(|hex| lower_hex(hex, 64))
}

#[derive(Default)]
struct InputFile {
    path: PathBuf,
    stream: String,
    start: Option<u64>,
    code: Option<&'static str>,
}

fn identify(name: &str) -> Option<InputFile> {
    let prefix = name.strip_suffix(".jsonl")?;
    let (_, version) = prefix.rsplit_once(".receipt-v")?;
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut file = InputFile::default();
    if version != "3" {
        file.code = Some("UNKNOWN_PROFILE");
    } else if let Some((id, number)) = name
        .strip_suffix(FILE_SUFFIX)
        .and_then(|base| base.split_once('-'))
        .filter(|(id, seq)| {
            lower_hex(id, 32) && seq.len() == 16 && seq.bytes().all(|b| b.is_ascii_digit())
        })
    {
        file.stream = id.into();
        file.start = number.parse().ok();
    } else {
        file.code = Some("FILE_LAYOUT");
    }
    Some(file)
}

fn open(path: &Path) -> Result<fs::File> {
    open_verifier_file(path)
}

fn name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
}

fn has_profile(path: &Path) -> Result<bool> {
    let mut file = open(path)?;
    let mut bytes = [0; PROFILE_PREFIX.len()];
    match file.read_exact(&mut bytes) {
        Ok(()) => Ok(bytes == PROFILE_PREFIX),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(err) => Err(input_error(format!("read evidence prefix: {err}"))),
    }
}

/// Tests whether a filename or evidence prefix claims the v3 or later profile.
pub fn claims_input(path: &Path) -> Result<bool> {
    if identify(name(path)).is_some() {
        return Ok(true);
    }
    has_profile(path)
}

#[derive(Default)]
struct Discovery {
    files: Vec<InputFile>,
    old: Vec<PathBuf>,
    inventories: BTreeMap<String, Vec<PathBuf>>,
    ignored: usize,
}

fn discover(paths: &[PathBuf], options: &Options) -> Result<Discovery> {
    let mut found = Discovery::default();
    let paths = if options.directory {
        let dir = paths[0]
            .canonicalize()
            .map_err(|e| input_error(format!("resolve evidence directory: {e}")))?;
        let mut selected = BTreeSet::new();
        let entries =
            fs::read_dir(dir).map_err(|e| input_error(format!("read evidence directory: {e}")))?;
        for entry in entries {
            let entry = entry.map_err(|e| input_error(format!("read evidence directory: {e}")))?;
            let path = entry.path();
            let name = name(&path);
            if identify(name).is_some()
                || legacy::inventory_id(name).is_some()
                || legacy::candidate(name)
            {
                let kind = entry
                    .file_type()
                    .map_err(|e| input_error(format!("stat evidence path: {e}")))?;
                if !kind.is_file() {
                    return Err(input_error(format!(
                        "evidence path is not a regular file: {}",
                        path.display()
                    )));
                }
                selected.insert(path);
            } else {
                found.ignored += 1;
            }
        }
        selected
    } else {
        for path in paths {
            let _ = open(path)?;
        }
        paths.iter().cloned().collect()
    };
    for path in paths {
        if let Some(id) = legacy::inventory_id(name(&path)) {
            found.inventories.entry(id).or_default().push(path);
        } else if let Some(file) = identify(name(&path)) {
            found.files.push(InputFile { path, ..file });
        } else if options.explicit_v3 {
            found.files.push(InputFile {
                path,
                ..InputFile::default()
            });
        } else if has_profile(&path)? {
            found.files.push(InputFile {
                path,
                code: Some("V3_CONTENT_UNCLAIMED"),
                ..InputFile::default()
            });
        } else {
            found.old.push(path);
        }
    }
    Ok(found)
}

struct Verifier<'a> {
    options: &'a Options,
    doc: Document,
    keys: BTreeMap<String, Option<VerifyingKey>>,
    pinned: BTreeSet<String>,
    used: BTreeSet<String>,
    store: Store,
    streams: BTreeMap<String, Stream>,
    histories: BTreeMap<String, Vec<String>>,
}

/// Verifies presented paths and returns both the full document and its normative projection.
///
/// Set `Options::directory` for a one-directory invocation. File order has no
/// effect on the result. Files with a v3 or later claim stay on the v3 path
/// even when they are malformed.
pub fn verify_paths(paths: &[PathBuf], options: &Options) -> Result<VerificationResult> {
    options.validate(paths)?;
    let found = discover(paths, options)?;
    let mut keys = BTreeMap::new();
    for key in &options.keys {
        if !lower_hex(key, 64) {
            return Err(input_error(
                "key must be 64 lowercase hexadecimal characters",
            ));
        }
        let raw: [u8; 32] = hex::decode(key).unwrap().try_into().unwrap();
        keys.insert(digest(&raw), validated_key(raw));
    }
    let pinned = keys.keys().cloned().collect();
    let mut verifier = Verifier {
        options,
        doc: Document::new(options, found.ignored),
        keys,
        pinned,
        used: BTreeSet::new(),
        store: Store::new()?,
        streams: BTreeMap::new(),
        histories: BTreeMap::new(),
    };
    for file in &found.files {
        verifier.discover_key(file)?;
    }
    verifier.stage_files(&found.files)?;
    verifier.verify_streams()?;
    verifier.verify_succession()?;
    let cutover_ends = verifier.verify_cutover(&found)?;
    verifier.appraise_decisions()?;
    verifier.check_expectations(&cutover_ends);
    if found.files.is_empty() {
        if !verifier.doc.legacy.is_empty() {
            return Err(input_error(
                "legacy-only evidence requires the legacy verification path",
            ));
        }
        if verifier.doc.findings.is_empty() {
            verifier.doc.add_code("NO_EVIDENCE", "");
        }
    }
    Ok(verifier.doc.finish(options, verifier.used))
}

#[derive(Default)]
struct FileState {
    stream: String,
    start: i128,
    last: Option<Record>,
    broken: bool,
    after_damage: bool,
}

impl Verifier<'_> {
    fn discover_key(&mut self, input: &InputFile) -> Result<()> {
        if input.code.is_some() || input.start.is_some_and(|seq| seq > 0) {
            return Ok(());
        }
        let mut reader = BufReader::new(open(&input.path)?);
        let mut line = Vec::new();
        if read_line(&mut reader, &mut line)
            .map_err(|e| input_error(format!("read opening record: {e}")))?
        {
            if let Ok(envelope) = parse_line(&line) {
                let record = envelope.record;
                if record.seq == 0 && record.kind == OPEN {
                    if let Some(raw) =
                        embedded_key(&record).filter(|key| digest(key) == record.signer)
                    {
                        self.keys
                            .entry(record.signer)
                            .or_insert_with(|| validated_key(raw));
                    }
                }
            }
        }
        Ok(())
    }

    fn stage_files(&mut self, inputs: &[InputFile]) -> Result<()> {
        let mut last_starts = BTreeMap::new();
        let mut tails = Vec::new();
        let mut line = Vec::new();
        for input in inputs {
            if let Some(code) = input.code {
                self.doc.add_code(code, &input.stream);
                continue;
            }
            let mut reader = BufReader::new(open(&input.path)?);
            let mut state = FileState {
                stream: input.stream.clone(),
                start: input.start.map_or(-1, i128::from),
                ..FileState::default()
            };
            let mut offset = 0;
            while read_line(&mut reader, &mut line)
                .map_err(|e| input_error(format!("read receipt file: {e}")))?
            {
                if !self.stage_line(&line, &mut state, offset)? {
                    state.broken = true;
                    state.after_damage = true;
                }
                offset += 1;
            }
            if let Some(last) = state.last {
                let max = last_starts.entry(state.stream).or_insert(0);
                *max = (*max).max(state.start);
                if !line.is_empty() {
                    tails.push((state.start, last));
                }
            } else if !state.broken {
                self.doc.add_code("FILE_LAYOUT", &state.stream);
            }
        }
        for (start, last) in tails {
            if last.kind == CLOSE {
                self.doc.add_record("DATA_AFTER_CLOSE", &last);
            } else if start < last_starts[&last.stream] {
                self.doc.add_code("FILE_LAYOUT", &last.stream);
            } else {
                self.doc.add_record("TORN_TAIL", &last);
            }
        }
        Ok(())
    }

    fn stage_line(&mut self, line: &[u8], state: &mut FileState, offset: i128) -> Result<bool> {
        let verified = parse_line(line).and_then(|envelope| {
            let key = self
                .keys
                .get(&envelope.record.signer)
                .and_then(Option::as_ref);
            check_signature(&envelope, key)?;
            Ok(envelope.record)
        });
        let mut record = match verified {
            Ok(record) => record,
            Err(code) => {
                self.doc.add_code(code, &state.stream);
                return Ok(false);
            }
        };
        self.used.insert(record.signer.clone());
        if state.last.is_none() {
            if offset == 0
                && state.start >= 0
                && (state.stream != record.stream || state.start != i128::from(record.seq))
            {
                self.doc.add_record("FILE_LAYOUT", &record);
                return Ok(false);
            }
            if state.start < 0 && state.stream.is_empty() {
                state.stream.clone_from(&record.stream);
                state.start = i128::from(record.seq) - offset;
            }
        }
        if !state.broken
            && (record.stream != state.stream || i128::from(record.seq) != state.start + offset)
        {
            self.doc.add_record("STREAM_ORDER", &record);
            return Ok(false);
        }
        if let Some(last) = &state.last {
            if last.kind == CLOSE {
                self.doc.add_record("DATA_AFTER_CLOSE", &record);
                return Ok(false);
            }
        }
        if !state.broken
            && record.seq != 0
            && (record.kind == OPEN
                || state
                    .last
                    .as_ref()
                    .is_some_and(|last| record.prev != last.id || record.signer != last.signer))
        {
            self.doc.add_record("STREAM_ORDER", &record);
            return Ok(false);
        }
        wire::check_body(&mut record);
        record.after_damage = state.after_damage;
        self.streams.entry(state.stream.clone()).or_default();
        self.store.insert(&record)?;
        state.last = Some(record);
        state.after_damage = false;
        Ok(true)
    }
}

pub(crate) fn run(args: &[String]) -> Result<i32> {
    run_cli(args).map_err(|err| input_error(err.to_string().replace(['\r', '\n'], " ")))
}

fn run_cli(args: &[String]) -> Result<i32> {
    if let [flag, path] = args {
        if flag == "--claims" {
            if path.starts_with("--") {
                return Err(input_error("v3 --claims requires one path"));
            }
            let _ = open(Path::new(path))?;
            println!("{}", claims_input(Path::new(path))?);
            return Ok(0);
        }
    }
    let (mut options, mut paths, mut projection) = (Options::default(), Vec::new(), false);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--" {
            paths.extend(args.map(PathBuf::from));
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            paths.push(PathBuf::from(arg));
            continue;
        }
        let (flag, inline) = arg
            .split_once('=')
            .map_or((arg.as_str(), None), |(flag, value)| (flag, Some(value)));
        let mut value = || {
            inline
                .or_else(|| {
                    args.next()
                        .map(String::as_str)
                        .filter(|value| !value.starts_with("--"))
                })
                .ok_or_else(|| input_error(format!("{flag} requires a value")))
        };
        match flag {
            "--allow-unpinned" if inline.is_none() => options.allow_unpinned = true,
            "--allow-prefix" if inline.is_none() => options.allow_prefix = true,
            "--accept-discontinuity" => options.accept_discontinuities.push(value()?.into()),
            "--allow-partial-history" => options.allow_partial_histories.push(value()?.into()),
            "--expect-lineage" => options.expect_lineage = value()?.into(),
            "--key" => options.keys.push(value()?.into()),
            "--expect-head" => options
                .expect_heads
                .push(parse_head(value()?).ok_or_else(|| {
                    input_error("expected head must be stream:seq:sha256:digest")
                })?),
            "--expect-seq" => options.expect_sequences.push(
                parse_sequence(value()?)
                    .ok_or_else(|| input_error("expected sequence must be stream:seq"))?,
            ),
            "--format" if value()? == "v3" => options.explicit_v3 = true,
            "--format" => return Err(input_error("expected format v3")),
            "--output" => {
                projection = match value()? {
                    "result" => false,
                    "projection" => true,
                    _ => return Err(input_error("expected output result or projection")),
                }
            }
            _ => return Err(input_error(format!("unknown v3 option {flag}"))),
        }
    }
    // A zero-file evidence set is supported by the library and the corpus CLI.
    options.directory = paths.len() == 1 && paths[0].is_dir();
    let result = verify_paths(&paths, &options)?;
    let mut stdout = io::stdout().lock();
    let output = if projection {
        result.projection()
    } else {
        result.json()
    };
    stdout
        .write_all(output)
        .and_then(|()| stdout.write_all(b"\n"))
        .map_err(|err| input_error(format!("write verification result: {err}")))?;
    Ok(result.exit_code())
}
