// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, BufRead};

use base64::{engine::general_purpose::STANDARD, Engine};
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar, traits::IsIdentity};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};

use super::{digest, is_digest, lower_hex, registry, Position, MAX_INTEGER};

pub(super) const PROFILE_PREFIX: &[u8] = b"{\"payloadType\":\"application/vnd.pipelock.receipt.";
pub(super) const FILE_SUFFIX: &str = ".receipt-v3.jsonl";
pub(super) const LINE_BYTES: usize = 1 << 20;
const PREFIX: &[u8] =
    b"{\"payloadType\":\"application/vnd.pipelock.receipt.v3+json\",\"signatures\":[";
const PAE_PREFIX: &str = "DSSEv1 40 application/vnd.pipelock.receipt.v3+json ";
const MAX_DEPTH: usize = 16;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct Record {
    pub stream: String,
    pub signer: String,
    pub kind: String,
    pub body: Value,
    pub body_version: u64,
    pub seq: u64,
    pub prev: String,
    pub ts: String,
    pub id: String,
    pub critical: bool,
    pub unknown: bool,
    #[serde(skip)]
    pub body_code: Option<&'static str>,
    #[serde(skip)]
    pub after_damage: bool,
}

impl Record {
    pub(super) fn position(&self) -> Position {
        Position {
            record: self.id.clone(),
            seq: self.seq,
        }
    }
}

pub(super) struct Envelope<'a> {
    pub record: Record,
    pub signature: [u8; 64],
    pub payload: &'a [u8],
}

pub(super) fn read_line(reader: &mut impl BufRead, buffer: &mut Vec<u8>) -> io::Result<bool> {
    buffer.clear();
    loop {
        let input = reader.fill_buf()?;
        if input.is_empty() {
            return Ok(false);
        }
        let newline = input.iter().position(|&byte| byte == b'\n');
        let len = newline.map_or(input.len(), |offset| offset + 1);
        let retained = len.min(LINE_BYTES + 1 - buffer.len());
        buffer.extend_from_slice(&input[..retained]);
        reader.consume(len);
        if newline.is_some() {
            return Ok(true);
        }
    }
}

fn member<'a>(input: &'a [u8], prefix: &[u8], width: usize) -> Option<(&'a [u8], &'a [u8])> {
    let input = input.strip_prefix(prefix)?;
    input.split_at_checked(width)
}

fn signature_entry(input: &[u8]) -> Option<(&str, [u8; 64], &[u8])> {
    let (key, rest) = member(input, b"{\"keyid\":\"", 71)?;
    let key = std::str::from_utf8(key).ok().filter(|key| is_digest(key))?;
    let (encoded, rest) = member(rest, b"\",\"sig\":\"", 88)?;
    let signature = decode_base64(std::str::from_utf8(encoded).ok()?)?;
    Some((key, signature, rest.strip_prefix(b"\"}")?))
}

pub(super) fn parse_line(line: &[u8]) -> Result<Envelope<'_>, &'static str> {
    if line.len() > LINE_BYTES {
        return Err("LINE_SIZE");
    }
    let Some(mut input) = line.strip_prefix(PREFIX) else {
        let profile = line.strip_prefix(PROFILE_PREFIX).and_then(|suffix| {
            suffix
                .iter()
                .position(|&byte| byte == b'"')
                .map(|end| &suffix[..end])
        });
        return Err(if profile.is_some_and(|profile| profile != b"v3+json") {
            "UNKNOWN_PROFILE"
        } else {
            "LINE_LAYOUT"
        });
    };
    let mut signatures = Vec::with_capacity(4);
    let mut last = "";
    loop {
        let (key, sig, rest) = signature_entry(input).ok_or("LINE_LAYOUT")?;
        if key <= last {
            return Err("LINE_LAYOUT");
        }
        signatures.push((key, sig));
        last = key;
        input = rest;
        let Some(rest) = input.strip_prefix(b",") else {
            break;
        };
        if signatures.len() == 4 {
            return Err("LINE_LAYOUT");
        }
        input = rest;
    }

    let payload = input
        .strip_prefix(b"],\"payload\":")
        .and_then(|input| input.strip_suffix(b"}\n"))
        .filter(|payload| payload.starts_with(b"{"))
        .ok_or("LINE_LAYOUT")?;
    let (mut values, tail) = parse_payload(payload).ok_or("PAYLOAD_LAYOUT")?;
    if !tail.is_empty() {
        return Err("LINE_LAYOUT");
    }
    if match_object(&values, "Common").is_none() || !sorted_strings(values.get("crit"), true) {
        return Err("COMMON_SCHEMA");
    }

    let signer = values["signer"].as_str().unwrap().to_owned();
    let signature = signatures
        .into_iter()
        .find_map(|(key, sig)| (key == signer).then_some(sig))
        .ok_or("SIGNER_MISSING")?;
    let record = Record {
        stream: values["stream"].as_str().unwrap().into(),
        signer,
        kind: values["kind"].as_str().unwrap().into(),
        body: values.remove("body").unwrap(),
        body_version: values["body_v"].as_u64().unwrap(),
        seq: values["seq"].as_u64().unwrap(),
        prev: values["prev"].as_str().unwrap().into(),
        ts: values["ts"].as_str().unwrap().into(),
        id: digest(&pae(payload)),
        critical: values.contains_key("crit"),
        unknown: false,
        body_code: None,
        after_damage: false,
    };
    Ok(Envelope {
        record,
        signature,
        payload,
    })
}

pub(super) fn embedded_key(record: &Record) -> Option<[u8; 32]> {
    decode_base64(record.body["signer_key"]["public"].as_str()?)
}

pub(super) fn validated_key(raw: [u8; 32]) -> Option<VerifyingKey> {
    let point = canonical_point(raw)?;
    if !point.is_torsion_free() {
        return None;
    }
    VerifyingKey::from_bytes(&raw).ok()
}

fn canonical_point(raw: [u8; 32]) -> Option<curve25519_dalek::edwards::EdwardsPoint> {
    let point = CompressedEdwardsY(raw).decompress()?;
    (point.compress().to_bytes() == raw && !point.is_identity()).then_some(point)
}

pub(super) fn check_signature(
    envelope: &Envelope<'_>,
    key: Option<&VerifyingKey>,
) -> Result<(), &'static str> {
    let key = key.ok_or("SIGNATURE_KEY")?;
    let (point, scalar) = envelope.signature.split_at(32);
    if !bool::from(Scalar::from_canonical_bytes(scalar.try_into().unwrap()).is_some()) {
        return Err("SIGNATURE_SCALAR");
    }
    if canonical_point(point.try_into().unwrap()).is_none() {
        return Err("SIGNATURE_POINT");
    }
    key.verify_strict(
        &pae(envelope.payload),
        &Signature::from_bytes(&envelope.signature),
    )
    .map_err(|_| "SIGNATURE_EQUATION")
}

fn pae(payload: &[u8]) -> Vec<u8> {
    let mut message = format!("{PAE_PREFIX}{} ", payload.len()).into_bytes();
    message.extend_from_slice(payload);
    message
}

fn decode_base64<const N: usize>(text: &str) -> Option<[u8; N]> {
    let decoded: [u8; N] = STANDARD.decode(text).ok()?.try_into().ok()?;
    (STANDARD.encode(decoded) == text).then_some(decoded)
}

pub(super) fn parse_payload(data: &[u8]) -> Option<(Map<String, Value>, &[u8])> {
    let mut parser = Parser { rest: data };
    let object = parser.object(1)?;
    Some((object, parser.rest))
}

struct Parser<'a> {
    rest: &'a [u8],
}

impl Parser<'_> {
    fn eat(&mut self, bytes: &[u8]) -> bool {
        let Some(rest) = self.rest.strip_prefix(bytes) else {
            return false;
        };
        self.rest = rest;
        true
    }

    fn object(&mut self, depth: usize) -> Option<Map<String, Value>> {
        if depth > MAX_DEPTH || !self.eat(b"{") {
            return None;
        }
        let mut fields = Map::new();
        if self.eat(b"}") {
            return Some(fields);
        }
        let mut last = String::new();
        loop {
            let key = self.string()?;
            if !member_name(&key) || key <= last || !self.eat(b":") {
                return None;
            }
            let value = self.value(depth)?;
            last.clone_from(&key);
            fields.insert(key, value);
            if !self.eat(b",") {
                return self.eat(b"}").then_some(fields);
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<Vec<Value>> {
        if depth > MAX_DEPTH || !self.eat(b"[") {
            return None;
        }
        let mut elements = Vec::new();
        if self.eat(b"]") {
            return Some(elements);
        }
        loop {
            elements.push(self.value(depth)?);
            if !self.eat(b",") {
                return self.eat(b"]").then_some(elements);
            }
        }
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        match self.rest.first()? {
            b'{' => self.object(depth + 1).map(Value::Object),
            b'[' => self.array(depth + 1).map(Value::Array),
            b'"' => self.string().map(Value::String),
            b't' => self.eat(b"true").then_some(Value::Bool(true)),
            b'f' => self.eat(b"false").then_some(Value::Bool(false)),
            _ => self.integer(),
        }
    }

    fn integer(&mut self) -> Option<Value> {
        let input = self.rest;
        let negative = self.eat(b"-");
        if self.eat(b"0") {
            return (!negative).then(|| Value::from(0));
        }
        let digits = self.rest.iter().take_while(|b| b.is_ascii_digit()).count();
        if !(1..=16).contains(&digits) {
            return None;
        }
        self.rest = &self.rest[digits..];
        let integer: i64 = std::str::from_utf8(&input[..digits + usize::from(negative)])
            .ok()?
            .parse()
            .ok()?;
        (integer.unsigned_abs() <= MAX_INTEGER).then(|| Value::from(integer))
    }

    fn string(&mut self) -> Option<String> {
        let input = self.rest;
        if !self.eat(b"\"") {
            return None;
        }
        while let Some((&byte, rest)) = self.rest.split_first() {
            self.rest = rest;
            match byte {
                b'"' => return serde_json::from_slice(&input[..input.len() - rest.len()]).ok(),
                b'\\' => self.escape()?,
                0..=31 => return None,
                _ => {}
            }
        }
        None
    }

    fn escape(&mut self) -> Option<()> {
        let (&escape, rest) = self.rest.split_first()?;
        self.rest = rest;
        match escape {
            b'"' | b'\\' | b'b' | b'f' | b'n' | b'r' | b't' => Some(()),
            b'u' => {
                let hex = self.rest.strip_prefix(b"00")?.get(..2)?;
                let text = std::str::from_utf8(hex)
                    .ok()
                    .filter(|hex| lower_hex(hex, 2))?;
                let byte = u8::from_str_radix(text, 16).ok()?;
                self.rest = &rest[4..];
                (byte < 32 && !matches!(byte, 8 | 9 | 10 | 12 | 13)).then_some(())
            }
            _ => None,
        }
    }
}

fn member_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn match_object(object: &Map<String, Value>, shape: &str) -> Option<bool> {
    let fields = registry()["objects"][shape].as_object()?;
    let mut unknown = false;
    for (name, value) in object {
        let field = fields.get(name)?;
        unknown |= match_field(value, field["type"].as_str()?, field["required"] == true)?;
    }
    if fields
        .iter()
        .any(|(name, field)| field["required"] == true && !object.contains_key(name))
    {
        return None;
    }
    if let Some(conditions) = registry()["conditions"][shape].as_array() {
        for condition in conditions {
            if object.get(condition["field"].as_str()?) != Some(&condition["value"]) {
                continue;
            }
            for (rule, present) in [("require", true), ("forbid", false)] {
                if let Some(names) = condition[rule].as_array() {
                    if names
                        .iter()
                        .any(|name| object.contains_key(name.as_str().unwrap()) != present)
                    {
                        return None;
                    }
                }
            }
            if let Some(expected) = condition["equals"].as_object() {
                if expected
                    .iter()
                    .any(|(name, value)| object.get(name) != Some(value))
                {
                    return None;
                }
            }
        }
    }
    Some(unknown)
}

fn match_field(value: &Value, kind: &str, required: bool) -> Option<bool> {
    if let Some(kind) = kind.strip_prefix("[]") {
        let array = value.as_array()?;
        if !required && array.is_empty() {
            return None;
        }
        return array.iter().try_fold(false, |unknown, item| {
            Some(unknown | match_field(item, kind, true)?)
        });
    }
    if let Some(kind) = kind.strip_prefix('@') {
        return (!value.as_str()?.is_empty()).then(|| {
            !registry()["enums"][kind]
                .as_array()
                .unwrap()
                .contains(value)
        });
    }
    match value {
        Value::Object(object) if required || !object.is_empty() => {
            if kind == "object" {
                Some(false)
            } else {
                match_object(object, kind)
            }
        }
        Value::String(text) if !text.is_empty() => match_string(text, kind).then_some(false),
        Value::Number(number) => match kind {
            "uint" => number.is_u64(),
            "positive" => number.as_u64().is_some_and(|number| number > 0),
            "version" => number.as_u64() == Some(3),
            _ => false,
        }
        .then_some(false),
        Value::Bool(_) if kind == "bool" => Some(false),
        _ => None,
    }
}

fn match_string(text: &str, kind: &str) -> bool {
    match kind {
        "string" => true,
        "name" => member_name(text),
        "id128" => lower_hex(text, 32),
        "digest" => is_digest(text),
        "action_id" => {
            text.len() <= 128
                && text
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        }
        "target" => text.len() <= 2048,
        "instance" => text.len() <= 128,
        "key" => decode_base64::<32>(text).is_some(),
        "time" => valid_timestamp(text),
        _ => false,
    }
}

fn valid_timestamp(text: &str) -> bool {
    let b = text.as_bytes();
    if b.len() != 24 {
        return false;
    }
    let separator = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
        (23, b'Z'),
    ];
    if !b.iter().enumerate().all(|(i, byte)| {
        separator
            .iter()
            .find(|(at, _)| *at == i)
            .map_or_else(|| byte.is_ascii_digit(), |(_, expected)| byte == expected)
    }) {
        return false;
    }
    let y: u16 = text[..4].parse().unwrap();
    let m: usize = text[5..7].parse().unwrap();
    let d: u8 = text[8..10].parse().unwrap();
    let leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let days = [
        0,
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    days.get(m).is_some_and(|&max| (1..=max).contains(&d))
        && &text[11..13] <= "23"
        && &text[14..16] <= "59"
        && &text[17..19] <= "59"
}

fn sorted_strings(value: Option<&Value>, unique: bool) -> bool {
    let Some(value) = value else { return true };
    let Some(items) = value.as_array() else {
        return false;
    };
    let mut previous = "";
    for item in items {
        let Some(text) = item.as_str() else {
            return false;
        };
        if text < previous || (unique && text == previous) {
            return false;
        }
        previous = text;
    }
    true
}

pub(super) fn check_body(record: &mut Record) {
    if record.critical {
        record.unknown = true;
        record.body_code = Some("UNKNOWN_CRIT");
        return;
    }
    let kind = &registry()["kinds"][&record.kind];
    let control = kind["class"] == "control";
    if kind["body_v"].as_u64() != Some(record.body_version) {
        record.unknown = true;
        record.body_code = control.then_some("UNKNOWN_CONTROL");
        return;
    }
    let body = &record.body;
    let Some(unknown) = body
        .as_object()
        .and_then(|object| match_object(object, kind["body"].as_str().unwrap()))
    else {
        record.body_code = Some("BODY_SCHEMA");
        return;
    };
    if unknown && control {
        record.unknown = true;
        record.body_code = Some("UNKNOWN_CONTROL");
        return;
    }
    let valid = match record.kind.as_str() {
        "stream_open" => {
            body["previous"].is_null() != body["legacy_cutover"].is_null()
                && sorted_strings(body["coverage"].get("surfaces"), false)
                && embedded_key(record).is_some_and(|key| digest(&key) == record.signer)
        }
        "stream_close" => body["records"].as_u64() == Some(record.seq + 1),
        "action" => action_fields(body),
        _ => true,
    };
    record.unknown = unknown;
    record.body_code = (!valid).then_some("BODY_SCHEMA");
}

fn action_fields(body: &Value) -> bool {
    let hold = &body["hold"];
    if !hold.is_null() {
        let valid = match body["phase"].as_str().unwrap() {
            "hold" => {
                !hold["policy"].is_null()
                    && hold["correction"].is_null()
                    && hold["resolution_policy"].is_null()
                    && hold["resolution_source"].is_null()
            }
            "resolution" => {
                hold["policy"].is_null()
                    && hold["parent"].is_null()
                    && !hold["resolution_policy"].is_null()
                    && !hold["resolution_source"].is_null()
            }
            _ => true,
        };
        if !valid {
            return false;
        }
    }
    body["policy"]["source"] != "writer_config"
        && body["redaction"]["classes"]
            .as_array()
            .is_none_or(|classes| {
                classes
                    .windows(2)
                    .all(|pair| pair[0]["class"].as_str() < pair[1]["class"].as_str())
            })
}
