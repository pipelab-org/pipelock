// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { Point } from "@noble/ed25519";

type Value = string | number | boolean | Value[] | Fields;
export interface Fields {
  [name: string]: Value;
}

export type FindingClass =
  "invalid" | "unsupported" | "incomplete" | "end_unproven" | "warning" | "info";

const registry: {
  profile: string;
  layout: Record<string, string> & { public_key_bytes: number; signature_bytes: number };
  limits: Record<string, number>;
  findings: Record<string, FindingClass>;
  normalization_profiles: Record<string, string>;
  kinds: Record<string, { body: string; body_v: number; class: string }>;
  enums: Record<string, string[]>;
  objects: Record<string, Record<string, { required: boolean; type: string }>>;
  conditions: Record<
    string,
    { field: string; value: Value; require?: string[]; forbid?: string[]; equals?: Fields }[]
  >;
} = JSON.parse(readFileSync(new URL("registry.json", import.meta.url), "utf8"));

export const { layout, limits, findings } = registry;
export const normalizationProfiles = registry.normalization_profiles;
export const profilePrefix = '{"payloadType":"application/vnd.pipelock.receipt.';
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const invalid = Symbol("invalid payload");
const member = /^[a-z][a-z0-9_]*$/u;

export const ascii = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
export const byteOrder = (a: string, b: string): number =>
  Buffer.compare(Buffer.from(a), Buffer.from(b));
export const digest = (value: Buffer | string): string =>
  "sha256:" + createHash("sha256").update(value).digest("hex");
export const isDigest = (value: string): boolean => /^sha256:[0-9a-f]{64}$/u.test(value);
export const isID = (value: string): boolean => /^[0-9a-f]{32}$/u.test(value);
export const isKey = (value: string): boolean => /^[0-9a-f]{64}$/u.test(value);
export const genesis = (stream: string): string => digest(layout.genesis_domain + "\0" + stream);

function parseBase64(value: string, size: number): Buffer | undefined {
  const raw = Buffer.from(value, "base64");
  return raw.length === size && raw.toString("base64") === value ? raw : undefined;
}

function pae(payload: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from(
      "DSSEv1 " + registry.profile.length + " " + registry.profile + " " + payload.length + " ",
    ),
    payload,
  ]);
}

class PayloadParser {
  pos = 0;
  // Use a byte-preserving view so string offsets can address the signed buffer.
  private readonly text: string;
  private readonly integer = /-?(?:0|[1-9][0-9]*)/uy;

  constructor(private readonly raw: Buffer) {
    this.text = raw.toString("latin1");
  }

  private eat(token: string): boolean {
    if (!this.text.startsWith(token, this.pos)) return false;
    this.pos += token.length;
    return true;
  }

  object(depth: number): Fields {
    if (depth > limits.depth || !this.eat("{")) throw invalid;
    const result: Fields = Object.create(null);
    if (this.eat("}")) return result;
    let last = "";
    do {
      const key = this.string();
      if (!member.test(key) || key.length > limits.member_bytes || key <= last || !this.eat(":"))
        throw invalid;
      result[key] = this.value(depth);
      last = key;
    } while (this.eat(","));
    if (!this.eat("}")) throw invalid;
    return result;
  }

  private array(depth: number): Value[] {
    if (depth > limits.depth || !this.eat("[")) throw invalid;
    const result: Value[] = [];
    if (this.eat("]")) return result;
    do {
      result.push(this.value(depth));
    } while (this.eat(","));
    if (!this.eat("]")) throw invalid;
    return result;
  }

  private string(): string {
    const start = this.pos;
    if (!this.eat('"')) throw invalid;
    while (this.pos < this.raw.length) {
      const next = this.raw[this.pos++];
      if (next === 0x22) return JSON.parse(utf8.decode(this.raw.subarray(start, this.pos)));
      if (next < 0x20) throw invalid;
      if (next === 0x5c) this.escape();
    }
    throw invalid;
  }

  private escape(): void {
    const type = this.text[this.pos++];
    if (type && '"\\bfnrt'.includes(type)) return;
    if (type === "u") {
      const code = this.text.slice(this.pos, this.pos + 4);
      if (/^00(?:0[0-7be-f]|1[0-9a-f])$/u.test(code)) {
        this.pos += 4;
        return;
      }
    }
    throw invalid;
  }

  private value(depth: number): Value {
    switch (this.text[this.pos]) {
      case "{":
        return this.object(depth + 1);
      case "[":
        return this.array(depth + 1);
      case '"':
        return this.string();
      case "t":
        if (this.eat("true")) return true;
        throw invalid;
      case "f":
        if (this.eat("false")) return false;
        throw invalid;
      default: {
        this.integer.lastIndex = this.pos;
        const match = this.integer.exec(this.text);
        if (!match || match[0] === "-0") throw invalid;
        const value = Number(match[0]);
        if (Math.abs(value) > limits.integer) throw invalid;
        this.pos = this.integer.lastIndex;
        return value;
      }
    }
  }
}

type Match = "valid" | "unknown" | "invalid";

function isObject(value: Value): value is Fields {
  return typeof value === "object" && !Array.isArray(value);
}

function sortedStrings(value: Value | undefined, unique: boolean): boolean {
  if (value === undefined) return true;
  return (
    Array.isArray(value) &&
    value.every((item, i) => {
      if (typeof item !== "string") return false;
      const prev = i ? byteOrder(item, value[i - 1] as string) : byteOrder(item, "");
      return unique ? prev > 0 : prev >= 0;
    })
  );
}

function matchObject(fields: Fields, shape: string): Match {
  const spec = registry.objects[shape];
  let result: Match = "valid";
  for (const [name, value] of Object.entries(fields)) {
    if (!Object.hasOwn(spec, name)) return "invalid";
    const field = spec[name];
    const match = matchField(value, field.type, field.required);
    if (match === "invalid") return match;
    if (match === "unknown") result = match;
  }
  for (const [name, field] of Object.entries(spec)) {
    if (field.required && fields[name] === undefined) return "invalid";
  }
  for (const rule of registry.conditions[shape] ?? []) {
    if (fields[rule.field] !== rule.value) continue;
    if (
      rule.require?.some((key) => fields[key] === undefined) ||
      rule.forbid?.some((key) => fields[key] !== undefined) ||
      Object.entries(rule.equals ?? {}).some(([key, value]) => fields[key] !== value)
    )
      return "invalid";
  }
  return result;
}

function matchField(value: Value, type: string, required: boolean): Match {
  if (type.startsWith("[]")) {
    if (!Array.isArray(value) || (!required && !value.length)) return "invalid";
    let result: Match = "valid";
    for (const item of value) {
      const match = matchField(item, type.slice(2), true);
      if (match === "invalid") return match;
      if (match === "unknown") result = match;
    }
    return result;
  }
  if (type.startsWith("@")) {
    if (typeof value !== "string" || !value) return "invalid";
    return registry.enums[type.slice(1)].includes(value) ? "valid" : "unknown";
  }
  if (isObject(value)) {
    if (!required && !Object.keys(value).length) return "invalid";
    if (type === "object") return "valid";
    return Object.hasOwn(registry.objects, type) ? matchObject(value, type) : "invalid";
  }
  let valid = false;
  if (typeof value === "string") valid = matchString(value, type);
  if (typeof value === "number")
    valid =
      (type === "uint" && value >= 0) ||
      (type === "positive" && value > 0) ||
      (type === "version" && value === 3);
  if (typeof value === "boolean") valid = type === "bool";
  return valid ? "valid" : "invalid";
}

function matchString(value: string, type: string): boolean {
  if (!value) return false;
  switch (type) {
    case "string":
      return true;
    case "name":
      return value.length <= limits.member_bytes && member.test(value);
    case "id128":
      return isID(value);
    case "digest":
      return isDigest(value);
    case "action_id":
      return /^[A-Za-z0-9._:-]{1,128}$/u.test(value);
    case "target":
      return Buffer.byteLength(value) <= limits.target_bytes;
    case "instance":
      return Buffer.byteLength(value) <= limits.writer_instance_bytes;
    case "key":
      return parseBase64(value, layout.public_key_bytes) !== undefined;
    case "time": {
      if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(value)) return false;
      const ms = Date.parse(value);
      return Number.isFinite(ms) && new Date(ms).toISOString() === value;
    }
    default:
      return false;
  }
}

export interface RecordV3 {
  id: string;
  stream: string;
  seq: number;
  kind: string;
  body_v: number;
  crit?: string[];
  prev: string;
  signer: string;
  ts: string;
  body: Fields;
  message: Buffer;
  signature: Buffer;
}

export function parseLine(line: Buffer): RecordV3 | string {
  if (line.length > limits.line_bytes) return "LINE_SIZE";
  const text = line.toString("latin1");
  if (!text.startsWith(layout.prefix)) {
    if (text.startsWith(profilePrefix)) {
      const version = text.slice(profilePrefix.length).split('"', 2);
      if (version.length === 2 && version[0] !== "v3+json") return "UNKNOWN_PROFILE";
    }
    return "LINE_LAYOUT";
  }
  const sigs = new Map<string, Buffer>();
  let pos = layout.prefix.length;
  let last = "";
  for (;;) {
    if (!text.startsWith(layout.entry_prefix, pos)) return "LINE_LAYOUT";
    pos += layout.entry_prefix.length;
    const key = text.slice(pos, pos + 71);
    pos += 71;
    if (!isDigest(key) || key <= last || !text.startsWith(layout.signature_prefix, pos))
      return "LINE_LAYOUT";
    pos += layout.signature_prefix.length;
    const sig = parseBase64(text.slice(pos, pos + 88), layout.signature_bytes);
    pos += 88;
    if (!sig || !text.startsWith(layout.entry_suffix, pos)) return "LINE_LAYOUT";
    pos += layout.entry_suffix.length;
    sigs.set(key, sig);
    last = key;
    if (!text.startsWith(layout.entry_separator, pos)) break;
    if (sigs.size === limits.signatures) return "LINE_LAYOUT";
    pos += layout.entry_separator.length;
  }
  if (!text.startsWith(layout.payload_prefix + "{", pos) || !text.endsWith(layout.suffix))
    return "LINE_LAYOUT";
  const payload = line.subarray(pos + layout.payload_prefix.length, -layout.suffix.length);
  const parser = new PayloadParser(payload);
  let fields: Fields;
  try {
    fields = parser.object(1);
  } catch (error) {
    if (error === invalid || error instanceof TypeError || error instanceof SyntaxError)
      return "PAYLOAD_LAYOUT";
    throw error;
  }
  if (parser.pos !== payload.length) return "LINE_LAYOUT";
  if (matchObject(fields, "Common") === "invalid" || !sortedStrings(fields.crit, true))
    return "COMMON_SCHEMA";
  const message = pae(payload);
  const signature = sigs.get(fields.signer as string);
  if (!signature) return "SIGNER_MISSING";
  return {
    ...(fields as unknown as Omit<RecordV3, "message" | "id" | "signature">),
    message,
    id: digest(message),
    signature,
  };
}

function point(bytes: Buffer): Point | undefined {
  try {
    const p = Point.fromBytes(bytes, false);
    if (!p.equals(Point.ZERO) && Buffer.from(p.toBytes()).equals(bytes)) return p;
  } catch {
    // The strict decoder rejects off-curve points and noncanonical encodings.
  }
  return undefined;
}

const scalarOrder = 2n ** 252n + 27742317777372353535851937790883648493n;
const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");

export function validatedKey(raw: Buffer): KeyObject | undefined {
  if (!point(raw)?.isTorsionFree()) return undefined;
  return createPublicKey({ key: Buffer.concat([spkiPrefix, raw]), format: "der", type: "spki" });
}

export function embeddedKey(record: RecordV3): Buffer | undefined {
  if (record.kind !== "stream_open" || record.seq !== 0) return undefined;
  const publicKey = (record.body.signer_key as Fields | undefined)?.public;
  if (typeof publicKey !== "string") return undefined;
  const raw = parseBase64(publicKey, layout.public_key_bytes);
  return raw && digest(raw) === record.signer ? raw : undefined;
}

export function signatureFinding(record: RecordV3, key: KeyObject | undefined): string {
  if (!key) return "SIGNATURE_KEY";
  const r = record.signature.subarray(0, 32);
  const s = Buffer.from(record.signature.subarray(32)).reverse().toString("hex");
  if (BigInt("0x" + s) >= scalarOrder) return "SIGNATURE_SCALAR";
  if (!point(r)) return "SIGNATURE_POINT";
  // OpenSSL's pure Ed25519 verifier checks the uncofactored equation.
  return verify(null, record.message, key, record.signature) ? "" : "SIGNATURE_EQUATION";
}

function actionFields(body: Fields): boolean {
  if ((body.policy as Fields).source === "writer_config") return false;
  const hold = body.hold as Fields | undefined;
  if (hold && body.phase === "hold") {
    if (!hold.policy || hold.correction || hold.resolution_policy || hold.resolution_source)
      return false;
  }
  if (hold && body.phase === "resolution") {
    if (hold.policy || hold.parent || !hold.resolution_policy || !hold.resolution_source)
      return false;
  }
  const classes = (body.redaction as Fields | undefined)?.classes as Fields[] | undefined;
  return (
    !classes ||
    sortedStrings(
      classes.map((item) => item.class),
      true,
    )
  );
}

export function checkBody(record: RecordV3): { unknown: boolean; bodyCode: string } {
  const result = (unknown: boolean, bodyCode = "") => ({ unknown, bodyCode });
  if (record.crit?.length) return result(true, "UNKNOWN_CRIT");
  const kind = Object.hasOwn(registry.kinds, record.kind) ? registry.kinds[record.kind] : undefined;
  if (!kind || record.body_v !== kind.body_v)
    return result(true, kind?.class === "control" ? "UNKNOWN_CONTROL" : "");
  const status = matchObject(record.body, kind.body);
  if (status === "invalid") return result(false, "BODY_SCHEMA");
  if (status === "unknown" && kind.class === "control") return result(true, "UNKNOWN_CONTROL");

  switch (record.kind) {
    case "action":
      if (!actionFields(record.body)) return result(false, "BODY_SCHEMA");
      break;
    case "stream_open":
      if (
        Boolean(record.body.previous) === Boolean(record.body.legacy_cutover) ||
        !sortedStrings((record.body.coverage as Fields).surfaces, false) ||
        !embeddedKey({ ...record, seq: 0 })
      )
        return result(false, "BODY_SCHEMA");
      break;
    case "stream_close":
      if (record.body.records !== record.seq + 1) return result(false, "BODY_SCHEMA");
  }
  return result(status === "unknown");
}
