export const entityTypes = [
  "EMAIL_ADDRESS",
  "PHONE_NUMBER",
  "CREDIT_CARD",
  "US_SSN",
  "IP_ADDRESS",
  "API_KEY",
  "PERSON",
  "ORGANIZATION",
  "LOCATION",
  "DATE_TIME",
  "MONEY",
  "URL",
  "IBAN_CODE",
  "US_BANK_NUMBER",
  "PASSPORT",
  "DRIVER_LICENSE",
  "MEDICAL_LICENSE",
] as const;

export type EntityType = (typeof entityTypes)[number];
export type Action =
  | "keep"
  | "redact"
  | "label"
  | "tokenize"
  | "hash"
  | "generalize"
  | "synthetic";

export interface PolicyRule {
  entity: EntityType;
  action: Action;
  enabled: boolean;
  reversible: boolean;
  minimumConfidencePpm: number;
  priority: number;
  locale: string;
  scopes: string[];
  requiredDetectors: string[];
}

export interface Policy {
  name: string;
  version: number;
  rules: PolicyRule[];
  allowTerms: string[];
  denyTerms: Partial<Record<string, EntityType>>;
  failClosed: boolean;
  mappingRetentionSeconds: number;
  auditRetentionSeconds: number;
}

export interface ServerPolicyRule {
  entity: EntityType;
  action: Action;
  enabled: boolean;
  reversible: boolean;
  minimum_confidence_ppm: number;
  priority: number;
  locale: string;
  scopes: string[];
  required_detectors: string[];
}

export interface ServerPolicy {
  name: string;
  version: number;
  rules: ServerPolicyRule[];
  allow_terms: string[];
  deny_terms: Partial<Record<string, EntityType>>;
  fail_closed: boolean;
  mapping_retention_seconds: number;
  audit_retention_seconds: number;
}

export interface Detection {
  entity: EntityType;
  start: number;
  end: number;
  jsStart: number;
  jsEnd: number;
  confidencePpm: number;
  detector: string;
  value: string;
}

export interface AppliedDetection extends Detection {
  action: Action;
  replacement: string;
}

export interface TransformResult {
  state: "protected" | "blocked";
  text: string | null;
  detections: AppliedDetection[];
  reverse: Record<string, string>;
  reason?: string;
}

const overrides: Record<string, Partial<Record<EntityType, Action>>> = {
  balanced: { API_KEY: "redact", DATE_TIME: "generalize", MONEY: "generalize", URL: "keep" },
  strict: {
    API_KEY: "redact",
    CREDIT_CARD: "redact",
    US_SSN: "redact",
    IBAN_CODE: "redact",
    US_BANK_NUMBER: "redact",
    PASSPORT: "redact",
    DRIVER_LICENSE: "redact",
    MEDICAL_LICENSE: "redact",
  },
  healthcare: {
    API_KEY: "redact",
    CREDIT_CARD: "redact",
    US_SSN: "redact",
    IBAN_CODE: "redact",
    US_BANK_NUMBER: "redact",
    PASSPORT: "redact",
    DRIVER_LICENSE: "redact",
    MEDICAL_LICENSE: "redact",
    PERSON: "synthetic",
    LOCATION: "synthetic",
    DATE_TIME: "synthetic",
  },
  finance: {
    API_KEY: "redact",
    US_SSN: "redact",
    PASSPORT: "redact",
    DRIVER_LICENSE: "redact",
    MEDICAL_LICENSE: "redact",
    CREDIT_CARD: "tokenize",
    IBAN_CODE: "tokenize",
    US_BANK_NUMBER: "tokenize",
    MONEY: "synthetic",
  },
  devsecops: {
    API_KEY: "redact",
    EMAIL_ADDRESS: "tokenize",
    PHONE_NUMBER: "tokenize",
    IP_ADDRESS: "tokenize",
    PERSON: "keep",
    ORGANIZATION: "keep",
    LOCATION: "keep",
    DATE_TIME: "keep",
    MONEY: "keep",
    URL: "keep",
  },
};

const reversibleDefaults: Record<Action, boolean> = {
  keep: false,
  redact: false,
  label: false,
  tokenize: true,
  hash: false,
  generalize: false,
  synthetic: false,
};

export function policyFromPreset(name: string): Policy {
  const selected = overrides[name.toLowerCase()];
  if (!selected) throw new Error(`unknown preset: ${name}`);
  return {
    name: name.toLowerCase(),
    version: 1,
    rules: entityTypes.map((entity) => {
      const action = selected[entity] ?? "tokenize";
      const healthcareReversible =
        name.toLowerCase() === "healthcare" &&
        (["PERSON", "LOCATION", "DATE_TIME"] as EntityType[]).includes(entity);
      return {
        entity,
        action,
        enabled: true,
        reversible: healthcareReversible || reversibleDefaults[action],
        minimumConfidencePpm: (["PERSON", "LOCATION", "ORGANIZATION"] as EntityType[]).includes(entity)
          ? 650_000
          : 500_000,
        priority: 0,
        locale: "en-US",
        scopes: ["*"],
        requiredDetectors: [],
      };
    }),
    allowTerms: [],
    denyTerms: {},
    failClosed: true,
    mappingRetentionSeconds: 86_400,
    auditRetentionSeconds: 2_592_000,
  };
}

export function policyFromServer(source: ServerPolicy): Policy {
  const policy: Policy = {
    name: source.name,
    version: source.version,
    rules: source.rules.map((rule) => ({
      entity: rule.entity,
      action: rule.action,
      enabled: rule.enabled,
      reversible: rule.reversible,
      minimumConfidencePpm: rule.minimum_confidence_ppm,
      priority: rule.priority,
      locale: rule.locale,
      scopes: [...rule.scopes],
      requiredDetectors: [...rule.required_detectors],
    })),
    allowTerms: [...source.allow_terms],
    denyTerms: { ...source.deny_terms },
    failClosed: source.fail_closed,
    mappingRetentionSeconds: source.mapping_retention_seconds,
    auditRetentionSeconds: source.audit_retention_seconds,
  };
  validatePolicy(policy);
  return policy;
}

export function validatePolicy(policy: Policy): void {
  if (policy.failClosed !== true) throw new Error("failClosed must be true");
  if (!Number.isInteger(policy.version) || policy.version < 1) throw new Error("policy version must be a positive integer");
  if (!Number.isInteger(policy.mappingRetentionSeconds) || policy.mappingRetentionSeconds < 1) {
    throw new Error("mapping retention must be a positive integer");
  }
  if (!Number.isInteger(policy.auditRetentionSeconds) || policy.auditRetentionSeconds < 1) {
    throw new Error("audit retention must be a positive integer");
  }
  const seen = new Set<EntityType>();
  for (const rule of policy.rules) {
    if (!entityTypes.includes(rule.entity)) throw new Error(`unknown entity: ${rule.entity}`);
    if (seen.has(rule.entity)) throw new Error(`duplicate rule: ${rule.entity}`);
    seen.add(rule.entity);
    if (!Number.isInteger(rule.minimumConfidencePpm) || rule.minimumConfidencePpm < 0 || rule.minimumConfidencePpm > 1_000_000) {
      throw new Error(`invalid confidence: ${rule.entity}`);
    }
    if (rule.reversible && (["keep", "redact", "label", "hash"] as Action[]).includes(rule.action)) {
      throw new Error(`${rule.action} cannot be reversible`);
    }
  }
}

const patterns: Partial<Record<EntityType, RegExp>> = {
  EMAIL_ADDRESS:
    /(?<![\w.!#$%&'*+=?^`{|}~-])[A-Z0-9.!#$%&'*+=?^_`{|}~-]{1,64}@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+(?![\w-])/giu,
  PHONE_NUMBER: /(?<!\d)(?:\+?\d{1,3}[ .-]?)?(?:\(\d{2,4}\)|\d{2,4})[ .-]\d{3,4}[ .-]\d{4}(?!\d)/gu,
  US_SSN: /(?<!\d)(?!000|666|9\d\d)\d{3}([- ]?)(?!00)\d{2}\1(?!0000)\d{4}(?!\d)/gu,
  CREDIT_CARD: /(?<!\d)(?:\d[ -]*?){13,19}(?!\d)/gu,
  IP_ADDRESS:
    /(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:.])|(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/gu,
  API_KEY: /(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{16,200}|gh[pousr]_[A-Za-z0-9]{20,255}|AKIA[A-Z0-9]{16})(?![A-Za-z0-9])/gu,
  DATE_TIME: /(?<!\d)(?:20\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]20\d{2})(?!\d)/gu,
  MONEY: /(?<!\w)(?:[$€£]\s?\d[\d ,.]*\d|[$€£]\s?\d|\d[\d ,.]*\d\s?(?:USD|EUR|GBP)|\d\s?(?:USD|EUR|GBP))(?!\w)/giu,
  URL: /(?<!\w)https?:\/\/[^\s<>"']+/giu,
  IBAN_CODE:
    /(?<![A-Z0-9])(?:DE(?: ?[A-Z0-9]){20}|ES(?: ?[A-Z0-9]){22}|FR(?: ?[A-Z0-9]){25}|GB(?: ?[A-Z0-9]){20})(?![A-Z0-9])/giu,
  US_BANK_NUMBER: /(?<!\d)\d{3}(?:[ -]?\d{3}){2}(?!\d)/gu,
};

const utf8Length = (value: string): number => new TextEncoder().encode(value).length;

function luhn(value: string): boolean {
  const digits = [...value].filter((char) => /\d/u.test(char)).map(Number);
  if (digits.length < 13 || digits.length > 19) return false;
  const parity = digits.length % 2;
  const total = digits.reduce((sum, original, index) => {
    let digit = original;
    if (index % 2 === parity) digit = digit > 4 ? digit * 2 - 9 : digit * 2;
    return sum + digit;
  }, 0);
  return total % 10 === 0;
}

function routing(value: string): boolean {
  const digits = [...value].filter((char) => /\d/u.test(char)).map(Number);
  if (digits.length !== 9) return false;
  return digits.reduce((sum, digit, index) => sum + digit * [3, 7, 1][index % 3]!, 0) % 10 === 0;
}

function iban(value: string): boolean {
  const compact = value.replaceAll(" ", "").toUpperCase();
  const lengths: Record<string, number> = { DE: 22, ES: 24, FR: 27, GB: 22 };
  if (compact.length !== lengths[compact.slice(0, 2)]) return false;
  const rotated = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const char of rotated) {
    const digits = /[A-Z]/u.test(char) ? String(char.charCodeAt(0) - 55) : char;
    for (const digit of digits) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

function validIp(value: string): boolean {
  if (!value.includes(":")) {
    const parts = value.split(".");
    return parts.length === 4 && parts.every((part) => /^\d{1,3}$/u.test(part) && Number(part) <= 255);
  }
  if ((value.match(/::/gu) ?? []).length > 1) return false;
  const sides = value.split("::");
  const groups = sides.flatMap((side) => (side ? side.split(":") : []));
  if (!groups.every((group) => /^[0-9A-Fa-f]{1,4}$/u.test(group))) return false;
  return value.includes("::") ? groups.length < 8 : groups.length === 8;
}

function validUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    const authority = value.slice(value.indexOf("://") + 3).split(/[/?#]/u, 1)[0]!;
    return (
      (parsed.protocol === "http:" || parsed.protocol === "https:") &&
      parsed.hostname.length > 0 &&
      !authority.includes("@") &&
      parsed.username === "" &&
      parsed.password === "" &&
      /^[\x00-\x7F]+$/u.test(value)
    );
  } catch {
    return false;
  }
}

export function detect(text: string, policy: Policy, scope = "text"): Detection[] {
  validatePolicy(policy);
  const active = new Map(
    policy.rules
      .filter((rule) => rule.enabled && rule.action !== "keep" && (rule.scopes.includes("*") || rule.scopes.includes(scope)))
      .map((rule) => [rule.entity, rule]),
  );
  const candidates: Detection[] = [];
  const unavailable = [...active.values()]
    .flatMap((rule) => rule.requiredDetectors)
    .filter((name) => name !== "regex-v1");
  if (unavailable.length > 0) {
    throw new Error(`required detectors unavailable: ${[...new Set(unavailable)].sort().join(", ")}`);
  }
  for (const [entity, pattern] of Object.entries(patterns) as [EntityType, RegExp][]) {
    const rule = active.get(entity);
    if (!rule) continue;
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      const value = match[0];
      const jsStart = match.index;
      const jsEnd = jsStart + value.length;
      if (entity === "CREDIT_CARD" && !luhn(value)) continue;
      if (entity === "US_BANK_NUMBER" && !routing(value)) continue;
      if (entity === "IBAN_CODE" && !iban(value)) continue;
      if (entity === "IP_ADDRESS" && !validIp(value)) continue;
      if (entity === "URL" && !validUrl(value)) continue;
      if (entity === "MONEY" && utf8Length(value) > 128) continue;
      candidates.push({
        entity,
        start: utf8Length(text.slice(0, jsStart)),
        end: utf8Length(text.slice(0, jsEnd)),
        jsStart,
        jsEnd,
        confidencePpm: 990_000,
        detector: "regex-v1",
        value,
      });
    }
  }
  for (const [value, entity] of Object.entries(policy.denyTerms)) {
    if (!entity || !active.has(entity)) continue;
    let jsStart = text.toLocaleLowerCase().indexOf(value.toLocaleLowerCase());
    while (jsStart >= 0) {
      const jsEnd = jsStart + value.length;
      candidates.push({
        entity,
        start: utf8Length(text.slice(0, jsStart)),
        end: utf8Length(text.slice(0, jsEnd)),
        jsStart,
        jsEnd,
        confidencePpm: 1_000_000,
        detector: "deny-list",
        value: text.slice(jsStart, jsEnd),
      });
      jsStart = text.toLocaleLowerCase().indexOf(value.toLocaleLowerCase(), jsEnd);
    }
  }
  const allow = new Set(policy.allowTerms.map((value) => value.toLocaleLowerCase()));
  const eligible = candidates.filter((item) => {
    const rule = active.get(item.entity)!;
    return item.confidencePpm >= rule.minimumConfidencePpm && !allow.has(item.value.toLocaleLowerCase());
  });
  eligible.sort((left, right) => {
    const leftRule = active.get(left.entity)!;
    const rightRule = active.get(right.entity)!;
    return (
      Number(left.detector !== "deny-list") - Number(right.detector !== "deny-list") ||
      rightRule.priority - leftRule.priority ||
      right.confidencePpm - left.confidencePpm ||
      right.end - right.start - (left.end - left.start) ||
      left.start - right.start ||
      left.entity.localeCompare(right.entity) ||
      left.detector.localeCompare(right.detector)
    );
  });
  const accepted: Detection[] = [];
  for (const candidate of eligible) {
    if (!accepted.some((item) => candidate.start < item.end && item.start < candidate.end)) accepted.push(candidate);
  }
  return accepted.sort((left, right) => left.start - right.start);
}

function base32(input: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

async function token(entity: EntityType, key: Uint8Array): Promise<string> {
  const generation = crypto.getRandomValues(new Uint8Array(16));
  const rawKey = Uint8Array.from(key);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    rawKey.buffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", cryptoKey, generation.buffer),
  );
  return `[[PG1|${entity}|${base32(generation)}|${base32(signature.slice(0, 10))}]]`;
}

async function digestBytes(entity: EntityType, value: string, key?: Uint8Array): Promise<Uint8Array> {
  const payload = new TextEncoder().encode(`${entity}\0${value}`);
  if (key) {
    const rawKey = Uint8Array.from(key);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      rawKey.buffer,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, payload.buffer));
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", payload.buffer));
}

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

function decimalDigits(seed: bigint, length: number): string {
  let output = "";
  let value = seed;
  while (output.length < length) {
    output += value.toString().padStart(20, "0");
    value = (value * 6_364_136_223_846_793_005n + 1_442_695_040_888_963_407n) & ((1n << 64n) - 1n);
  }
  return output.slice(0, length);
}

function luhnCheckDigit(prefix: string): string {
  for (const candidate of "0123456789") {
    const digits = [...`${prefix}${candidate}`].map(Number);
    const parity = digits.length % 2;
    const total = digits.reduce((sum, digit, index) => {
      const adjusted = index % 2 === parity ? (digit > 4 ? digit * 2 - 9 : digit * 2) : digit;
      return sum + adjusted;
    }, 0);
    if (total % 10 === 0) return candidate;
  }
  throw new Error("a Luhn check digit must exist");
}

function syntheticIban(country: "DE" | "ES" | "FR" | "GB", seed: bigint): string {
  const lengths = { DE: 18, ES: 20, FR: 23, GB: 18 } as const;
  const bban = country === "GB" ? `PGAT${decimalDigits(seed, 14)}` : decimalDigits(seed, lengths[country]);
  const provisional = `${bban}${country}00`;
  const numeric = [...provisional]
    .map((char) => /[A-Z]/u.test(char) ? String(char.charCodeAt(0) - 55) : char)
    .join("");
  let remainder = 0n;
  for (const digit of numeric) remainder = (remainder * 10n + BigInt(digit)) % 97n;
  return `${country}${String(98n - remainder).padStart(2, "0")}${bban}`;
}

function routingNumber(seed: bigint): string {
  const prefix = `01${decimalDigits(seed, 6)}`;
  for (const candidate of "0123456789") {
    const digits = [...`${prefix}${candidate}`].map(Number);
    const total = digits.reduce((sum, digit, index) => sum + [3, 7, 1][index % 3]! * digit, 0);
    if (total % 10 === 0) return `${prefix}${candidate}`;
  }
  throw new Error("an ABA routing check digit must exist");
}

async function synthetic(item: Detection, key?: Uint8Array): Promise<string> {
  const digest = await digestBytes(item.entity, item.value, key);
  const seed = BigInt(`0x${hex(digest.slice(0, 8))}`);
  if (item.entity === "EMAIL_ADDRESS") return `person${seed % 100_000n}@example.test`;
  if (item.entity === "PHONE_NUMBER") return `+1-202-555-${String(seed % 10_000n).padStart(4, "0")}`;
  if (item.entity === "PERSON") {
    const first = ["Alex", "Jordan", "Morgan", "Riley", "Taylor", "Casey"][Number(seed % 6n)]!;
    const last = ["Brooks", "Chen", "Diaz", "Patel", "Rivera", "Singh"][Number((seed / 7n) % 6n)]!;
    return `${first} ${last}`;
  }
  if (item.entity === "ORGANIZATION") {
    return ["Northstar Labs", "Juniper Works", "Atlas Harbor", "Cinder Systems"][Number(seed % 4n)]!;
  }
  if (item.entity === "LOCATION") {
    return ["Madison, WI", "Raleigh, NC", "Boise, ID", "Albany, NY"][Number(seed % 4n)]!;
  }
  if (item.entity === "DATE_TIME") {
    return `20${String(20n + (seed % 7n)).padStart(2, "0")}-${String(1n + ((seed / 7n) % 12n)).padStart(2, "0")}-${String(1n + ((seed / 97n) % 28n)).padStart(2, "0")}`;
  }
  if (item.entity === "MONEY") return `$${(10n + (seed % 9_990n)).toLocaleString("en-US")}.00`;
  if (item.entity === "CREDIT_CARD") {
    const prefix = `4${decimalDigits(seed, 14)}`;
    return prefix + luhnCheckDigit(prefix);
  }
  if (item.entity === "US_SSN") {
    let area = 100n + (seed % 799n);
    if (area >= 666n) area += 1n;
    const group = 1n + ((seed / 799n) % 99n);
    const serial = 1n + ((seed / (799n * 99n)) % 9_999n);
    return `${String(area).padStart(3, "0")}-${String(group).padStart(2, "0")}-${String(serial).padStart(4, "0")}`;
  }
  if (item.entity === "IP_ADDRESS") {
    return item.value.includes(":") ? `2001:db8::${(1n + (seed % 65_534n)).toString(16)}` : `192.0.2.${1n + (seed % 254n)}`;
  }
  if (item.entity === "API_KEY") {
    const value = base32(digest).slice(0, 24);
    if (item.value.startsWith("AKIA")) return `AKIA${value.slice(0, 16)}`;
    if (/^gh[pousr]_/u.test(item.value)) return `${item.value.slice(0, 4)}${value}`;
    return `sk-pg_${value}`;
  }
  if (item.entity === "URL") return `https://service-${seed % 10_000n}.example.test/resource/${seed % 100_000n}`;
  if (item.entity === "IBAN_CODE") {
    const candidate = item.value.replaceAll(" ", "").slice(0, 2).toUpperCase();
    const country = (["DE", "ES", "FR", "GB"] as const).find((value) => value === candidate) ?? "GB";
    return syntheticIban(country, seed);
  }
  if (item.entity === "US_BANK_NUMBER") return routingNumber(seed);
  if (item.entity === "PASSPORT") return `P${decimalDigits(seed, 8)}`;
  if (item.entity === "DRIVER_LICENSE") return `D${decimalDigits(seed, 8)}`;
  if (item.entity === "MEDICAL_LICENSE") return `M${decimalDigits(seed, 9)}`;
  return `SYNTHETIC_${item.entity}_${hex(digest).slice(0, 10).toUpperCase()}`;
}

function generalize(item: Detection): string {
  if (item.entity === "DATE_TIME") return item.value.match(/(?:19|20)\d{2}/u)?.[0] ?? "[DATE]";
  if (item.entity === "EMAIL_ADDRESS") return `***@${item.value.split("@").at(-1)}`;
  if (item.entity === "MONEY") {
    const digits = item.value.replace(/\D/gu, "").replace(/^0+/u, "") || "0";
    const symbol = /^[\$€£]/u.test(item.value) ? item.value[0] : "";
    return `${symbol}~10^${Math.max(0, digits.length - 1)}`;
  }
  return `[${item.entity}]`;
}

export async function transform(text: string, policy: Policy, key?: Uint8Array): Promise<TransformResult> {
  try {
    validatePolicy(policy);
  } catch (error) {
    return { state: "blocked", text: null, detections: [], reverse: {}, reason: String(error) };
  }
  const needsKey = policy.rules.some((rule) => rule.enabled && rule.action !== "keep" && rule.reversible);
  if (needsKey && !key) {
    return { state: "blocked", text: null, detections: [], reverse: {}, reason: "reversible policy requires a key" };
  }
  const operationKey = key ?? crypto.getRandomValues(new Uint8Array(32));
  let found: Detection[];
  try {
    found = detect(text, policy);
  } catch (error) {
    return { state: "blocked", text: null, detections: [], reverse: {}, reason: String(error) };
  }
  const seen = new Map<string, string>();
  const reverse: Record<string, string> = {};
  const applied: AppliedDetection[] = [];
  let cursor = 0;
  let output = "";
  for (const item of found) {
    const rule = policy.rules.find((candidate) => candidate.entity === item.entity)!;
    const identity = `${item.entity}\0${item.value}`;
    let replacement = seen.get(identity);
    if (!replacement) {
      if (rule.action === "redact") replacement = `[REDACTED:${item.entity}]`;
      else if (rule.action === "label") replacement = `<${item.entity}>`;
      else if (rule.action === "generalize") replacement = generalize(item);
      else if (rule.action === "tokenize") replacement = await token(item.entity, key!);
      else if (rule.action === "hash") {
        replacement = `sha256:${hex(await digestBytes(item.entity, item.value, operationKey)).slice(0, 48)}`;
      } else if (rule.action === "synthetic") replacement = await synthetic(item, operationKey);
      else replacement = item.value;
      if (rule.reversible && rule.action !== "tokenize") {
        replacement = `${replacement} ${await token(item.entity, key!)}`;
      }
      seen.set(identity, replacement);
    }
    output += text.slice(cursor, item.jsStart) + replacement;
    cursor = item.jsEnd;
    if (rule.reversible) reverse[replacement] = item.value;
    applied.push({ ...item, action: rule.action, replacement });
  }
  output += text.slice(cursor);
  return { state: "protected", text: output, detections: applied, reverse };
}

export function restore(text: string, reverse: Record<string, string>): string {
  const exact = Object.entries(reverse)
    .sort(([left], [right]) => right.length - left.length)
    .reduce((value, [replacement, original]) => value.split(replacement).join(original), text);
  const tokenSource = String.raw`\[\[ ?[Pp][Gg]1 ?\| ?([A-Za-z_]+) ?\| ?([A-Za-z2-7]{26}) ?\| ?([A-Za-z2-7]{16}) ?\]\]`;
  const escapeRegex = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  let tolerant = exact;
  for (const [surface, original] of Object.entries(reverse)) {
    const matches = [...surface.matchAll(new RegExp(tokenSource, "g"))];
    const match = matches.at(-1);
    if (!match || match.index + match[0].length !== surface.length) continue;
    const expected = match.slice(1).map((part) => part!.toUpperCase()).join("|");
    const composite = new RegExp(`${escapeRegex(surface.slice(0, match.index))}${tokenSource}`, "g");
    tolerant = tolerant.replace(composite, (candidate, entity, generation, auth) => {
      const actual = [entity, generation, auth].map((part: string) => part.toUpperCase()).join("|");
      return actual === expected ? original : candidate;
    });
  }
  return tolerant;
}

export class StreamingRestorer {
  // Covers the largest v1 composite surface while remaining strictly bounded.
  static readonly maxCandidateChars = 512;
  readonly #reverse: Record<string, string>;
  readonly #compositePrefixes: string[];
  #buffer = "";
  #finished = false;

  constructor(reverse: Record<string, string>) {
    this.#reverse = { ...reverse };
    const token = /\[\[PG1\|[A-Z_]+\|[A-Z2-7]{26}\|[A-Z2-7]{16}\]\]/gu;
    this.#compositePrefixes = Object.keys(reverse).flatMap((surface) => {
      const matches = [...surface.matchAll(token)];
      const match = matches.at(-1);
      return match && match.index > 0 && match.index + match[0].length === surface.length
        ? [surface.slice(0, match.index)]
        : [];
    });
  }

  feed(chunk: string): string {
    if (this.#finished) throw new Error("stream restorer is already finished");
    this.#buffer += chunk;
    const cut = this.#safeCut();
    const ready = this.#buffer.slice(0, cut);
    this.#buffer = this.#buffer.slice(cut);
    return restore(ready, this.#reverse);
  }

  finish(): string {
    if (this.#finished) throw new Error("stream restorer is already finished");
    this.#finished = true;
    const ready = this.#buffer;
    this.#buffer = "";
    return restore(ready, this.#reverse);
  }

  #safeCut(): number {
    let cut = this.#buffer.length;
    for (const surface of Object.keys(this.#reverse)) {
      const limit = Math.min(surface.length - 1, this.#buffer.length);
      for (let length = 1; length <= limit; length += 1) {
        if (this.#buffer.endsWith(surface.slice(0, length))) {
          cut = Math.min(cut, this.#buffer.length - length);
        }
      }
    }
    for (const prefix of this.#compositePrefixes) {
      const limit = Math.min(prefix.length, this.#buffer.length);
      for (let length = 1; length <= limit; length += 1) {
        if (this.#buffer.endsWith(prefix.slice(0, length))) {
          cut = Math.min(cut, this.#buffer.length - length);
        }
      }
      const start = this.#buffer.lastIndexOf(`${prefix}[[`);
      if (start >= 0 && !this.#buffer.slice(start + prefix.length + 2).includes("]]")) {
        cut = Math.min(cut, start);
      }
    }
    const lastOpen = this.#buffer.lastIndexOf("[[");
    if (lastOpen >= 0 && !this.#buffer.slice(lastOpen + 2).includes("]]")) {
      if (this.#buffer.length - lastOpen <= StreamingRestorer.maxCandidateChars) {
        cut = Math.min(cut, lastOpen);
      } else {
        cut = Math.min(cut, Math.max(0, this.#buffer.length - StreamingRestorer.maxCandidateChars));
      }
    }
    if (this.#buffer.endsWith("[")) cut = Math.min(cut, this.#buffer.length - 1);
    return Math.max(cut, this.#buffer.length - StreamingRestorer.maxCandidateChars);
  }
}

export function restoreJson(
  value: unknown,
  reverse: Record<string, string>,
  blockedPointers: ReadonlySet<string> = new Set(),
): unknown {
  const blocked = (pointer: string): boolean =>
    [...blockedPointers].some((prefix) => pointer === prefix || pointer.startsWith(`${prefix}/`));
  const escape = (segment: string): string => segment.replaceAll("~", "~0").replaceAll("/", "~1");
  const walk = (node: unknown, pointer: string): unknown => {
    if (blocked(pointer)) return node;
    if (typeof node === "string") return restore(node, reverse);
    if (Array.isArray(node)) return node.map((item, index) => walk(item, `${pointer}/${index}`));
    if (node && typeof node === "object") {
      return Object.fromEntries(
        Object.entries(node).map(([key, item]) => [key, walk(item, `${pointer}/${escape(key)}`)]),
      );
    }
    return node;
  };
  return walk(value, "");
}
