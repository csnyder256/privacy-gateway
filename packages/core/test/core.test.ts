import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  detect,
  entityTypes,
  policyFromPreset,
  policyFromServer,
  restore,
  restoreJson,
  StreamingRestorer,
  transform,
  validatePolicy,
} from "../src/index.js";

test("catalog and preset actions match the compatibility manifest", async () => {
  const manifest = JSON.parse(await readFile(new URL("../../../contracts/compatibility-v1.json", import.meta.url), "utf8"));
  assert.deepEqual(entityTypes, manifest.entities);
  for (const [name, expected] of Object.entries(manifest.preset_overrides) as [string, Record<string, string>][]) {
    const policy = policyFromPreset(name);
    for (const [entity, action] of Object.entries(expected)) {
      assert.equal(policy.rules.find((rule) => rule.entity === entity)?.action, action);
    }
  }
});

test("server policy JSON converts to the browser core schema", () => {
  const policy = policyFromServer({
    name: "downloaded",
    version: 1,
    rules: [{
      entity: "EMAIL_ADDRESS",
      action: "redact",
      enabled: true,
      reversible: false,
      minimum_confidence_ppm: 990_001,
      priority: 0,
      locale: "en-US",
      scopes: ["*"],
      required_detectors: [],
    }],
    allow_terms: [],
    deny_terms: {},
    fail_closed: true,
    mapping_retention_seconds: 86_400,
    audit_retention_seconds: 2_592_000,
  });
  assert.equal(policy.rules[0]?.minimumConfidencePpm, 990_001);
  assert.deepEqual(detect("a@example.com", policy), []);
});

test("shared detection fixtures use UTF-8 byte offsets", async () => {
  const fixtures = JSON.parse(await readFile(new URL("../../../conformance/core-v1.json", import.meta.url), "utf8"));
  for (const fixture of fixtures.detection) {
    const found = detect(fixture.text, policyFromPreset(fixture.preset));
    assert.deepEqual(
      found.map(({ entity, start, end, value }) => ({ entity, start, end, value })),
      fixture.expected,
    );
  }
});

test("keyless reversible transform blocks", async () => {
  const result = await transform("a@example.com", policyFromPreset("balanced"));
  assert.equal(result.state, "blocked");
  assert.equal(result.text, null);
});

test("keyless hash uses an ephemeral key instead of a reusable raw digest", async () => {
  const policy = policyFromPreset("balanced");
  policy.rules = [{
    entity: "EMAIL_ADDRESS",
    action: "hash",
    enabled: true,
    reversible: false,
    minimumConfidencePpm: 500_000,
    priority: 0,
    locale: "en-US",
    scopes: ["*"],
    requiredDetectors: [],
  }];
  const first = await transform("a@example.com", policy);
  const second = await transform("a@example.com", policy);
  assert.match(first.text!, /^sha256:[0-9a-f]{48}$/u);
  assert.match(second.text!, /^sha256:[0-9a-f]{48}$/u);
  assert.notEqual(first.text, second.text);
});

test("client transform is bijective within a call", async () => {
  const source = "a@example.com then a@example.com";
  const result = await transform(source, policyFromPreset("balanced"), crypto.getRandomValues(new Uint8Array(32)));
  assert.equal(result.state, "protected");
  assert.equal(new Set(result.detections.map((item) => item.replacement)).size, 1);
  assert.equal(restore(result.text!, result.reverse), source);
});

test("invalid policies and unavailable required detectors block", async () => {
  const duplicate = policyFromPreset("balanced");
  duplicate.rules.push({ ...duplicate.rules[0]! });
  assert.throws(() => validatePolicy(duplicate), /duplicate rule/u);
  assert.equal((await transform("a@example.com", duplicate, new Uint8Array(32))).state, "blocked");

  const invalid = policyFromPreset("balanced");
  const email = invalid.rules.find((rule) => rule.entity === "EMAIL_ADDRESS")!;
  email.action = "redact";
  email.reversible = true;
  assert.equal((await transform("a@example.com", invalid, new Uint8Array(32))).state, "blocked");

  const required = policyFromPreset("balanced");
  required.rules.find((rule) => rule.entity === "EMAIL_ADDRESS")!.requiredDetectors = ["missing-v1"];
  const result = await transform("a@example.com", required, new Uint8Array(32));
  assert.equal(result.state, "blocked");
  assert.match(result.reason!, /required detectors unavailable/u);
});

test("tagged-token restoration has bounded case and ASCII-space tolerance", async () => {
  const source = "a@example.com";
  const result = await transform(source, policyFromPreset("balanced"), crypto.getRandomValues(new Uint8Array(32)));
  const spaced = result.text!.toLowerCase().replaceAll("|", " | ");
  assert.equal(restore(spaced, result.reverse), source);
  const tabbed = result.text!.replaceAll("|", "\t|\t");
  const wide = result.text!.replaceAll("|", "  |  ");
  assert.equal(restore(tabbed, result.reverse), tabbed);
  assert.equal(restore(wide, result.reverse), wide);
  const unicodeCase = result.text!.replace("SS", "ſſ");
  assert.equal(restore(unicodeCase, result.reverse), unicodeCase);
});

test("reversible generalized collisions remain bijective", async () => {
  const policy = policyFromPreset("balanced");
  const date = policy.rules.find((rule) => rule.entity === "DATE_TIME")!;
  date.reversible = true;
  const source = "2024-01-01 then 2024-02-02";
  const result = await transform(source, policy, crypto.getRandomValues(new Uint8Array(32)));
  assert.equal(new Set(result.detections.map((item) => item.replacement)).size, 2);
  assert.equal(restore(result.text!, result.reverse), source);
});

test("shared deterministic operator fixtures match", async () => {
  const fixtures = JSON.parse(await readFile(new URL("../../../conformance/core-v1.json", import.meta.url), "utf8"));
  for (const fixture of fixtures.operators) {
    const policy = policyFromPreset("balanced");
    policy.rules = [
      {
        entity: fixture.entity,
        action: fixture.action,
        enabled: true,
        reversible: false,
        minimumConfidencePpm: 500_000,
        priority: 0,
        locale: "en-US",
        scopes: ["*"],
        requiredDetectors: [],
      },
    ];
    const key = Uint8Array.from(Buffer.from(fixture.key, "base64url"));
    const result = await transform(fixture.text, policy, key);
    assert.equal(result.text, fixture.expected, fixture.name);
  }
});

test("standardized synthetic values remain detectably format-valid", async () => {
  const cases = [
    ["EMAIL_ADDRESS", "source@example.com"],
    ["PHONE_NUMBER", "+1-212-555-1234"],
    ["CREDIT_CARD", "4111 1111 1111 1111"],
    ["US_SSN", "123-45-6789"],
    ["IP_ADDRESS", "203.0.113.7"],
    ["API_KEY", "sk-abcdefghijklmnopqrstuvwxyz"],
    ["DATE_TIME", "2026-09-21"],
    ["MONEY", "$1,234.00"],
    ["URL", "https://source.example/path"],
    ["IBAN_CODE", "GB82 WEST 1234 5698 7654 32"],
    ["US_BANK_NUMBER", "021000021"],
  ] as const;
  for (const [entity, source] of cases) {
    const policy = policyFromPreset("balanced");
    policy.rules = [{
      entity,
      action: "synthetic",
      enabled: true,
      reversible: false,
      minimumConfidencePpm: 500_000,
      priority: 0,
      locale: "en-US",
      scopes: ["*"],
      requiredDetectors: [],
    }];
    const result = await transform(source, policy);
    assert.equal(result.state, "protected", entity);
    assert.doesNotMatch(result.text!, /SYNTHETIC_/u, entity);
    assert.deepEqual(detect(result.text!, policy).map((item) => item.value), [result.text], entity);
  }
});

test("stream restorer handles every split and single-character chunks", async () => {
  const source = "prefix a@example.com suffix";
  const result = await transform(source, policyFromPreset("balanced"), new Uint8Array(32));
  for (let split = 0; split <= result.text!.length; split += 1) {
    const stream = new StreamingRestorer(result.reverse);
    assert.equal(stream.feed(result.text!.slice(0, split)) + stream.feed(result.text!.slice(split)) + stream.finish(), source);
  }
  const stream = new StreamingRestorer(result.reverse);
  assert.equal([...result.text!].map((char) => stream.feed(char)).join("") + stream.finish(), source);
  assert.throws(() => stream.finish(), /already finished/u);
});

test("stream restorer handles reversible composite surrogates and bounded variants", async () => {
  const source = "2024-01-01";
  const policy = policyFromPreset("healthcare");
  const result = await transform(source, policy, new Uint8Array(32));
  assert.match(result.text!, /\[\[PG1\|/u);
  for (const protectedText of [result.text!, result.text!.toLowerCase().replaceAll("|", " | ")]) {
    const stream = new StreamingRestorer(result.reverse);
    assert.equal([...protectedText].map((char) => stream.feed(char)).join("") + stream.finish(), source);
  }
});

test("maximum-domain generalized email streams exactly", async () => {
  const domain = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)].join(".");
  const source = `x@${domain}`;
  const policy = policyFromPreset("balanced");
  const rule = policy.rules.find((item) => item.entity === "EMAIL_ADDRESS")!;
  rule.action = "generalize";
  rule.reversible = true;
  const result = await transform(source, policy, new Uint8Array(32));
  assert.ok(result.text!.length < StreamingRestorer.maxCandidateChars);
  const stream = new StreamingRestorer(result.reverse);
  assert.equal([...result.text!].map((char) => stream.feed(char)).join("") + stream.finish(), source);
});

test("money recognition is bounded and generalization is compact", async () => {
  const policy = policyFromPreset("balanced");
  const source = `$1234 and $${"9".repeat(300)}`;
  const found = detect(source, policy);
  assert.deepEqual(found.filter((item) => item.entity === "MONEY").map((item) => item.value), ["$1234"]);
  const result = await transform("$1234", policy, new Uint8Array(32));
  assert.equal(result.text, "$~10^3");
});

test("stream restorer bounds malformed suffixes and leaves foreign tags", () => {
  const foreign = "[[PG1|EMAIL_ADDRESS|AAAAAAAAAAAAAAAAAAAAAAAAAA|AAAAAAAAAAAAAAAA]]";
  const stream = new StreamingRestorer({});
  const candidate = `${foreign} [[${"A".repeat(1000)}`;
  const emitted = stream.feed(candidate);
  assert.match(emitted, /PG1/u);
  assert.equal(emitted.length, candidate.length - StreamingRestorer.maxCandidateChars);
  assert.equal(stream.finish().length, StreamingRestorer.maxCandidateChars);
});

test("stream restorer bounds malformed composite candidates", async () => {
  const result = await transform("2024-01-01", policyFromPreset("healthcare"), new Uint8Array(32));
  const prefix = result.text!.split("[[", 1)[0]!;
  const stream = new StreamingRestorer(result.reverse);
  const emitted = stream.feed(`${prefix}[[${"A".repeat(1000)}`);
  assert.ok(emitted.length > 0);
  assert.equal(stream.finish().length, StreamingRestorer.maxCandidateChars);
});

test("recursive restore leaves blocked subtrees untouched", async () => {
  const source = "a@example.com";
  const result = await transform(source, policyFromPreset("balanced"), new Uint8Array(32));
  const value = { display: result.text, tool: { arguments: result.text }, list: [result.text, 3] };
  assert.deepEqual(restoreJson(value, result.reverse, new Set(["/tool/arguments"])), {
    display: source,
    tool: { arguments: result.text },
    list: [source, 3],
  });
});
