const entities = [
  ["EMAIL_ADDRESS", "Email address", "name@example.com"],
  ["PHONE_NUMBER", "Phone number", "+1-202-555-0182"],
  ["CREDIT_CARD", "Payment card", "Luhn-valid card numbers"],
  ["US_SSN", "US Social Security number", "AAA-GG-SSSS"],
  ["IP_ADDRESS", "IP address", "IPv4 and IPv6"],
  ["API_KEY", "API key or secret", "OpenAI, GitHub, AWS"],
  ["PERSON", "Person name", "ML recognizer"],
  ["ORGANIZATION", "Organization", "ML recognizer"],
  ["LOCATION", "Location", "ML recognizer"],
  ["DATE_TIME", "Date or time", "Locale-aware"],
  ["MONEY", "Money amount", "Locale-aware"],
  ["URL", "Web URL", "HTTP and HTTPS"],
  ["IBAN_CODE", "IBAN", "Checksum validated"],
  ["US_BANK_NUMBER", "US routing number", "ABA checksum"],
  ["PASSPORT", "Passport", "Recognizer extension"],
  ["DRIVER_LICENSE", "Driver license", "Recognizer extension"],
  ["MEDICAL_LICENSE", "Medical license", "Recognizer extension"],
];
const overrides = {
  balanced: { API_KEY: "redact", DATE_TIME: "generalize", MONEY: "generalize", URL: "keep" },
  strict: { API_KEY: "redact", CREDIT_CARD: "redact", US_SSN: "redact", IBAN_CODE: "redact", US_BANK_NUMBER: "redact", PASSPORT: "redact", DRIVER_LICENSE: "redact", MEDICAL_LICENSE: "redact" },
  healthcare: { API_KEY: "redact", CREDIT_CARD: "redact", US_SSN: "redact", IBAN_CODE: "redact", US_BANK_NUMBER: "redact", PASSPORT: "redact", DRIVER_LICENSE: "redact", MEDICAL_LICENSE: "redact", PERSON: "synthetic", LOCATION: "synthetic", DATE_TIME: "synthetic" },
  finance: { API_KEY: "redact", US_SSN: "redact", PASSPORT: "redact", DRIVER_LICENSE: "redact", MEDICAL_LICENSE: "redact", CREDIT_CARD: "tokenize", IBAN_CODE: "tokenize", US_BANK_NUMBER: "tokenize", MONEY: "synthetic" },
  devsecops: { API_KEY: "redact", EMAIL_ADDRESS: "tokenize", PHONE_NUMBER: "tokenize", IP_ADDRESS: "tokenize", PERSON: "keep", ORGANIZATION: "keep", LOCATION: "keep", DATE_TIME: "keep", MONEY: "keep", URL: "keep" },
};
const actions = ["keep", "redact", "label", "tokenize", "hash", "generalize", "synthetic"];
const irreversible = new Set(["keep", "redact", "label", "hash"]);
const draftKey = "privacy-gateway-policy-draft-v1";
let step = 1;
let preset = "balanced";
let mode = "client";
let snippet = "python";
let initialized = false;
const rules = new Map();
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function lines(value) {
  return value.split(/\r?\n/u).map((item) => item.trim()).filter(Boolean);
}
function denyTerms() {
  const known = new Set(entities.map(([entity]) => entity));
  return Object.fromEntries(lines($("#deny-terms").value).map((item) => {
    const split = item.lastIndexOf(":");
    return [item.slice(0, split).trim(), item.slice(split + 1).trim().toUpperCase()];
  }).filter(([term, entity]) => term && known.has(entity)));
}
function policy() {
  const days = Math.max(1, Math.min(365, Number($("#retention").value) || 1));
  const auditDays = Math.max(1, Math.min(365, Number($("#audit-retention").value) || 1));
  return {
    name: preset,
    version: 1,
    rules: entities.map(([entity]) => ({ entity, ...rules.get(entity), locale: $("#locale").value, scopes: ["*"], required_detectors: [] })),
    allow_terms: lines($("#allow-terms").value),
    deny_terms: denyTerms(),
    fail_closed: true,
    mapping_retention_seconds: days * 86400,
    audit_retention_seconds: auditDays * 86400,
  };
}
function saveDraft() {
  if (!initialized) return;
  try {
    localStorage.setItem(draftKey, JSON.stringify({ preset, mode, locale: $("#locale").value, retention: $("#retention").value, auditRetention: $("#audit-retention").value, allowTerms: $("#allow-terms").value, denyTerms: $("#deny-terms").value, rules: Object.fromEntries(rules) }));
  } catch { /* Optional policy-only draft; source samples are never persisted. */ }
}
function applyPreset(name, persist = true) {
  preset = name;
  for (const [entity] of entities) {
    const action = overrides[name][entity] || "tokenize";
    rules.set(entity, { enabled: true, action, reversible: action === "tokenize" || (name === "healthcare" && ["PERSON", "LOCATION", "DATE_TIME"].includes(entity)), minimum_confidence_ppm: ["PERSON", "ORGANIZATION", "LOCATION"].includes(entity) ? 650000 : 500000 });
  }
  if (mode === "oneway") enforceOneWay();
  renderEntities();
  updatePreview();
  if (persist) saveDraft();
}
function enforceOneWay() {
  for (const rule of rules.values()) {
    if (rule.action === "tokenize") rule.action = "redact";
    rule.reversible = false;
  }
}
function renderEntities(filter = "") {
  $("#entity-table").innerHTML = entities.filter(([id, label]) => `${id}${label}`.toLowerCase().includes(filter.toLowerCase())).map(([id, label, help]) => {
    const rule = rules.get(id);
    return `<div class="entity-row ${rule.enabled ? "" : "off"}" data-entity="${id}">
      <label class="switch"><span class="sr-only">Enable ${label}</span><input class="enabled" type="checkbox" aria-label="Enable ${label}" ${rule.enabled ? "checked" : ""}><i></i></label>
      <span><strong>${label}</strong><small>${help}</small></span>
      <label><span class="sr-only">Action for ${label}</span><select class="action" aria-label="Action for ${label}">${actions.map((action) => `<option ${action === rule.action ? "selected" : ""} ${mode === "oneway" && action === "tokenize" ? "disabled" : ""}>${action}</option>`).join("")}</select></label>
      <label class="reversible"><input type="checkbox" class="reverse" ${rule.reversible ? "checked" : ""} ${mode === "oneway" || irreversible.has(rule.action) ? "disabled" : ""}> restore</label>
    </div>`;
  }).join("");
}
function replacement(entity, action, index, value) {
  if (action === "keep") return value;
  if (action === "redact") return `[REDACTED:${entity}]`;
  if (action === "label") return `<${entity}>`;
  if (action === "hash") return `sha256:${String(index).padStart(8, "0")}…`;
  if (action === "generalize") return entity === "DATE_TIME" ? (value.match(/20\d{2}/u) || ["[DATE]"])[0] : `[${entity}]`;
  if (action === "synthetic") return entity === "EMAIL_ADDRESS" ? `person${index}@example.test` : `[SYNTHETIC:${entity}:${index}]`;
  return `[[PG1|${entity}|DEMO${String(index).padStart(4, "0")}…]]`;
}
function validLuhn(value) {
  const digits = [...value].filter((character) => /\d/u.test(character)).map(Number);
  if (digits.length < 13 || digits.length > 19) return false;
  const parity = digits.length % 2;
  return digits.reduce((sum, digit, index) => sum + (index % 2 === parity ? (digit > 4 ? digit * 2 - 9 : digit * 2) : digit), 0) % 10 === 0;
}
function updatePreview() {
  const patterns = [[/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/giu, "EMAIL_ADDRESS"], [/(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}/gu, "PHONE_NUMBER"], [/(?:\d[ -]*?){13,19}/gu, "CREDIT_CARD"], [/(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})/gu, "API_KEY"]];
  const source = $("#sample-input")?.value || "";
  const candidates = [];
  const allowed = new Set(lines($("#allow-terms").value).map((item) => item.toLowerCase()));
  for (const [regex, entity] of patterns) {
    const rule = rules.get(entity);
    if (!rule?.enabled || rule.action === "keep") continue;
    if (rule.minimum_confidence_ppm > 990000) continue;
    regex.lastIndex = 0;
    for (const match of source.matchAll(regex)) {
      if (entity === "CREDIT_CARD" && !validLuhn(match[0])) continue;
      if (!allowed.has(match[0].toLowerCase())) candidates.push({ entity, start: match.index, end: match.index + match[0].length, value: match[0], rule });
    }
  }
  for (const [term, entity] of Object.entries(denyTerms())) {
    const rule = rules.get(entity);
    if (!rule?.enabled || rule.action === "keep" || allowed.has(term.toLowerCase())) continue;
    let start = source.toLowerCase().indexOf(term.toLowerCase());
    while (start >= 0) {
      candidates.push({ entity, start, end: start + term.length, value: source.slice(start, start + term.length), rule });
      start = source.toLowerCase().indexOf(term.toLowerCase(), start + term.length);
    }
  }
  const priority = { API_KEY: 0, EMAIL_ADDRESS: 1, PHONE_NUMBER: 2, CREDIT_CARD: 3 };
  candidates.sort((left, right) => (priority[left.entity] ?? -1) - (priority[right.entity] ?? -1) || left.start - right.start || (right.end - right.start) - (left.end - left.start));
  const accepted = [];
  for (const item of candidates) if (!accepted.some((other) => item.start < other.end && other.start < item.end)) accepted.push(item);
  accepted.sort((left, right) => left.start - right.start);
  let text = "";
  let cursor = 0;
  let count = 0;
  const summary = {};
  for (const item of accepted) {
    count += 1;
    text += source.slice(cursor, item.start) + replacement(item.entity, item.rule.action, count, item.value);
    cursor = item.end;
    summary[item.entity] = (summary[item.entity] || 0) + 1;
  }
  text += source.slice(cursor);
  $("#sample-output").value = text;
  $("#preview-summary").innerHTML = Object.entries(summary).map(([entity, total]) => `<span>${entity.replaceAll("_", " ")} · ${total}</span>`).join("") || "<span>No configured sample values detected</span>";
  $("#policy-json").textContent = JSON.stringify(policy(), null, 2);
}
const modeDescriptions = {
  client: "Client-held capsule: run the core beside your application; no original mapping is stored by the gateway.",
  local: "Local encrypted vault: originals are encrypted in SQLite under your operator-held master key.",
  selfhosted: "Self-hosted network vault: your central gateway owns encrypted mappings; v0.1 is single-operator, not managed multi-tenant.",
  oneway: "One-way: the downloaded policy contains no reversible rules or restoration key.",
};
function pythonSnippet() {
  const shared = `from pathlib import Path\nfrom privacy_gateway.models import Policy\n\npolicy = Policy.model_validate_json(Path("privacy-gateway-policy.json").read_text())`;
  if (mode === "client") return `pip install privacy-gateway\n\n${shared}\nfrom privacy_gateway.crypto import generate_key\nfrom privacy_gateway.engine import PrivacyEngine\nfrom privacy_gateway.vault import Vault\n\nclient_key = generate_key()  # keep in client-local secure storage\ngateway = PrivacyEngine(Vault("./privacy-decisions.db"))\nresult = gateway.transform(text, policy=policy, restore_key=client_key)\nif result.state.value != "protected": raise RuntimeError(result.reason)`;
  if (mode === "oneway") return `pip install privacy-gateway\n\n${shared}\nfrom privacy_gateway.engine import PrivacyEngine\nfrom privacy_gateway.vault import Vault\n\nresult = PrivacyEngine(Vault("./privacy-decisions.db")).transform(text, policy=policy)\nif result.state.value != "protected": raise RuntimeError(result.reason)`;
  if (mode === "local") return `pip install privacy-gateway\n\n${shared}\nfrom privacy_gateway.crypto import key_from_env\nfrom privacy_gateway.engine import PrivacyEngine\nfrom privacy_gateway.vault import Vault\n\ngateway = PrivacyEngine(Vault("./data/privacy.db", key_from_env()))\nresult = gateway.transform(text, policy=policy)\nif result.state.value != "protected": raise RuntimeError(result.reason)`;
  return `pip install privacy-gateway\n\n${shared}\nfrom privacy_gateway import PrivacyGatewayClient\n\nwith PrivacyGatewayClient("https://privacy-gateway.internal") as gateway:\n    session = gateway.create_session(policy=policy)\n    result = gateway.transform(text, session_id=session["session_id"])\n    if result.state.value != "protected": raise RuntimeError(result.reason)`;
}
function typescriptSnippet() {
  if (mode === "client" || mode === "oneway") return `npm install @privacy-gateway/core\n\nimport { policyFromServer, transform, type ServerPolicy } from "@privacy-gateway/core";\nimport rawPolicy from "./privacy-gateway-policy.json" with { type: "json" };\n\nconst policy = policyFromServer(rawPolicy as ServerPolicy);\n${mode === "client" ? "const clientKey = crypto.getRandomValues(new Uint8Array(32));\n" : ""}const result = await transform(text, policy, ${mode === "client" ? "clientKey" : "undefined"});\nif (result.state !== "protected") throw new Error(result.reason ?? "blocked");`;
  return `npm install @privacy-gateway/client\n\nimport { PrivacyGatewayClient } from "@privacy-gateway/client";\nimport policy from "./privacy-gateway-policy.json" with { type: "json" };\n\nconst gateway = new PrivacyGatewayClient({ baseUrl: "${mode === "local" ? "http://127.0.0.1:8787" : "https://privacy-gateway.internal"}" });\nconst session = await gateway.createSession({ policy });\nconst result = await gateway.transform(text, { sessionId: session.session_id });\nif (result.state !== "protected") throw new Error(result.reason ?? "blocked");`;
}
function vaultOnly(body) {
  return ["client", "oneway"].includes(mode) ? `# This adapter needs gateway-owned restoration in v0.1.\n# Select Local encrypted vault or Self-hosted network vault.` : body;
}
const snippets = {
  python: pythonSnippet,
  typescript: typescriptSnippet,
  docker: () => ["client", "oneway"].includes(mode) ? `# ${modeDescriptions[mode]}\n# No gateway container is required for this mode.` : `export PRIVACY_GATEWAY_MASTER_KEY="$(privacy-gateway keygen)"\ndocker compose up --build\ncurl --fail http://127.0.0.1:8787/v1/health\njq -n --slurpfile policy privacy-gateway-policy.json '{policy:$policy[0]}' | curl --json @- http://127.0.0.1:8787/v1/sessions`,
  mcp: () => vaultOnly(`Pass the downloaded policy JSON as protect_text's policy argument.\n\n{"mcpServers":{"privacy-gateway":{"command":"privacy-gateway-mcp","env":{"PRIVACY_GATEWAY_DB":"./data/privacy.db","PRIVACY_GATEWAY_MASTER_KEY":"<from secret manager>"}}}}`),
  openai: () => vaultOnly(`from pathlib import Path\nimport httpx\nfrom openai import OpenAI\n\npolicy = __import__("json").loads(Path("privacy-gateway-policy.json").read_text())\nsession = httpx.post("http://127.0.0.1:8787/v1/sessions", json={"policy": policy}).json()\nclient = OpenAI(\n    base_url="http://127.0.0.1:8787/proxy/openai/v1",\n    default_headers={"X-Privacy-Session-ID": session["session_id"]},\n)`),
  anthropic: () => vaultOnly(`from pathlib import Path\nimport httpx\nfrom anthropic import Anthropic\n\npolicy = __import__("json").loads(Path("privacy-gateway-policy.json").read_text())\nsession = httpx.post("http://127.0.0.1:8787/v1/sessions", json={"policy": policy}).json()\nclient = Anthropic(\n    base_url="http://127.0.0.1:8787/proxy/anthropic/v1",\n    default_headers={"X-Privacy-Session-ID": session["session_id"]},\n)`),
  webhook: () => `from privacy_gateway.adapters import WebhookVerifier\n\nsigner = WebhookVerifier(secret_from_your_secret_manager)\nheaders = signer.sign(json_body_bytes)`,
  synthetic: () => `privacy-gateway synthesize source.csv synthetic.csv \\\n  --rows 1000 --schema-output schema.json --report-output report.json`,
};
function renderStep() {
  $$(".wizard-step").forEach((element) => element.classList.toggle("active", Number(element.dataset.step) === step));
  $$('[data-step-indicator]').forEach((element) => {
    const number = Number(element.dataset.stepIndicator);
    element.classList.toggle("active", number === step);
    element.classList.toggle("complete", number < step);
    element.querySelector("b").textContent = number < step ? "✓" : String(number);
  });
  $("#back").disabled = step === 1;
  $("#next").textContent = step === 5 ? "Start over" : "Continue";
  $("#step-status").textContent = `${step} / 5`;
  if (step === 4) updatePreview();
  if (step === 5) {
    $("#mode-summary").textContent = modeDescriptions[mode];
    $("#install-snippet").textContent = snippets[snippet]();
  }
}
document.addEventListener("click", (event) => {
  const presetButton = event.target.closest("[data-preset]");
  if (presetButton) {
    $$('[data-preset]').forEach((element) => element.classList.remove("active"));
    presetButton.classList.add("active");
    applyPreset(presetButton.dataset.preset);
  }
  const modeButton = event.target.closest("[data-mode]");
  if (modeButton) {
    $$('[data-mode]').forEach((element) => element.classList.remove("active"));
    modeButton.classList.add("active");
    mode = modeButton.dataset.mode;
    if (mode === "oneway") enforceOneWay();
    renderEntities(); updatePreview(); saveDraft();
    if (step === 5) renderStep();
  }
  const tab = event.target.closest("[data-snippet]");
  if (tab) {
    $$('[data-snippet]').forEach((element) => element.classList.remove("active"));
    tab.classList.add("active"); snippet = tab.dataset.snippet; $("#install-snippet").textContent = snippets[snippet]();
  }
});
$("#entity-table").addEventListener("change", (event) => {
  const row = event.target.closest("[data-entity]");
  const rule = rules.get(row.dataset.entity);
  if (event.target.classList.contains("enabled")) rule.enabled = event.target.checked;
  if (event.target.classList.contains("action")) { rule.action = event.target.value; if (mode === "oneway" && rule.action === "tokenize") rule.action = "redact"; if (mode === "oneway" || irreversible.has(rule.action)) rule.reversible = false; else if (rule.action === "tokenize") rule.reversible = true; }
  if (event.target.classList.contains("reverse")) rule.reversible = mode === "oneway" ? false : event.target.checked;
  renderEntities($("#entity-filter").value); updatePreview(); saveDraft();
});
$("#entity-filter").addEventListener("input", (event) => renderEntities(event.target.value));
$("#sample-input").addEventListener("input", updatePreview);
for (const selector of ["#locale", "#retention", "#audit-retention", "#allow-terms", "#deny-terms"]) $(selector).addEventListener("input", () => { updatePreview(); saveDraft(); });
$("#toggle-all").addEventListener("click", () => {
  const any = [...rules.values()].some((rule) => rule.enabled);
  for (const rule of rules.values()) rule.enabled = !any;
  $("#toggle-all").textContent = any ? "Enable all" : "Disable all";
  renderEntities(); updatePreview(); saveDraft();
});
$("#next").addEventListener("click", () => { step = step === 5 ? 1 : step + 1; renderStep(); });
$("#back").addEventListener("click", () => { if (step > 1) step -= 1; renderStep(); });
$("#copy-snippet").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("#install-snippet").textContent); $("#copy-snippet").textContent = "Copied"; setTimeout(() => { $("#copy-snippet").textContent = "Copy"; }, 1200); }
  catch { $("#copy-snippet").textContent = "Select and copy"; }
});
$("#download-policy").addEventListener("click", () => {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([`${JSON.stringify(policy(), null, 2)}\n`], { type: "application/json" }));
  link.download = "privacy-gateway-policy.json"; link.click(); URL.revokeObjectURL(link.href);
});
applyPreset("balanced", false);
try {
  const draft = JSON.parse(localStorage.getItem(draftKey));
  if (draft && overrides[draft.preset] && draft.rules) {
    preset = draft.preset; mode = ["client", "local", "selfhosted", "oneway"].includes(draft.mode) ? draft.mode : "client";
    for (const [entity] of entities) if (draft.rules[entity]) rules.set(entity, draft.rules[entity]);
    $("#locale").value = draft.locale || "en-US"; $("#retention").value = draft.retention || "1"; $("#audit-retention").value = draft.auditRetention || "30";
    $("#allow-terms").value = draft.allowTerms || ""; $("#deny-terms").value = draft.denyTerms || "";
    $$('[data-preset]').forEach((element) => element.classList.toggle("active", element.dataset.preset === preset));
    $$('[data-mode]').forEach((element) => element.classList.toggle("active", element.dataset.mode === mode));
  }
} catch { /* Ignore unavailable or malformed local drafts. */ }
initialized = true;
renderEntities(); updatePreview(); renderStep();
