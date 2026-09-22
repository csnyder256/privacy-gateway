# Agent Guide: Set Up Privacy Gateway for This Platform

This file is deliberately written as an execution protocol. A non-technical user can give
an AI coding agent this repository and say:

> Read `AGENT-GUIDE.md` and help me set Privacy Gateway up for my platform.

The agent should not assume an architecture, copy production data into a prompt, or claim
the boundary works before running the verification probes.

## Agent operating rules

1. Read `README.md`, `docs/threat-boundaries.md`, and `contracts/compatibility-v1.json`.
2. Inspect the target platform without printing secrets. Locate its language, deployment
   model, outbound AI/API calls, streaming behavior, structured payloads, and secret manager.
3. Ask the short setup interview below. Explain unfamiliar terms in plain language.
4. Propose the smallest integration that covers every identified outbound boundary.
5. Generate a policy file and show the user a before/after preview made from fake data.
6. Keep keys out of source control, logs, command history, images, and chat transcripts.
7. Implement in a branch. Do not alter unrelated code or deployment settings.
8. Run unit tests plus `privacy-gateway verify` before describing the integration as working.
9. Report what is verified, what is configured but not exercised, and any boundary still able
   to send unprotected data.

## Setup interview

Ask these questions one at a time when needed; infer answers from the repository when safe.

1. **What leaves the platform?** AI prompts, documents, database rows, images, logs,
   webhooks, tool arguments, or something else?
2. **Where does it go?** OpenAI-compatible API, Anthropic, a different HTTP service, an
   agent harness, an MCP server, a data warehouse, or multiple destinations?
3. **What must be protected?** Offer the five presets, then let the user change every entity
   and action. Never reduce the choice to a single on/off toggle.
4. **Must responses contain the original values again?** If no, prefer irreversible actions.
   If yes, explain client-held capsules versus a local encrypted vault.
5. **How long may mappings and audit decisions exist?** Record an explicit duration.
6. **What languages/locales occur?** Select recognizer models and formatting policies.
7. **What should happen if detection is unavailable?** Recommend blocking the outbound call.
8. **Where are secrets managed?** Reuse the platform's existing secret manager; never add a
   plaintext `.env` containing a real key to the repository.

## Choose an integration

Use the first option that fits. Avoid a network hop when an in-process library provides the
same boundary.

| Platform shape | Preferred integration |
|---|---|
| Python application | `privacy_gateway` package around the outbound client |
| Browser or Node application | `@privacy-gateway/core` with a client-held key |
| Existing OpenAI/Anthropic client fleet | compatible proxy with an explicit endpoint allowlist |
| Agent harness | MCP tools plus middleware around tool arguments and results |
| Framework-neutral HTTP service | Python ASGI middleware, TypeScript HTTP client, or webhook adapter |
| CLI/batch job | `privacy-gateway anonymize` or the Python SDK |

## Minimum safe Python integration

```python
from privacy_gateway.engine import PrivacyEngine
from privacy_gateway.vault import Vault

# Obtain the key from the platform's secret manager. Do not hard-code it.
gateway = PrivacyEngine(Vault("/var/lib/privacy-gateway/vault.db", master_key))

protected = gateway.transform(user_text, preset="balanced")
if protected.state.value != "protected":
    raise RuntimeError(protected.reason or "privacy boundary blocked the request")

external_response = call_external_system(protected.text)
safe_response = gateway.restore(external_response, protected.session_id)
```

The explicit state check is mandatory. Never substitute the original text when a transform
returns `blocked`.

## Client-held capsule integration

Choose this when originals should not be persisted by the gateway:

1. Generate a random 32-byte key in the client or retrieve it from client-local secure storage.
2. Send only the public policy plus the restore-key input required by the local integration.
3. Keep the returned capsule with the request context on the client.
4. Restore only display text. Do not automatically restore executable tool arguments,
   database commands, URLs, or webhook destinations.
5. Delete the capsule and key at the configured expiry.

## Policy checklist

For every enabled entity, record:

- action: `keep`, `redact`, `label`, `tokenize`, `hash`, `generalize`, or `synthetic`;
- minimum confidence in integer parts per million;
- whether restoration is required;
- locale and scope/path restrictions;
- required detectors;
- mapping and audit retention.

Add known false positives to an allow list and business-specific sensitive terms to a deny
list. Use fake examples in committed tests. Do not commit customer data as fixtures.

## Required verification

Run from the repository root:

```bash
pytest
ruff check src tests
ruff format --check src tests
npm run check
npm test
npm run build
privacy-gateway verify
```

Then add target-platform tests that prove:

- a protected entity cannot reach a mocked outbound client in plaintext;
- a required detector failure prevents the outbound call;
- response restoration works for the chosen trust mode;
- streaming chunks cannot leak a partial original or unverified surrogate;
- expired mappings are unavailable and purgeable;
- logs, traces, exceptions, and audit rows contain no original sample value;
- every alternate outbound path is either protected or explicitly documented as out of scope.

## Handoff format

End the setup with this exact distinction:

- **Verified:** commands and probes that passed, with their scope.
- **Configured:** deployment, proxy, or secret-manager wiring that exists but was not exercised.
- **Not covered:** payload types or outbound paths that remain outside the privacy boundary.
- **Rollback:** the focused steps needed to disable the integration without losing unrelated data.

Do not call a configured deployment healthy without checking its live health endpoint and one
non-sensitive end-to-end probe.
