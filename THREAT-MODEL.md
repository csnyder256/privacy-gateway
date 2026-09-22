# Threat Model

Privacy Gateway reduces how much sensitive data crosses an application boundary. It does not
prove that an arbitrary dataset is legally anonymous, and it cannot protect a value it does not
detect or a route that does not use the gateway.

## Assets

- Original values and structured source records.
- Server master keys, client restoration keys, and signed-webhook secrets.
- Reversible mappings and restoration capsules.
- Policy definitions and audit classifications, which may themselves be sensitive.
- Downstream provider credentials. They are forwarded only to the configured provider and are
  never placed in capsules or audit events.

## Trust boundaries

```text
application/client       privacy boundary              configured provider
original + policy  ->  detect / transform  ->  protected prompt only
       ^                 vault or capsule                 |
       +------------- deliberate display restore <--------+
```

Client-capsule mode keeps reversible material in an AEAD-encrypted capsule held by the client.
Local-vault mode stores originals as AES-GCM ciphertext under an operator-supplied key. Proxy
mode sees plaintext inside the self-hosted gateway process and uses a fixed operator-configured
upstream. One-way policies retain no restoration mapping for irreversible actions.

## Defended threats

- Accidental PII disclosure to configured AI/API providers for supported payload shapes.
- Plaintext mapping disclosure from a copied SQLite database without the master key.
- Silent detector/key failure: required failures produce a blocked result.
- Ambiguous reversal: active replacements are unique per session.
- Basic SSRF and credential confusion: provider URLs are not request-controlled, redirects are
  disabled, HTTPS is required except for loopback, and forwarded headers are allowlisted.
- Webhook tampering and short-window replay through HMAC signatures, timestamps, and delivery IDs.

## Residual risks

- False negatives, novel identifiers, unsupported languages, and deliberately obfuscated input.
- Values configured as `keep`, disabled, allowed, or outside the selected scope.
- Compromise of the client, gateway process, key store, or source application.
- Traffic or audit metadata, prompt meaning, and re-identification through retained context.
- Replay across gateway restarts for the in-memory v0.1 webhook verifier.
- SSE provider streaming, images/OCR, OIDC multi-tenancy, and executable tool restoration are not
  supported in v0.1. Unsupported proxy shapes block; they are not passed through.
- SQLite row deletion is not a claim of physical erasure from storage media or backups.

## Operator responsibilities

Route every outbound path through a tested adapter, keep keys in a secret manager, terminate TLS
at a trusted boundary, restrict network egress to intended providers, run `privacy-gateway verify`,
review false positives/negatives with synthetic fixtures, purge expired data, and test restore
behavior before production use. See [operations](docs/operations.md) and
[limitations](docs/limitations.md).
