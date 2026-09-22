<div align="center">

# Privacy Gateway

### Keep sensitive data inside your trust boundary.

Local-first PII detection, policy-controlled anonymization, encrypted reversible mappings,
and client-held restoration for applications, APIs, and AI agents.

![Privacy Gateway — useful data goes out; sensitive data stays in](assets/privacy-gateway-social-preview.png)

[![CI](https://img.shields.io/github/actions/workflow/status/csnyder256/privacy-gateway/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/csnyder256/privacy-gateway/actions)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Local First](https://img.shields.io/badge/Privacy-Local--First-7c3aed?style=for-the-badge)](#trust-modes)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](#docker)
[![MCP](https://img.shields.io/badge/MCP-Agent--Ready-f59e0b?style=for-the-badge)](AGENT-GUIDE.md)

**[Documentation](https://csnyder256.github.io/privacy-gateway/)** ·
**[Quick start](#quick-start)** · **[Agent setup](AGENT-GUIDE.md)** ·
**[Threat model](docs/threat-boundaries.md)**

</div>

> [!IMPORTANT]
> Privacy Gateway reduces exposure; it is not a legal-anonymity guarantee. Read the
> [threat model](THREAT-MODEL.md) and [limitations](docs/limitations.md) before production use.

## Why Privacy Gateway

AI and data pipelines routinely cross trust boundaries. Privacy Gateway places a small,
source-agnostic control plane in front of those boundaries.

![Privacy Gateway boundary flow: inspect locally, apply policy, and release protected output](assets/privacy-gateway-flow.svg)

- **Choose exactly what changes.** Every entity type gets its own action, confidence floor,
  scope, locale, and reversibility setting; mapping and audit retention are policy-wide.
- **Fail closed.** Required detector failure returns a blocked result; it never quietly sends
  the original payload onward.
- **Keep restoration local.** A client-held key can seal a restoration capsule so the gateway
  never persists original values.
- **Audit decisions, not secrets.** Query entity type, detector, confidence, action, policy
  version, and byte span without storing plaintext values in audit rows.
- **Plug in anywhere.** Supported surfaces include Python, TypeScript, ASGI middleware,
  OpenAI/Anthropic-compatible proxies, MCP, webhooks, and CLI workflows.
- **Generate safer test data.** Infer CSV/JSON/JSONL schemas, preserve constraints and
  relationships, and receive aggregate quality/privacy reports.

## Actions

![Table of Privacy Gateway transformation actions, outputs, and restoration behavior](assets/action-catalog.svg)

The built-in entity catalog covers email, phone, payment card, SSN, IP address, API keys,
people, organizations, locations, dates, money, URLs, IBANs, US routing numbers, passports,
driver licenses, and medical licenses.

## Quick start

The local build currently requires Python 3.11+ and Node.js 20+.

```bash
git clone https://github.com/csnyder256/privacy-gateway.git
cd privacy-gateway
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'

export PRIVACY_GATEWAY_MASTER_KEY="$(privacy-gateway keygen)"
privacy-gateway anonymize 'Email me at person@example.com'
```

For a client-held restoration flow:

```python
from privacy_gateway.crypto import generate_key
from privacy_gateway.engine import PrivacyEngine
from privacy_gateway.vault import Vault

client_key = generate_key()
gateway = PrivacyEngine(Vault("privacy.db"))

protected = gateway.transform(
    "Email me at person@example.com",
    restore_key=client_key,
)

original = PrivacyEngine.restore_capsule(
    protected.text,
    protected.capsule,
    client_key,
    protected.session_id,
)
```

Open `http://127.0.0.1:8787` after `privacy-gateway serve` for the guided policy builder.

![Animated local protection flow: raw values are inspected, transformed by policy, and released as protected output](assets/privacy-boundary-loop.gif)

## Trust modes

![Comparison table of Privacy Gateway trust modes and original-value residency](assets/trust-modes.svg)

Read [the threat boundaries](docs/threat-boundaries.md) before selecting a mode. Anonymization
reduces exposure; it does not make arbitrary data automatically safe or legally anonymous.

## Storage backends

The vault slots into whatever database you already run. By default it uses a local SQLite file;
point `PRIVACY_GATEWAY_DB` (or the `serve --database` flag) at a `postgresql://` URL to use
PostgreSQL instead, with `pip install 'privacy-gateway[postgres]'`. Both backends share the same
encrypted, expiry-enforcing schema, so nothing else changes.

```bash
export PRIVACY_GATEWAY_DB="postgresql://user:pass@db.internal:5432/privacy"
```

## Integrations

![Diagram of Privacy Gateway integration surfaces](assets/integrations.svg)

Unsupported provider paths, malformed shapes, streaming, redirects, or non-JSON responses block
instead of forwarding the original. Restorable values in tool/side-effect output also block.

## Synthetic structured data

```bash
privacy-gateway synthesize source.csv synthetic.csv \
  --rows 1000 \
  --schema-output schema.json \
  --report-output report.json
```

CSV, JSON, and JSONL are supported. Explicit schemas can describe types, nullability, ranges,
categories, locales, primary keys, and multi-table foreign keys. The clean-room generator has no
SDV runtime dependency; see [provenance](docs/provenance.md) and
[limitations](docs/limitations.md).

## Docker

```bash
export PRIVACY_GATEWAY_MASTER_KEY="$(.venv/bin/privacy-gateway keygen)"
docker compose up --build
curl --fail http://127.0.0.1:8787/v1/health
```

The Compose service binds to loopback, drops capabilities, uses a read-only root filesystem, and
persists its encrypted SQLite database in a named volume. See [operations](docs/operations.md).

## Presets

Start from `balanced`, `strict`, `healthcare`, `finance`, or `devsecops`, then override any
rule. Presets are ordinary versioned policies, not hidden behavior.

```python
from privacy_gateway.models import Action, EntityType
from privacy_gateway.policies import policy_from_preset

policy = policy_from_preset("balanced")
email = policy.rule_for(EntityType.EMAIL_ADDRESS)
email.action = Action.REDACT
email.reversible = False
email.minimum_confidence_ppm = 900_000
```

## Repository map

![Diagram of Privacy Gateway repository structure](assets/repository-map.svg)

## Verification

```bash
pytest
ruff check src tests
ruff format --check src tests
npm run check
npm test
npm run build
```

Current local release gate: 107 Python tests and 22 TypeScript tests, plus Python lint/format,
TypeScript typecheck/build, package build, CLI probes, browser onboarding, and container smoke
tests. This is not a third-party security certification.

## Design provenance

Privacy Gateway draws architectural lessons from pii-proxy, Anonproxy, prompt-anonymizer,
Microsoft Presidio, and SDV. See [research verification](docs/research-verification.md) and
[provenance](docs/provenance.md) for exact revisions and license boundaries. The structured
synthetic-data work is a clean-room implementation; SDV code is not copied or bundled.

## Security

Please do not report vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md).
Start with the [threat model](THREAT-MODEL.md), then review
[operations](docs/operations.md) and [limitations](docs/limitations.md).

## License

MIT © Cade Snyder. See [LICENSE](LICENSE).
