# Operations

## Deployment

Generate the master key once and store it in the platform's secret manager:

```bash
privacy-gateway keygen
```

Provide it as `PRIVACY_GATEWAY_MASTER_KEY`; do not place it in an image, Compose file, shell
history, or repository. `docker compose up --build` binds the service to loopback by default,
drops Linux capabilities, enables a read-only root filesystem, and persists only `/data`.

For network use, place an authenticated TLS reverse proxy in front of port 8787. v0.1 does not
include OIDC or tenant authorization, so do not expose it as a shared public service.

## Required checks

```bash
privacy-gateway verify
curl --fail http://127.0.0.1:8787/v1/health
pytest
npm test
```

`/v1/health` reports whether persistent restoration has a master key; it does not prove a
downstream provider is reachable. Exercise a fake-data transform/restore probe separately.

## Retention and deletion

- Reads reject expired sessions/mappings immediately.
- `privacy-gateway purge-expired` removes expired live rows.
- `DELETE /v1/sessions/{id}` deletes one session and cascading mappings/detections.
- Backups and storage-media reclamation remain operator-owned. SQLite deletion is not described
  as forensic erasure.

Schedule purge at least as often as the shortest configured retention. Back up the encrypted
database only when restoration continuity is required, and expire backups independently.

## Provider proxy

Set `PRIVACY_GATEWAY_OPENAI_UPSTREAM` or `PRIVACY_GATEWAY_ANTHROPIC_UPSTREAM` to a fixed HTTPS
base URL. The corresponding client base URLs are `/proxy/openai/v1` and
`/proxy/anthropic/v1`. JSON non-streaming Chat Completions, Responses, and Messages are supported.
Unsupported paths/shapes, redirects, non-JSON responses, oversized bodies, and streaming block.

## Upgrade and rollback

Back up the encrypted database and key reference, deploy the new image, run the verification
probe, then switch traffic. Roll back by restoring the previous image; do not replace or discard
the master key while live mappings still require restoration. The v0.1 schema is additive and
created automatically, but production operators should still test a copy before upgrade.
