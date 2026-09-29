# Install Privacy Gateway

## Python package

Download the wheel and checksums from the [latest release](https://github.com/csnyder256/privacy-gateway/releases/latest).
Python 3.11+ is supported. Verify the wheel's SHA-256 before installing it into a
virtual environment with `python -m pip install <wheel>`.
Run `privacy-gateway --help` for configuration and server commands.
Presidio, MCP and PostgreSQL extras are documented in [README.md](README.md).

## Docker Compose and ARM64

The published image now supports Linux AMD64 and ARM64:

```sh
docker pull ghcr.io/csnyder256/privacy-gateway:v0.4.1
```

Use the existing [Compose configuration](compose.yml) and [README container guide](README.md)
for policy files, authentication, capsule keys and persistent storage. Pin an image
version or digest when deploying; `latest` follows stable releases. Real keys must
be supplied at runtime and excluded from build contexts.

## Upgrade

Stop the gateway and back up policy configuration and persistent ledgers. Keep
client-held capsules and their keys available before updating. Change the pinned
image version or install the new wheel, then check `/v1/health` and exercise a
synthetic transform/reconstitution round trip. Retain the prior version and backup
for rollback. The release publishes wheel, sdist, SPDX SBOM and checksums only
after policy tests, site-claim checks and version validation pass.
