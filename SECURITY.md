# Security Policy

Privacy Gateway is pre-release software. Do not use it for production secrets until the
integration and threat model have been reviewed for your environment.

## Reporting a vulnerability

Do not open a public issue containing exploit details, real personal data, credentials, or
decryption material. Use GitHub's private vulnerability reporting feature for this repository.
Include the affected revision, deployment mode, reproduction with synthetic values, impact,
and any suggested mitigation.

## Security invariants

- A required detector failure blocks; callers must never fall back to the original payload.
- Persistent reversible mappings require an explicit 32-byte master key.
- Client-capsule mode does not persist originals in the gateway vault.
- Mapping and session expiry is enforced on read as well as by purge.
- Audit records describe decisions and hashes; they must not contain original detected values.
- Restoration of display text is distinct from authorization to execute tool arguments or
  other side effects.

See [docs/threat-boundaries.md](docs/threat-boundaries.md) for the complete trust model and
known limitations.
