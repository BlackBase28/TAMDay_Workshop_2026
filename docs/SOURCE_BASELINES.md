# Source baselines

This merged project was created from the following user-designated authoritative archives.

| Component | Version | SHA256 |
|---|---:|---|
| EDA Event Stream | `1.9.5-slim10` | `9669a8f7747995212143f3b1c95a28433737631feed8126fb86ef96f26e45261` |
| Ansible MCP remediation | `0.2.2` | `6d6fa4af95d985840e59918d16cd1cf47b357c8e311ac769df642ac834d94110` |

## Integration-only changes

The component runtime logic was not redesigned. Integration changes are limited to:

1. A common repository root and version.
2. A combined Ansible role search path.
3. Unified collection requirements.
4. Forwarder deployment through AAP Machine Credential instead of a host-password file.
5. Combined documentation, AAP object definitions, and validation tests.
