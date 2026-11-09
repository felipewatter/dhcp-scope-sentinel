# DHCP ScopeSentinel — English Guide

**Offline DHCPv4 address-plan security and change regression auditor.** No DHCP packets, live host access, packet capture or device writes.

[Português (primary documentation)](README.md) · [JSON schema](docs/SCHEMA.md) · [Threat model](docs/THREAT_MODEL.md)

## What it checks

- Cross-scope dynamic pool overlaps, pool self-overlap and unsafe gateway/static host allocation.
- Failover peers' pool, exclusion, reservation and unique-server consistency.
- Duplicate IP/client reservations and same-VRF overlapping routed subnets.
- Approved versus observed DHCP server identifiers, offered addresses, router/DNS option deviations and relay identifier presence/allowlisting.
- Independently maintained policy contracts: subnet, router, authorized servers, relay trust allowlist, DNS allowlist, usable capacity and scope count.
- Baseline/candidate difference between newly introduced, persistent and resolved findings, with deterministic SHA-256 fingerprints.
- SARIF 2.1.0/JSON reports and exit-code-based CI gating.

This is **not** a DHCP rogue discovery tool, active network scanner, lease database validator, full DHCP/Option 82 protocol simulator, or replacement for DHCP snooping or actual network verification. Observed DHCPOFFER messages do not prove address lease conflicts.

## Quick start

```bash
python -m pip install -e .
dhcp-scope-sentinel audit examples/baseline.json --policy examples/contracts.json
dhcp-scope-sentinel diff examples/baseline.json examples/candidate-risky.json \
  --policy examples/contracts.json --fail-on high
```

- `0`: no findings at or above selected threshold.
- `2`: findings meet or exceed selected threshold (with valid CLI syntax).
- `3`: input/output validation error; fail closed.

By default, `diff` gates only **introduced** findings; use `--all-findings` to include persistent ones. For reports, specify `--json-out` and/or `--sarif-out` with *new* destination paths. Existing output files are never overwritten.

## Design and security

Python 3.11+ with **zero third-party runtime dependencies**, strict bounded JSON parsing, duplicate-key rejection, interval arithmetic without subnet host enumeration, deterministic reports, symlink and overwrite protection. Test matrix: Ubuntu/Windows/macOS × Python 3.11/3.12/3.13. Release automation requires green CI on the exact current `main` commit; published tags are immutable.

The JSON input is a normalized representation, not a raw Kea/ISC/Microsoft export. Evidence supplied by an operator is not cryptographically authenticated by this tool. Retain logs safely and avoid publishing client IDs, IP plans or other operational metadata.

See [the Portuguese README](README.md), [schema](docs/SCHEMA.md), [operations runbook](docs/OPERATIONS.md), [security policy](SECURITY.md) and [MIT license](LICENSE).
