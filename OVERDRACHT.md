# Ringwall: Handover

## Current Status (2026-11-26)

- **Repository:** `https://github.com/samyxo-bv/ringwall` (public, Apache-2.0).
- **Live / Released:** Initial v0.1.0 build in progress.
- **Open:** Complete Go daemon (`ringwalld`), CLI (`ringwallctl`), eBPF CO-RE sensor, policy packs, local AI Guardian, web dashboard, immutable ISO pipeline, GitHub Actions CI + QEMU live boot/attack test, independent Claude Opus security review, and `v0.1.0` release.
- **Next step:** Finish v0.1.0 implementation, verify green CI (Go tests + eBPF build + ISO build + QEMU live attack E2E), pass independent security review, and tag `v0.1.0`.

## Key Decisions

- **Architecture:** Deterministic policy engine + kernel enforcement is the hard security wall; local AI Guardian explains, scores, and can escalate only — never downgrade a deterministic deny/freeze/kill verdict.
- **CI Runner:** Public repo uses GitHub-hosted `ubuntu-latest` (unlimited free minutes, avoids exposing private self-hosted runners to untrusted public PRs).
- **Zero-secret public repo:** Keep all docs, configs, and scripts free of internal infrastructure details.
