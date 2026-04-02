# Governance — lib-conclave-sdk

This document defines the business role, ownership, and operational standards for the Conclave SDK.

## 1. Business Role

The Conclave SDK (`lib-conclave-sdk`) is the **canonical high-integrity integration surface** for the Conxian ecosystem. Its primary role is to provide a unified, secure interface for:

- **Institutional Key Custody**: Hardware-backed key management and signing.
- **Sovereign Interoperability**: Orchestration of non-custodial cross-chain swaps via the Sovereign Handshake.
- **Identity & Attribution**: Cryptographic partner identification and business attribution.
- **Financial Messaging**: ISO 20022 and Conxian Job Card Schema (CJCS) generation.

As a shared public-facing dependency, the SDK ensures that all downstream products (like Conxius Wallet) and external integrations adhere to the core security principles of **Zero Secret Egress** and **Hardware Attestation**.

## 2. Ownership & Support

- **Primary Owner**: [Conxian-Labs](https://github.com/Conxian)
- **Support Channel**:
  - Technical issues and feature requests should be tracked via [GitHub Issues](https://github.com/Conxian/lib-conclave-sdk/issues).
  - Security vulnerabilities MUST be reported to `security@conxian.com` as per [SECURITY.md](SECURITY.md).
- **Service Level**: The SDK is currently in **Beta** (`0.x`). Support is provided on a best-effort basis by the core engineering team.

## 3. Release Governance

### Versioning Discipline
We strictly follow [Semantic Versioning 2.0.0](https://semver.org/).

- **Major (X.0.0)**: Breaking changes to the core API (e.g., `EnclaveManager` trait modifications).
- **Minor (0.X.0)**: New features or significant additions (e.g., new Sovereign Rails).
- **Patch (0.0.X)**: Bug fixes, performance improvements, and documentation updates.

**Note on 0.x.y versions**: During the Beta phase, breaking changes may occur in minor (`0.x.0`) releases.

### Compatibility Communication
- **Changelogs**: Every release must include an update to [CHANGELOG.md](CHANGELOG.md) following the [Keep a Changelog](https://keepachangelog.com/) format.
- **Breaking Changes**: For versions >= 1.0.0, breaking changes will be announced at least one minor version in advance via deprecation warnings in the codebase and release notes.

## 4. Integration Surface

The SDK exposes two primary integration surfaces:

1. **Rust Crate**: For low-level system integrations and other Rust-based services.
2. **WebAssembly (WASM)**: High-level bindings for browser and mobile environments (e.g., React Native via JSI or WebView).

All public APIs are documented in [README.md](README.md) and through inline Rust documentation (`cargo doc`).
