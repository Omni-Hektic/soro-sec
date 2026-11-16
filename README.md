# soro-sec 🛡️

> Fast, AST-powered static security analyzer and vulnerability linter for **Soroban smart contracts** on Stellar.

[![CI](https://github.com/Omni-Hektic/soro-sec/actions/workflows/ci.yml/badge.svg)](https://github.com/Omni-Hektic/soro-sec/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Stellar Ecosystem](https://img.shields.io/badge/Stellar-Soroban-purple.svg)](https://stellar.org)

`soro-sec` is a dedicated CLI and continuous security scanner for Soroban smart contracts written in Rust. It catches critical vulnerability patterns unique to Soroban runtime semantics before deployment to testnet and mainnet.

---

## 🚀 Features

- **Soroban-Specific Semantic Rules:** Catches state expiration hazards, missing authorization, CEI reentrancy violations, and financial math traps.
- **AST-Driven Precision:** Built directly with Rust `syn` AST visitors for low false-positive rates.
- **Lightning Fast:** Scans contract files in single-digit milliseconds.
- **Multi-Format Reporting:** Terminal with colored diagnostics, SARIF (for GitHub Security tab & IDE code scanning), JSON, and audit-ready Markdown.
- **CI / GitHub Action Integration:** Drop `uses: Omni-Hektic/soro-sec@v1` into any Soroban repo to enforce automated security gates on pull requests.

---

## 🔍 Detection Rules

| Rule ID | Name | Severity | Description |
| :--- | :--- | :---: | :--- |
| **`SG001`** | **Missing TTL Extension** | `HIGH` | Storage entries (`instance`/`persistent`) mutated without `extend_ttl`, risking contract archival. |
| **`SG002`** | **Missing require_auth()** | `CRITICAL` | Privileged functions (`admin`, `upgrade`, `set_*`, `withdraw`) executing without caller verification. |
| **`SG003`** | **Checks-Effects-Interactions (CEI)** | `HIGH` | External contract calls/transfers made *before* updating internal contract storage state. |
| **`SG004`** | **Unchecked Arithmetic** | `MEDIUM` | Raw arithmetic (`+`, `-`, `*`, `/`) in token/balance logic instead of `checked_*` methods. |
| **`SG005`** | **Storage Key Collisions** | `LOW` | Use of raw `symbol_short!` strings instead of strongly typed `#[contracttype] enum DataKey`. |

---

## 📦 Installation

### From Source (Cargo)
```bash
git clone https://github.com/Omni-Hektic/soro-sec.git
cd soro-sec
cargo install --path .
```

---

## 🛠️ Usage

### Quick Scan
Scan the current directory:
```bash
soro-sec
```

Scan a specific contract file:
```bash
soro-sec contracts/vault/src/lib.rs
```

### List Rules
```bash
soro-sec --list-rules
```

### Export to SARIF (for GitHub Security Tab)
```bash
soro-sec . --format sarif --output results.sarif
```

### Export to Markdown (for Audit Reports)
```bash
soro-sec . --format markdown --output AUDIT_REPORT.md
```

### CI Failure Gate
Fail the build with non-zero exit code if vulnerabilities of `HIGH` or `CRITICAL` severity exist:
```bash
soro-sec . --fail-on HIGH
```

---

## 🤖 GitHub Action Workflow

Add this to `.github/workflows/security.yml` in your Soroban contract repository:

```yaml
name: Soroban Security Scan

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  soro-sec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Soro-Sec Scanner
        uses: Omni-Hektic/soro-sec@v1
        with:
          path: '.'
          fail-on: 'HIGH'
          format: 'sarif'
          output: 'soro-sec.sarif'

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'soro-sec.sarif'
```

---

## 🧪 Testing

Run unit and integration test fixtures verifying detections against both vulnerable and secure Soroban contracts:

```bash
cargo test
```

---

## 📜 License
Licensed under either of Apache License, Version 2.0 or MIT license at your option.
