# Stellar Community Fund (SCF) Proposal: `soro-sec`

**Project Name:** `soro-sec`  
**Track:** Developer Tooling & Security Infrastructure  
**Applicant:** Omni-Hektic (`@Omni-Hektic`)  
**Repository:** https://github.com/Omni-Hektic/soro-sec  

---

## 1. Executive Summary

`soro-sec` is an automated, AST-powered static security analysis and vulnerability linter built specifically for Soroban smart contracts on the Stellar network.

While the Ethereum ecosystem benefits from established static analysis suites like Slither and Mythril, Soroban developers currently lack dedicated automated security linting. Standard Rust compiler checks and Clippy miss critical, chain-specific runtime pitfalls—such as state entry expiration hazards (missing `extend_ttl`), improper `require_auth` placement, Checks-Effects-Interactions (CEI) reentrancy vulnerabilities, and unconstrained financial arithmetic.

`soro-sec` fills this gap by delivering a lightweight, millisecond-fast Rust CLI and plug-and-play GitHub Action that flags security anti-patterns with actionable remediations before contracts hit testnet or mainnet.

---

## 2. Problem Statement

Soroban introduces state-of-the-art WebAssembly smart contracts with unique architectural semantics that general-purpose linters cannot evaluate:
1. **State Archival & TTL Expiration:** Unlike EVM contracts with perpetual state, Soroban storage entries (`instance`, `persistent`, `temporary`) have lifetimes governed by Time-To-Live (TTL). Contracts failing to extend TTL risk permanent lockout of user funds.
2. **Soroban Authorization Mechanics:** The `require_auth()` and `require_auth_for_args()` system is fine-grained. Functions modifying admin state without caller checks create catastrophic access-control bypasses.
3. **Checks-Effects-Interactions (CEI) Traps:** Cross-contract client invocations before storage persistence invite reentrancy and state desynchronization.
4. **Developer Friction:** Teams participating in hackathons and Drips Waves frequently deploy code without access to automated pre-audit verification.

---

## 3. The Solution: `soro-sec`

`soro-sec` provides automated, compile-time AST inspection of Soroban smart contract source code:
- **Rust `syn` Engine:** Performs deep abstract syntax tree analysis on `#[contract]` and `#[contractimpl]` definitions.
- **Rule Engine (v0.1.0 Ready):**
  - `SG001`: Missing TTL extension on storage mutations.
  - `SG002`: Missing `require_auth()` on privileged administrative endpoints.
  - `SG003`: Checks-Effects-Interactions (CEI) violation on external calls.
  - `SG004`: Unchecked arithmetic operators in financial balance logic.
  - `SG005`: Unstructured storage keys prone to namespace collision.
- **Plug-and-Play CI:** Full SARIF integration with GitHub Code Scanning, allowing any Stellar repository to enable automated security gates with a single 10-line workflow file.

---

## 4. Current Status & Working Prototype

Unlike early-stage concepts, `soro-sec` already has a working, tested codebase:
- Comprehensive Rust CLI with modular rule engine and multi-format reporters (Terminal, JSON, SARIF, Markdown).
- End-to-end integration test suite verifying detections against real vulnerable and secure Soroban contracts (`cargo test` passes 100%).
- Composite GitHub Action (`action.yml`) ready for ecosystem deployment.

---

## 5. Milestone & Deliverables Roadmap

### Milestone 1: Core Engine & CI Infrastructure (Completed / MVP)
- [x] Abstract syntax tree (AST) traversal engine for Soroban contracts.
- [x] Initial 5 core security rules (`SG001` through `SG005`).
- [x] Output reporters: Terminal (ANSI colored), JSON, SARIF 2.1.0, and Markdown.
- [x] GitHub Action (`action.yml`) for pull request automation.

### Milestone 2: Advanced Semantic Analysis & Rule Expansion (Month 1–2)
- [ ] Implement dataflow taint analysis: trace function arguments directly into storage keys to detect parameter injection.
- [ ] Add rules `SG006`–`SG010` (Contract upgrade validation, reentrancy guards, event emission compliance, and Soroban budget/resource exhaustion heuristics).
- [ ] Benchmark against top 20 public Soroban open-source protocols (Trellis, TrustLink, Stolla, MindVault) and publish automated audit reports.

### Milestone 3: VS Code IDE Extension & Developer Onboarding (Month 3–4)
- [ ] Build a lightweight VS Code extension / LSP integration providing real-time in-editor diagnostic squiggles as developers write Soroban contracts.
- [ ] Community documentation, interactive tutorial on fixing Soroban vulnerabilities, and workshop hosting for Stellar Developers Discord.

---

## 6. Team & Ecosystem Track Record

- **Lead Developer:** Omni-Hektic (`@Omni-Hektic`)
- **Stellar Track Record:** Active contributor to the Stellar Drips Wave program (Wave 10 & Wave 11), authoring code fixes and security-tier audits across repositories including `TrustLink` (Soroban admin transfer security), `stolla` (DAO contracts), `Trellis-API`, and `mindvault`.
