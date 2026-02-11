# CIFER Security

**Zero-Key Encryption Infrastructure** for smart contracts, AI agents, and sensitive data workflows.

Website: [https://cifer-security.com](https://cifer-security.com)

## Quick Links

### Product

- Homepage: [https://cifer-security.com](https://cifer-security.com)
- Why CIFER: [https://cifer-security.com/why-cifer](https://cifer-security.com/why-cifer)
- Smart Contracts: [https://cifer-security.com/solutions/smart-contract-privacy](https://cifer-security.com/solutions/smart-contract-privacy)
- Consumer App (Scan, Protect, Share): [https://app.cifer-security.com](https://app.cifer-security.com)
- Playground: [https://playground.cifer-security.com](https://playground.cifer-security.com)

### Developer & SDK

- Encryption API: [https://cifer-security.com/solutions/api](https://cifer-security.com/solutions/api)
- AI Agent Security Insight: [https://cifer-security.com/insights/why-ai-agents-need-confidential-computing](https://cifer-security.com/insights/why-ai-agents-need-confidential-computing)
- Prompt Injection Defense: [https://cifer-security.com/insights/prompt-injection-data-exfiltration-defense](https://cifer-security.com/insights/prompt-injection-data-exfiltration-defense)
- Insights Hub: [https://cifer-security.com/insights](https://cifer-security.com/insights)

### Company

- Contact: [https://cifer-security.com/contact](https://cifer-security.com/contact)
- X: [https://x.com/cifer_security](https://x.com/cifer_security)
- Email: `contactus@cifer-security.com`

## Grant-Focused Overview

CIFER Security is building confidential computing infrastructure where encryption keys are never managed by end users, app teams, or centralized operators.

The platform combines:

- Hardware-enforced execution (secure enclaves)
- Post-quantum cryptography (ML-KEM-768)
- Distributed custody and threshold authorization
- On-chain permission checks for Web3-native use cases

This model enables private-by-default data workflows for smart contracts, AI agents, and sensitive enterprise applications.

## Why This Matters

Traditional encryption breaks in practice because key management is operationally fragile.

CIFER removes this operational burden by design:

- No long-lived encryption keys handled by customers
- No plaintext access by infrastructure operators
- No single point of failure in custody
- Forward-looking posture for post-quantum migration timelines

## SDK & Developer Experience

CIFER currently provides a **language-agnostic API integration model** and AI-agent-ready knowledge resources.

### 1. API-first integration (available now)

No SDK is required to start. Any stack can call CIFER through REST + wallet signatures.

Base URL:

```text
https://cifer-blackbox.ternoa.dev:3010
```

Core endpoints:

- `GET /healthz`
- `POST /encrypt-payload`
- `POST /decrypt-payload`
- `POST /encrypt-file`
- `POST /decrypt-file`

### 2. AI Agent SDK enablement

CIFER provides dedicated AI-agent security content and positions the platform as a skill/SDK integration layer for LLM workflows.

- AI security context: [https://cifer-security.com/insights/why-ai-agents-need-confidential-computing](https://cifer-security.com/insights/why-ai-agents-need-confidential-computing)
- Prompt-exfiltration defense context: [https://cifer-security.com/insights/prompt-injection-data-exfiltration-defense](https://cifer-security.com/insights/prompt-injection-data-exfiltration-defense)

### Minimal integration flow

1. Call `GET /healthz` to fetch the latest block number.
2. Build a signed `dataString` payload with wallet auth.
3. Call encrypt/decrypt endpoints.
4. Store `cifer` + ciphertext for later authorized decryption.

## Smart Contract Track

On-chain confidential storage is available through CIFER's smart-contract integration model.

Reference environment documented publicly:

- Network: Ternoa zkEVM+ (`chainId: 752025`)
- Secrets Controller: `0x4e31230737847C0895Df4F11876056960537E9Df`
- On-Chain Storage/Vault: `0x6A8b01CA9AB653510F579cfB59502880DCD0F174`

Implementation page:
[https://cifer-security.com/solutions/smart-contract-privacy](https://cifer-security.com/solutions/smart-contract-privacy)

## What Grant Support Accelerates

Grant funding helps CIFER move faster on:

- Developer SDK packaging and reference implementations
- Security hardening and audit depth
- Integration tooling for AI agents and Web3 teams
- Adoption support (docs, examples, developer onboarding)

## Repository

- `high_level.md`: high-level architecture and technical context.

---

CIFER Security treats encryption as infrastructure: developer-friendly, verifiable, and secure by default.
