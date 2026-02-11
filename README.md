# CIFER Security

**Zero-Key Encryption Infrastructure** for smart contracts, AI agents, and sensitive data workflows.

Official website: [https://cifer-security.com](https://cifer-security.com)

## Product Links

- Website: [https://cifer-security.com](https://cifer-security.com)
- Why CIFER: [https://cifer-security.com/why-cifer](https://cifer-security.com/why-cifer)
- Smart Contracts (On-Chain Confidential Storage): [https://cifer-security.com/solutions/smart-contract-privacy](https://cifer-security.com/solutions/smart-contract-privacy)
- Encryption API: [https://cifer-security.com/solutions/api](https://cifer-security.com/solutions/api)
- AI Agent Security Insight: [https://cifer-security.com/insights/why-ai-agents-need-confidential-computing](https://cifer-security.com/insights/why-ai-agents-need-confidential-computing)
- Prompt Injection Defense (AI): [https://cifer-security.com/insights/prompt-injection-data-exfiltration-defense](https://cifer-security.com/insights/prompt-injection-data-exfiltration-defense)
- Consumer App (Scan, Protect, Share): [https://app.cifer-security.com](https://app.cifer-security.com)
- Playground: [https://playground.cifer-security.com](https://playground.cifer-security.com)
- Insights: [https://cifer-security.com/insights](https://cifer-security.com/insights)
- Contact: [https://cifer-security.com/contact](https://cifer-security.com/contact)

## What CIFER Provides

- Zero key management: keys are generated and used inside secure enclaves.
- Confidential computing foundation: Intel SGX/TDX and AMD SEV compatible model.
- Post-quantum primitives: ML-KEM-768 + modern symmetric encryption.
- Distributed trust: threshold custody architecture to reduce single points of failure.
- Developer-ready interfaces: API-first encryption and on-chain integration flows.

## Core Use Cases

### Smart Contracts

Use CIFER to store encrypted state on public chains while keeping decryption rights controlled and auditable.

- Private transactions and confidential state
- Sealed bids and sensitive on-chain workflows
- Threshold custody + on-chain authorization patterns

### AI Agents

Use confidential computing patterns to secure agent memory, prompts, and sensitive outputs.

- Protect agent conversation/context data
- Limit exfiltration risk from prompt injection scenarios
- Add hardware-enforced boundaries around sensitive AI workflows

### Consumer Share Flows

Use the consumer app to scan, protect, and share files with encrypted handling.

- File encryption and secure sharing
- User-controlled access model
- Zero-knowledge style handling posture

## API Snapshot

Base URL:

```text
https://cifer-blackbox.ternoa.dev:3010
```

Main endpoints:

- `GET /healthz`
- `POST /encrypt-payload`
- `POST /decrypt-payload`

Minimal payload encryption flow:

1. Read block context from `GET /healthz`.
2. Build signed `dataString` payload.
3. Call `POST /encrypt-payload`.
4. Store `cifer` + `encryptedMessage` for later decryption.

## Smart Contract Snapshot (Live Environment)

Reference network highlighted on CIFER docs:

- Ternoa zkEVM+ mainnet (Chain ID `752025`)
- Secrets Controller: `0x4e31230737847C0895Df4F11876056960537E9Df`
- On-Chain Storage/Vault: `0x6A8b01CA9AB653510F579cfB59502880DCD0F174`

See full implementation guide:
[https://cifer-security.com/solutions/smart-contract-privacy](https://cifer-security.com/solutions/smart-contract-privacy)

## Repository Contents

- `high_level.md`: high-level architecture and system context.

## Contact

- Web: [https://cifer-security.com/contact](https://cifer-security.com/contact)
- Email: `contactus@cifer-security.com`
- X: [https://x.com/cifer_security](https://x.com/cifer_security)

---

CIFER Security positions encryption as infrastructure: usable by developers, secure by default, and aligned with post-quantum migration timelines.
