# CIFER Security — Technical Documentation Suite

> **Zero-Key Encryption Architecture**  
> Post-Quantum • TEE-Based • Decentralized Key Custody

---

## Document Navigation

This repository contains the complete technical specification for CIFER Security's zero-key encryption platform. Documents are organized by technical domain and target audience.

### Quick Links

| Document | Audience | Description |
|----------|----------|-------------|
| [Executive Summary](high_level.md) | All | High-level architecture overview |
| [Cryptographic Specification](docs/01_cryptographic_specification.md) | Cryptographers, Security VCs | Formal crypto primitives and proofs |
| [TEE Architecture](docs/02_tee_architecture.md) | Infrastructure VCs, Security Researchers | Enclave design and attestation |
| [Protocol Specification](docs/03_protocol_specification.md) | Protocol Engineers, Auditors | Formal protocol definitions |
| [Security Analysis](docs/04_security_analysis.md) | Security VCs, CISOs | Threat model and security proofs |
| [Distributed Systems](docs/05_distributed_systems.md) | Infrastructure VCs, SREs | CAP analysis and fault tolerance |
| [API Specification](docs/06_api_specification.md) | Developers, Enterprise VCs | Integration and SDK reference |

---

## Reading Order by Investor Type

### Security-Focused VCs
1. Executive Summary → 2. Cryptographic Specification → 3. Security Analysis → 4. TEE Architecture

### Infrastructure / Deep Tech VCs
1. Executive Summary → 2. TEE Architecture → 3. Distributed Systems → 4. Protocol Specification

### Enterprise Software VCs
1. Executive Summary → 2. API Specification → 3. Security Analysis → 4. Distributed Systems

### Crypto / Blockchain VCs
1. Executive Summary → 2. Protocol Specification → 3. Cryptographic Specification → 4. Distributed Systems

---

## Repository Structure

```
moretech/
├── README.md                              # This file
├── high_level.md                          # Executive summary / high-level architecture
└── docs/
    ├── 01_cryptographic_specification.md  # Formal cryptographic specification
    ├── 02_tee_architecture.md             # TEE platform and attestation
    ├── 03_protocol_specification.md       # Protocol state machines and messages
    ├── 04_security_analysis.md            # Threat model and security proofs
    ├── 05_distributed_systems.md          # Distributed architecture and CAP
    ├── 06_api_specification.md            # REST/gRPC API and SDK design
    ├── diagrams/                          # Source files for diagrams
    └── references/                        # Academic paper citations
```

---

## Standards Compliance

| Standard | Status | Document Reference |
|----------|--------|-------------------|
| NIST FIPS 203 (ML-KEM) | Compliant | [Cryptographic Specification](docs/01_cryptographic_specification.md) |
| NIST SP 800-56C (KDF) | Compliant | [Cryptographic Specification](docs/01_cryptographic_specification.md) |
| Intel SGX / AMD SEV | Supported | [TEE Architecture](docs/02_tee_architecture.md) |
| SOC 2 Type II | Designed for | [API Specification](docs/06_api_specification.md) |
| GDPR Article 32 | Addressed | [Security Analysis](docs/04_security_analysis.md) |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | 2025-12-28 | Initial high-level architecture |
| 0.2 | 2026-01-08 | Full technical documentation suite |

---

## Contact

For technical due diligence inquiries, contact the CIFER Security engineering team.

