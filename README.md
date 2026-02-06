# OBELISK

**Open Bilateral Enterprise Ledger for Interbank Sovereign Knowledge**

A zero-knowledge cross-border payment protocol that solves the GDPR Article 44 vs. 6AMLD Travel Rule conflict through cryptographic innovation. PII never crosses jurisdiction boundaries — only zero-knowledge proofs transit the Trust Mesh.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    OBELISK Protocol                      │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│ Sovereign│  Trust   │  Trust   │ Payment  │  Compliance │
│  Vault   │  Node    │  Mesh    │ Engine   │  Pipeline   │
│          │          │          │          │             │
│ Ed25519  │ Juris-   │ Bilateral│ 14-State │ 4-Tier KYC  │
│ Shamir's │ diction  │ Netting  │ Machine  │ 7-Pattern   │
│ ZK Proof │ Aware    │ P2P      │ IBAN/FX  │ AML + OFAC  │
│ Rate Lim │ Corridor │ Settle   │ TimeLock │ Risk Score  │
└──────────┴──────────┴──────────┴──────────┴─────────────┘
        │                                        │
   AES-256-GCM + HKDF Key Derivation    Enhanced Sanctions
   Per-Context Key Isolation             (Phonetic/Transliteration)
```

**The Innovation:** The Sovereign Vault generates zero-knowledge compliance proofs — cryptographic attestations that a customer is KYC-verified and sanctions-cleared, without revealing any PII. Trust Nodes validate these proofs locally, create bilateral commitments, and settle through the Trust Mesh. Data sovereignty is enforced at the protocol level.

## Quick Start

```bash
git clone https://github.com/HWyn2020/OBELISK.git
cd OBELISK
npm install
npm test
```

## Test Suite

```
17 suites | 865 tests | 100% pass rate
```

Run the full enterprise security assessment:
```bash
npx jest tests/ --runInBand --forceExit
```

## Security

- **26 vulnerabilities** discovered across 4 rounds of penetration testing
- **23 fixed in code**, 3 documented for production deployment
- Tested against OWASP API Top 10, NIST SP 800-53, PCI DSS v4.0, CWE Top 25
- See `ENTERPRISE_SECURITY_REPORT.md` for full assessment

## License

MIT
