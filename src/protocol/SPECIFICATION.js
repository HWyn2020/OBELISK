/**
 * ═══════════════════════════════════════════════════════════════════════
 * SOVEREIGN PROOF PROTOCOL (SPP)
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * A zero-knowledge cross-border payment protocol where PII never
 * leaves the user's device or jurisdiction.
 * 
 * ─────────────────────────────────────────────────────────────────────
 * THE PROBLEM
 * ─────────────────────────────────────────────────────────────────────
 * 
 * Two EU regulations are in direct conflict:
 * 
 *   GDPR Article 44: Personal data shall not transfer to a third
 *   country unless adequate safeguards exist.
 *   
 *   6AMLD / PSD2: Payment service providers MUST identify sender
 *   and receiver for any cross-border transfer (Travel Rule).
 * 
 * Every existing solution (SWIFT, Wise, Revolut) resolves this by:
 *   - Storing PII centrally (GDPR risk)
 *   - Relying on Standard Contractual Clauses (legally fragile)
 *   - Operating under a single banking license (jurisdictional limit)
 * 
 * ─────────────────────────────────────────────────────────────────────
 * THE SOLUTION: PROVE WITHOUT REVEALING
 * ─────────────────────────────────────────────────────────────────────
 * 
 * Instead of sending PII across borders, we send PROOFS.
 * 
 * A Sovereign Proof is a cryptographic attestation that:
 *   ✓ This person has been KYC-verified (without revealing their name)
 *   ✓ This person is not on any sanctions list (without revealing who was checked)
 *   ✓ This transaction passes AML screening (without revealing the pattern)
 *   ✓ This amount is within their verified tier limits (without revealing the tier)
 *   ✓ This person's jurisdiction permits this corridor (without revealing location)
 * 
 * The receiving Trust Node can VERIFY all of the above without
 * ever learning the sender's identity. If regulators need to audit,
 * they go to the SENDER'S jurisdiction node — where the PII lives,
 * under that jurisdiction's data protection laws.
 * 
 * ─────────────────────────────────────────────────────────────────────
 * ARCHITECTURE OVERVIEW
 * ─────────────────────────────────────────────────────────────────────
 * 
 *   ┌──────────────────────────────────────────────────────────────┐
 *   │                     USER'S DEVICE                           │
 *   │                                                              │
 *   │  ┌──────────────────────────────────────────────────────┐   │
 *   │  │           SOVEREIGN VAULT (Secure Enclave)           │   │
 *   │  │                                                      │   │
 *   │  │  ┌──────────┐  ┌──────────┐  ┌────────────────┐    │   │
 *   │  │  │ Identity │  │  Keys    │  │  Proof Engine  │    │   │
 *   │  │  │ Store    │  │  Master  │  │  ZK commitment │    │   │
 *   │  │  │ (PII)    │  │  Derived │  │  generation    │    │   │
 *   │  │  │          │  │  Session │  │                │    │   │
 *   │  │  └──────────┘  └──────────┘  └────────────────┘    │   │
 *   │  │                                                      │   │
 *   │  │  Keys generated HERE, used ONCE, then destroyed.     │   │
 *   │  │  PII encrypted HERE, never leaves.                   │   │
 *   │  │  Proofs generated HERE, only proofs cross borders.   │   │
 *   │  └──────────────────────────────────────────────────────┘   │
 *   │                          │                                   │
 *   │                    Sovereign Proof                           │
 *   │                    (zero PII)                                │
 *   └──────────────────────┬───────────────────────────────────────┘
 *                          │
 *                          ▼
 *   ┌──────────────────────────────────────────────────────────────┐
 *   │              JURISDICTION TRUST NODE (e.g., DE)             │
 *   │                                                              │
 *   │  Receives: Sovereign Proof + encrypted amount                │
 *   │  Verifies: Proof validity, not PII                          │
 *   │  Stores:   Proof hash + jurisdiction's audit record          │
 *   │  Has:      PII for its OWN citizens only (GDPR compliant)   │
 *   │                                                              │
 *   │  ┌──────────────────────────────────────────────────────┐   │
 *   │  │  LOCAL COMPLIANCE ENGINE                             │   │
 *   │  │  - Verifies proofs from own citizens (has PII)       │   │
 *   │  │  - Verifies proofs from foreign citizens (no PII)    │   │
 *   │  │  - Issues jurisdiction attestations                   │   │
 *   │  │  - Responds to regulator audit requests               │   │
 *   │  └──────────────────────────────────────────────────────┘   │
 *   │                          │                                   │
 *   │              Settlement Commitment                           │
 *   │              (hash-linked, Merkle proof)                    │
 *   └──────────────────────┬───────────────────────────────────────┘
 *                          │
 *                          ▼
 *   ┌──────────────────────────────────────────────────────────────┐
 *   │              DECENTRALIZED TRUST MESH                       │
 *   │                                                              │
 *   │    DE ──── FR ──── NL                                       │
 *   │    │       │       │                                        │
 *   │    AT ──── IT ──── SG                                       │
 *   │    │               │                                        │
 *   │    ES ──── PT ──── US                                       │
 *   │                                                              │
 *   │  Each node:                                                  │
 *   │    - Maintains its own commitment chain (like blockchain)    │
 *   │    - Validates proofs from other nodes                       │
 *   │    - Settles bilateral obligations via netting               │
 *   │    - No single node sees all transactions                    │
 *   │    - Byzantine fault tolerant (⅓ nodes can be compromised)  │
 *   └──────────────────────────────────────────────────────────────┘
 * 
 * ─────────────────────────────────────────────────────────────────────
 * PAYMENT FLOW (Alice in DE sends €100 to Bob in SG)
 * ─────────────────────────────────────────────────────────────────────
 * 
 * 1. ALICE'S DEVICE (Sovereign Vault):
 *    - Vault confirms Alice is KYC TIER_2, sanctions-clear, AML-clean
 *    - Generates Sovereign Proof:
 *        proof = {
 *          commitment: HASH(alice_id || amount || bob_token || nonce),
 *          kyc_attestation: SIGN(kyc_verified, tier >= 2, DE_node_key),
 *          sanctions_clear: SIGN(screening_passed, timestamp, DE_node_key),
 *          aml_clear: SIGN(no_indicators, timestamp, DE_node_key),
 *          amount_commitment: Pedersen(100, blinding_factor),
 *          corridor_permit: SIGN(DE→SG_allowed, DE_node_key)
 *        }
 *    - NO names, no IBANs, no addresses in the proof
 *    - Sends proof to DE Trust Node
 * 
 * 2. DE TRUST NODE:
 *    - Verifies Alice's proof (DE node HAS Alice's PII — she's German)
 *    - Checks amount against Alice's tier limits
 *    - Creates a Settlement Commitment:
 *        commitment = {
 *          proof_hash: HASH(proof),
 *          sender_jurisdiction: "DE",
 *          receiver_jurisdiction: "SG",
 *          amount_range: "€50-€500",  // Range, not exact amount
 *          timestamp: NOW(),
 *          merkle_root: HASH(previous_commitments)
 *        }
 *    - Broadcasts commitment to SG Trust Node
 * 
 * 3. SG TRUST NODE:
 *    - Receives commitment (contains NO PII about Alice)
 *    - Verifies DE node's signature (trusts DE did its compliance)
 *    - Checks Bob is registered and KYC-verified on SG node
 *    - Creates matching settlement entry
 *    - Notifies Bob's device: "Incoming transfer, verify with your vault"
 * 
 * 4. BOB'S DEVICE:
 *    - Bob's Vault generates acceptance proof
 *    - SG node confirms receipt
 * 
 * 5. SETTLEMENT:
 *    - DE node and SG node add to their bilateral netting ledger
 *    - At settlement window (e.g., hourly), net obligations settle
 *    - DE owes SG net €X, or SG owes DE net €Y
 *    - Actual fund movement is jurisdiction-to-jurisdiction, not person-to-person
 *    - Settled via existing banking rails (TARGET2, FAST, etc.)
 * 
 * ─────────────────────────────────────────────────────────────────────
 * KEY MANAGEMENT (Ephemeral Container Model)
 * ─────────────────────────────────────────────────────────────────────
 * 
 * The user's device runs a Sovereign Vault — conceptually an
 * ephemeral secure container (maps to iOS Secure Enclave / Android
 * Keystore / TEE in production).
 * 
 * Key hierarchy:
 *   
 *   DEVICE ROOT KEY (hardware-backed, never extractable)
 *   └── VAULT MASTER KEY (derived from root + user passphrase)
 *       ├── IDENTITY KEY (encrypts PII at rest)
 *       ├── SIGNING KEY (signs proofs — rotated monthly)
 *       ├── SESSION KEYS (ephemeral, per-transaction, destroyed after use)
 *       └── RECOVERY KEY (encrypted, stored in user's chosen backup)
 * 
 * Critical rule: NO key persists in memory after use.
 * Session keys are generated, used for one proof, then zeroed.
 * 
 * If the device is compromised:
 *   - Attacker gets encrypted PII (useless without vault master key)
 *   - Attacker gets no session keys (already destroyed)
 *   - Attacker can't forge proofs (signing key is in secure enclave)
 *   - Attacker can't move funds (requires biometric + vault unlock)
 * 
 * ─────────────────────────────────────────────────────────────────────
 * REGULATORY COMPLIANCE
 * ─────────────────────────────────────────────────────────────────────
 * 
 * GDPR Article 44 (Cross-border transfer):
 *   ✓ PII never leaves the user's device
 *   ✓ PII never leaves the user's jurisdiction
 *   ✓ Only cryptographic proofs cross borders
 *   ✓ Proofs contain no personal data (just mathematical commitments)
 * 
 * 6AMLD / Travel Rule:
 *   ✓ KYC performed by jurisdiction node (has PII locally)
 *   ✓ Sanctions screening performed locally (proof attests result)
 *   ✓ AML monitoring performed locally (proof attests result)
 *   ✓ Regulators can audit by requesting from LOCAL node
 *   ✓ Cross-border regulator cooperation via mutual legal assistance
 * 
 * PSD2:
 *   ✓ Payment initiation via user's Sovereign Vault (strong customer auth)
 *   ✓ Two-factor: biometric + vault passphrase
 *   ✓ Transaction confirmation on user's device
 * 
 * eIDAS (Digital Identity):
 *   ✓ Proof system compatible with EU Digital Identity Wallet framework
 *   ✓ Jurisdiction attestations can be issued by qualified trust providers
 * 
 * ─────────────────────────────────────────────────────────────────────
 * VS. BITCOIN
 * ─────────────────────────────────────────────────────────────────────
 * 
 * What we borrow from Bitcoin:
 *   ✓ Peer-to-peer settlement (no central clearinghouse)
 *   ✓ Hash-linked commitment chains (tamper-evident history)
 *   ✓ Cryptographic proof of validity
 *   ✓ No single point of failure
 * 
 * What we do differently:
 *   ✗ NOT a blockchain (no global consensus needed)
 *   ✗ NOT permissionless (Trust Nodes are licensed institutions)
 *   ✗ NOT a cryptocurrency (settles in fiat via banking rails)
 *   ✗ NOT transparent (privacy by design, not pseudonymous)
 *   ✓ Bilateral netting instead of global ledger
 *   ✓ Jurisdiction-aware instead of borderless
 *   ✓ Regulatory compliant by architecture, not by exception
 */

module.exports = {
  PROTOCOL_VERSION: "1.0.0",
  PROTOCOL_NAME: "SOVEREIGN_PROOF_PROTOCOL",
  CODENAME: "SPP"
};
