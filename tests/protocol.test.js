/**
 * Sovereign Proof Protocol Tests
 * 
 * Tests the complete flow: vault → proof → trust node → mesh → settlement
 */

const { SovereignVault } = require("../src/vault/sovereign-vault");
const { TrustNode } = require("../src/trust/trust-node");
const { TrustMesh } = require("../src/trust/trust-mesh");

// ============================================================
// SOVEREIGN VAULT
// ============================================================

describe("Sovereign Vault", () => {
  let vault;

  beforeEach(() => {
    vault = new SovereignVault();
  });

  afterEach(() => {
    if (vault._vaultUnlocked) vault.lock();
  });

  test("unlock vault with passphrase", () => {
    const result = vault.unlock("MySecure2024Pass");
    expect(result.publicKey).toBeDefined();
    expect(result.vaultId).toBe(vault.vaultId);
    expect(vault._vaultUnlocked).toBe(true);
  });

  test("rejects short passphrase", () => {
    expect(() => vault.unlock("short")).toThrow("at least 12");
  });

  test("store and read identity (PII stays on device)", () => {
    vault.unlock("TestPass123Secure");
    
    const { commitment } = vault.storeIdentity({
      firstName: "Alice", lastName: "Schmidt",
      email: "alice@example.de", phone: "+49301234567",
      country: "DE", dateOfBirth: "1990-05-15",
      idNumber: "T22000129", idType: "PASSPORT", idExpiry: "2030-12-31"
    });
    
    expect(commitment).toBeDefined();
    expect(commitment.length).toBe(64); // SHA-256 hex
    
    // PII is readable from the vault
    const identity = vault.readIdentity();
    expect(identity.firstName).toBe("Alice");
    expect(identity.lastName).toBe("Schmidt");
    expect(identity.country).toBe("DE");
  });

  test("identity is encrypted at rest", () => {
    vault.unlock("TestPass123Secure");
    vault.storeIdentity({
      firstName: "Alice", lastName: "Schmidt",
      email: "alice@example.de", phone: "+49301234567", country: "DE"
    });
    
    // Raw encrypted data should not contain plaintext
    const raw = vault._encryptedIdentity;
    expect(raw.ciphertext).toBeDefined();
    expect(raw.ciphertext.toString("utf8")).not.toContain("Alice");
  });

  test("generate Sovereign Proof with zero PII", () => {
    vault.unlock("TestPass123Secure");
    vault.storeIdentity({
      firstName: "Alice", lastName: "Schmidt",
      email: "alice@example.de", phone: "+49301234567", country: "DE"
    });
    
    const proof = vault.generateProof({
      type: "PAYMENT",
      claims: {
        kycVerified: true,
        tierSufficient: true,
        sanctionsClear: true,
        listsChecked: ["OFAC", "EU", "UN", "UK-HMT"],
        amlClear: true,
        patternsChecked: 7,
        amountWithinLimits: true,
        corridorPermitted: true
      },
      recipientNodeId: "TN-SG-abc123",
      amount: 100
    });
    
    // Proof exists
    expect(proof.payload).toBeDefined();
    expect(proof.signature).toBeDefined();
    expect(proof.publicKey).toBeDefined();
    
    // CRITICAL: Proof contains ZERO PII
    const proofStr = JSON.stringify(proof);
    expect(proofStr).not.toContain("Alice");
    expect(proofStr).not.toContain("Schmidt");
    expect(proofStr).not.toContain("alice@example.de");
    expect(proofStr).not.toContain("+49301234567");
    expect(proofStr).not.toContain("T22000129");
    
    // Proof contains attestations (boolean claims)
    expect(proof.payload.attestations.kyc.claim).toBe("IDENTITY_VERIFIED");
    expect(proof.payload.attestations.kyc.value).toBe(true);
    expect(proof.payload.attestations.sanctions.value).toBe(true);
    expect(proof.payload.attestations.aml.value).toBe(true);
    
    // Amount is committed, not revealed
    expect(proof.payload.amountCommitment).toBeDefined();
    expect(proof.payload.amountCommitment.range).toBe("0-100");
    expect(proofStr).not.toContain('"amount":100');
  });

  test("verify Sovereign Proof (static method)", () => {
    vault.unlock("TestPass123Secure");
    vault.storeIdentity({
      firstName: "Alice", lastName: "Schmidt",
      email: "alice@example.de", phone: "+49", country: "DE"
    });
    
    const proof = vault.generateProof({
      type: "PAYMENT",
      claims: { kycVerified: true, sanctionsClear: true, amlClear: true,
                amountWithinLimits: true, corridorPermitted: true },
      recipientNodeId: "TN-SG",
      amount: 50
    });
    
    const result = SovereignVault.verifyProof(proof);
    expect(result.valid).toBe(true);
    expect(result.proofId).toBeDefined();
    expect(result.attestations.kyc.value).toBe(true);
  });

  test("tampered proof fails verification", () => {
    vault.unlock("TestPass123Secure");
    vault.storeIdentity({
      firstName: "Alice", lastName: "Schmidt",
      email: "a@b.de", phone: "+49", country: "DE"
    });
    
    const proof = vault.generateProof({
      type: "PAYMENT",
      claims: { kycVerified: true, sanctionsClear: true, amlClear: true,
                amountWithinLimits: true, corridorPermitted: true },
      recipientNodeId: "TN-SG",
      amount: 50
    });
    
    // Tamper: change an attestation
    proof.payload.attestations.sanctions.value = false;
    
    const result = SovereignVault.verifyProof(proof);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("SIGNATURE_INVALID");
  });

  test("expired proof fails verification", () => {
    vault.unlock("TestPass123Secure");
    vault.storeIdentity({
      firstName: "X", lastName: "Y", email: "x@y.z", phone: "+1", country: "US"
    });
    
    const proof = vault.generateProof({
      type: "PAYMENT",
      claims: { kycVerified: true, sanctionsClear: true, amlClear: true,
                amountWithinLimits: true, corridorPermitted: true },
      recipientNodeId: "TN-SG",
      amount: 50
    });
    
    // Artificially expire
    proof.payload.expiresAt = new Date(Date.now() - 1000).toISOString();
    // FIX PEN-002: Signature is now verified BEFORE expiry, so modifying
    // the payload after signing invalidates the signature first.
    
    const result = SovereignVault.verifyProof(proof);
    expect(result.valid).toBe(false);
    expect(["PROOF_EXPIRED", "SIGNATURE_INVALID"]).toContain(result.reason);
  });

  test("session keys are destroyed after proof generation", () => {
    vault.unlock("TestPass123Secure");
    vault.storeIdentity({
      firstName: "A", lastName: "B", email: "a@b.c", phone: "+1", country: "US"
    });
    
    vault.generateProof({
      type: "PAYMENT",
      claims: { kycVerified: true, sanctionsClear: true, amlClear: true,
                amountWithinLimits: true, corridorPermitted: true },
      recipientNodeId: "TN-SG",
      amount: 50
    });
    
    expect(vault._activeSessionKeys.size).toBe(0);
  });

  test("vault lock zeros all keys from memory", () => {
    vault.unlock("TestPass123Secure");
    // FIX PEN-003: Master key is now zeroed immediately after derivation
    expect(vault._vaultMasterKey).toBeNull(); // Transient, already zeroed
    expect(vault._identityKey).not.toBeNull(); // Derived key persists while unlocked
    
    vault.lock();
    
    expect(vault._vaultMasterKey).toBeNull();
    expect(vault._identityKey).toBeNull();
    expect(vault._signingKeyPair).toBeNull();
    expect(vault._vaultUnlocked).toBe(false);
  });

  test("locked vault rejects operations", () => {
    expect(() => vault.storeIdentity({})).toThrow("locked");
    expect(() => vault.readIdentity()).toThrow("locked");
    expect(() => vault.generateProof({})).toThrow("locked");
  });

  test("proof counter is monotonically increasing", () => {
    vault.unlock("TestPass123Secure");
    vault.storeIdentity({
      firstName: "A", lastName: "B", email: "a@b.c", phone: "+1", country: "US"
    });
    
    const claims = { kycVerified: true, sanctionsClear: true, amlClear: true,
                     amountWithinLimits: true, corridorPermitted: true };
    
    const p1 = vault.generateProof({ type: "PAYMENT", claims, recipientNodeId: "TN-1", amount: 10 });
    const p2 = vault.generateProof({ type: "PAYMENT", claims, recipientNodeId: "TN-2", amount: 20 });
    const p3 = vault.generateProof({ type: "PAYMENT", claims, recipientNodeId: "TN-3", amount: 30 });
    
    expect(p2.payload.counter).toBeGreaterThan(p1.payload.counter);
    expect(p3.payload.counter).toBeGreaterThan(p2.payload.counter);
  });

  test("recovery key is split into 3 shares", () => {
    vault.unlock("TestPass123Secure");
    const recovery = vault.generateRecoveryKey();
    
    expect(recovery.shares.length).toBe(3);
    expect(recovery.threshold).toBe(2);
    expect(recovery.shares[0].store).toBe("USER_DEVICE");
    expect(recovery.shares[1].store).toBe("USER_CLOUD_BACKUP");
    expect(recovery.shares[2].store).toBe("TRUSTED_CONTACT");
  });
});

// ============================================================
// TRUST NODE
// ============================================================

describe("Trust Node", () => {
  let deNode;
  let sgNode;

  beforeEach(() => {
    deNode = new TrustNode({ jurisdiction: "DE", operatorName: "Deutsche Trust GmbH" });
    sgNode = new TrustNode({ jurisdiction: "SG", operatorName: "Singapore Trust Pte Ltd" });
  });

  test("node initialization", () => {
    expect(deNode.jurisdiction).toBe("DE");
    expect(deNode.publicKey).toBeDefined();
    expect(deNode.commitmentChain.length).toBe(0);
  });

  test("register vault on home jurisdiction node", () => {
    const vault = new SovereignVault();
    const { publicKey } = vault.unlock("TestPass123Secure");
    
    const result = deNode.registerVault(
      vault.vaultId, publicKey, "commitment-hash", "TIER_2"
    );
    
    expect(result.registered).toBe(true);
    expect(deNode.registeredVaults.size).toBe(1);
  });

  test("connect two peer nodes", () => {
    deNode.connectPeer(sgNode);
    
    expect(deNode.peers.has(sgNode.nodeId)).toBe(true);
    expect(sgNode.peers.has(deNode.nodeId)).toBe(true);
    expect(deNode.nettingLedgers.has(sgNode.nodeId)).toBe(true);
  });

  test("process outbound payment with valid proof", async () => {
    const vault = new SovereignVault();
    const { publicKey } = vault.unlock("TestPass123Secure");
    
    vault.storeIdentity({
      firstName: "Alice", lastName: "Schmidt",
      email: "alice@example.de", phone: "+49", country: "DE"
    });
    
    deNode.registerVault(vault.vaultId, publicKey, vault._identityCommitment, "TIER_2");
    deNode.connectPeer(sgNode);
    
    const proof = vault.generateProof({
      type: "PAYMENT",
      claims: {
        kycVerified: true, tierSufficient: true,
        sanctionsClear: true, amlClear: true,
        amountWithinLimits: true, corridorPermitted: true
      },
      recipientNodeId: sgNode.nodeId,
      amount: 100
    });
    
    const result = await deNode.processOutboundPayment(proof, sgNode.nodeId, "0-100");
    
    expect(result.success).toBe(true);
    expect(result.commitmentId).toBeDefined();
    expect(result.commitment.senderJurisdiction).toBe("DE");
    expect(result.commitment.receiverJurisdiction).toBe("SG");
    expect(result.chain.height).toBe(1);
  });

  test("reject proof with failed KYC attestation", async () => {
    const vault = new SovereignVault();
    const { publicKey } = vault.unlock("TestPass123Secure");
    vault.storeIdentity({ firstName: "A", lastName: "B", email: "a@b.c", phone: "+1", country: "DE" });
    
    deNode.registerVault(vault.vaultId, publicKey, vault._identityCommitment, "TIER_1");
    deNode.connectPeer(sgNode);
    
    const proof = vault.generateProof({
      type: "PAYMENT",
      claims: {
        kycVerified: false, // FAILED
        sanctionsClear: true, amlClear: true,
        amountWithinLimits: true, corridorPermitted: true
      },
      recipientNodeId: sgNode.nodeId,
      amount: 50
    });
    
    const result = await deNode.processOutboundPayment(proof, sgNode.nodeId, "0-100");
    expect(result.success).toBe(false);
    expect(result.error).toBe("KYC_NOT_VERIFIED");
  });

  test("replay protection rejects duplicate proof", async () => {
    const vault = new SovereignVault();
    const { publicKey } = vault.unlock("TestPass123Secure");
    vault.storeIdentity({ firstName: "A", lastName: "B", email: "a@b.c", phone: "+1", country: "DE" });
    
    deNode.registerVault(vault.vaultId, publicKey, vault._identityCommitment, "TIER_2");
    deNode.connectPeer(sgNode);
    
    const proof = vault.generateProof({
      type: "PAYMENT",
      claims: { kycVerified: true, sanctionsClear: true, amlClear: true,
                amountWithinLimits: true, corridorPermitted: true },
      recipientNodeId: sgNode.nodeId,
      amount: 100
    });
    
    const first = await deNode.processOutboundPayment(proof, sgNode.nodeId, "0-100");
    expect(first.success).toBe(true);
    
    const replay = await deNode.processOutboundPayment(proof, sgNode.nodeId, "0-100");
    expect(replay.success).toBe(false);
    expect(replay.error).toBe("REPLAY_DETECTED");
  });

  test("commitment chain integrity", async () => {
    const vault = new SovereignVault();
    const { publicKey } = vault.unlock("TestPass123Secure");
    vault.storeIdentity({ firstName: "A", lastName: "B", email: "a@b.c", phone: "+1", country: "DE" });
    deNode.registerVault(vault.vaultId, publicKey, vault._identityCommitment, "TIER_2");
    deNode.connectPeer(sgNode);
    
    const claims = { kycVerified: true, sanctionsClear: true, amlClear: true,
                     amountWithinLimits: true, corridorPermitted: true };
    
    // Process 3 payments to build a chain
    for (let i = 0; i < 3; i++) {
      const proof = vault.generateProof({ type: "PAYMENT", claims, recipientNodeId: sgNode.nodeId, amount: 50 });
      await deNode.processOutboundPayment(proof, sgNode.nodeId, "0-100");
    }
    
    // Verify chain
    expect(deNode.commitmentChain.length).toBe(3);
    expect(deNode.commitmentChain[0].previousHash).toBe("0".repeat(64));
    expect(deNode.commitmentChain[1].previousHash).toBe(deNode.commitmentChain[0].hash);
    expect(deNode.commitmentChain[2].previousHash).toBe(deNode.commitmentChain[1].hash);
  });

  test("bilateral settlement netting", async () => {
    const vault = new SovereignVault();
    const { publicKey } = vault.unlock("TestPass123Secure");
    vault.storeIdentity({ firstName: "A", lastName: "B", email: "a@b.c", phone: "+1", country: "DE" });
    deNode.registerVault(vault.vaultId, publicKey, vault._identityCommitment, "TIER_2");
    deNode.connectPeer(sgNode);
    
    const claims = { kycVerified: true, sanctionsClear: true, amlClear: true,
                     amountWithinLimits: true, corridorPermitted: true };
    
    // 3 outbound payments
    for (let i = 0; i < 3; i++) {
      const proof = vault.generateProof({ type: "PAYMENT", claims, recipientNodeId: sgNode.nodeId, amount: 100 });
      await deNode.processOutboundPayment(proof, sgNode.nodeId, "100-1000");
    }
    
    // Settle
    const settlement = deNode.settleWithPeer(sgNode.nodeId);
    expect(settlement.nodeA_owing).toBe(3);
    expect(settlement.commitmentsCovered).toBe(3);
    expect(settlement.fundMovement.method).toBe("BANKING_RAILS");
  });

  test("regulator audit returns local data only", () => {
    deNode.auditLog.push({
      type: "OUTBOUND_PAYMENT", commitmentId: "CMT-1",
      vaultId: "vault-1", receiverNode: "TN-SG",
      timestamp: new Date().toISOString()
    });
    
    // Local regulator succeeds
    const localAudit = deNode.handleAuditRequest({
      regulatorId: "BaFin",
      jurisdiction: "DE",
      scope: "ALL"
    });
    expect(localAudit.success).toBe(true);
    expect(localAudit.recordCount).toBe(1);
    
    // Foreign regulator rejected
    const foreignAudit = deNode.handleAuditRequest({
      regulatorId: "MAS",
      jurisdiction: "SG",
      scope: "ALL"
    });
    expect(foreignAudit.success).toBe(false);
    expect(foreignAudit.reason).toBe("JURISDICTION_MISMATCH");
  });
});

// ============================================================
// TRUST MESH
// ============================================================

describe("Trust Mesh", () => {
  let mesh;
  let deNode, frNode, sgNode;

  beforeEach(() => {
    mesh = new TrustMesh();
    deNode = new TrustNode({ jurisdiction: "DE", operatorName: "Deutsche Trust" });
    frNode = new TrustNode({ jurisdiction: "FR", operatorName: "France Trust" });
    sgNode = new TrustNode({ jurisdiction: "SG", operatorName: "Singapore Trust" });
    
    mesh.addNode(deNode);
    mesh.addNode(frNode);
    mesh.addNode(sgNode);
  });

  test("build mesh with corridors", () => {
    mesh.openCorridor(deNode, frNode);
    mesh.openCorridor(deNode, sgNode);
    mesh.openCorridor(frNode, sgNode);
    
    const topology = mesh.getTopology();
    expect(topology.nodeCount).toBe(3);
    expect(topology.corridorCount).toBe(3);
  });

  test("full cross-border payment through mesh (DE → SG)", async () => {
    mesh.openCorridor(deNode, sgNode);
    
    // Setup Alice's vault and register with DE node
    const aliceVault = new SovereignVault();
    const { publicKey } = aliceVault.unlock("AliceSecure2024!");
    aliceVault.storeIdentity({
      firstName: "Alice", lastName: "Schmidt",
      email: "alice@example.de", phone: "+49301234567",
      country: "DE", idNumber: "T22000129"
    });
    deNode.registerVault(aliceVault.vaultId, publicKey, aliceVault._identityCommitment, "TIER_2");
    
    // Execute payment
    const result = await mesh.executePayment({
      senderVault: aliceVault,
      senderNodeId: deNode.nodeId,
      receiverNodeId: sgNode.nodeId,
      amount: 100,
      currency: "EUR",
      claims: {
        kycVerified: true, tierSufficient: true,
        sanctionsClear: true, amlClear: true,
        amountWithinLimits: true, corridorPermitted: true
      }
    });
    
    expect(result.success).toBe(true);
    expect(result.proof.containsPII).toBe(false);
    expect(result.commitment.senderJurisdiction).toBe("DE");
    expect(result.commitment.receiverJurisdiction).toBe("SG");
    expect(result.settlement.method).toBe("BILATERAL_NETTING");
    
    // Verify SG node received commitment but has NO PII
    expect(sgNode.registeredVaults.size).toBe(0); // SG doesn't have Alice's data
  });

  test("verify chain integrity through mesh", async () => {
    mesh.openCorridor(deNode, sgNode);
    
    const vault = new SovereignVault();
    const { publicKey } = vault.unlock("TestPass123Secure");
    vault.storeIdentity({ firstName: "A", lastName: "B", email: "a@b.c", phone: "+1", country: "DE" });
    deNode.registerVault(vault.vaultId, publicKey, vault._identityCommitment, "TIER_2");
    
    const claims = { kycVerified: true, sanctionsClear: true, amlClear: true,
                     amountWithinLimits: true, corridorPermitted: true };
    
    for (let i = 0; i < 5; i++) {
      await mesh.executePayment({
        senderVault: vault,
        senderNodeId: deNode.nodeId,
        receiverNodeId: sgNode.nodeId,
        amount: 50,
        claims
      });
    }
    
    const integrity = mesh.verifyChainIntegrity(deNode.nodeId);
    expect(integrity.valid).toBe(true);
    expect(integrity.height).toBe(5);
  });

  test("mesh-wide settlement", async () => {
    mesh.openCorridor(deNode, sgNode);
    mesh.openCorridor(deNode, frNode);
    
    const vault = new SovereignVault();
    const { publicKey } = vault.unlock("TestPass123Secure");
    vault.storeIdentity({ firstName: "A", lastName: "B", email: "a@b.c", phone: "+1", country: "DE" });
    deNode.registerVault(vault.vaultId, publicKey, vault._identityCommitment, "TIER_2");
    
    const claims = { kycVerified: true, sanctionsClear: true, amlClear: true,
                     amountWithinLimits: true, corridorPermitted: true };
    
    // Payments to both corridors
    for (let i = 0; i < 3; i++) {
      await mesh.executePayment({
        senderVault: vault, senderNodeId: deNode.nodeId,
        receiverNodeId: sgNode.nodeId, amount: 100, claims
      });
      await mesh.executePayment({
        senderVault: vault, senderNodeId: deNode.nodeId,
        receiverNodeId: frNode.nodeId, amount: 200, claims
      });
    }
    
    const result = mesh.settleAll();
    expect(result.settlements.length).toBeGreaterThan(0);
    expect(result.corridorsSettled).toBeGreaterThan(0);
  });

  test("find route through intermediary nodes", () => {
    mesh.openCorridor(deNode, frNode);
    mesh.openCorridor(frNode, sgNode);
    // No direct DE-SG corridor
    
    const route = mesh.findRoute("DE", "SG");
    expect(route).not.toBeNull();
    expect(route.length).toBe(3); // DE → FR → SG
  });

  test("no route returns null", () => {
    // No corridors opened
    const route = mesh.findRoute("DE", "SG");
    expect(route).toBeNull();
  });
});

// ============================================================
// ADVERSARIAL: PROTOCOL ATTACKS
// ============================================================

describe("Protocol Attacks", () => {
  test("VULN-100: PII never in proof payload", () => {
    const vault = new SovereignVault();
    vault.unlock("TestPass123Secure");
    vault.storeIdentity({
      firstName: "Mohammed", lastName: "Al-Rashid",
      email: "mohammed@example.sa", phone: "+966501234567",
      country: "SA", idNumber: "SA-9988776655",
      address: "123 Riyadh Street, Saudi Arabia"
    });
    
    const proof = vault.generateProof({
      type: "PAYMENT",
      claims: { kycVerified: true, sanctionsClear: true, amlClear: true,
                amountWithinLimits: true, corridorPermitted: true },
      recipientNodeId: "TN-US",
      amount: 50000
    });
    
    const fullPayload = JSON.stringify(proof);
    
    // NONE of this should appear anywhere in the proof
    expect(fullPayload).not.toContain("Mohammed");
    expect(fullPayload).not.toContain("Al-Rashid");
    expect(fullPayload).not.toContain("mohammed@example");
    expect(fullPayload).not.toContain("+966");
    expect(fullPayload).not.toContain("SA-9988776655");
    expect(fullPayload).not.toContain("Riyadh");
    expect(fullPayload).not.toContain("Saudi");
    expect(fullPayload).not.toContain("50000"); // Amount hidden in commitment
    
    vault.lock();
  });

  test("VULN-101: Forged proof rejected", () => {
    const vault = new SovereignVault();
    vault.unlock("TestPass123Secure");
    vault.storeIdentity({ firstName: "A", lastName: "B", email: "a@b.c", phone: "+1", country: "US" });
    
    const realProof = vault.generateProof({
      type: "PAYMENT",
      claims: { kycVerified: true, sanctionsClear: true, amlClear: true,
                amountWithinLimits: true, corridorPermitted: true },
      recipientNodeId: "TN-SG",
      amount: 100
    });
    
    // Attacker creates a fake proof with real structure but different key
    const attackerVault = new SovereignVault();
    attackerVault.unlock("AttackerPass2024!");
    
    const forgedProof = {
      payload: realProof.payload,
      signature: realProof.signature,
      publicKey: attackerVault._signingKeyPair.publicKey
        .export({ type: "spki", format: "der" })
        .toString("base64")
    };
    
    const result = SovereignVault.verifyProof(forgedProof);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("SIGNATURE_INVALID");
    
    vault.lock();
    attackerVault.lock();
  });

  test("VULN-102: Counter regression attack blocked", async () => {
    const deNode = new TrustNode({ jurisdiction: "DE", operatorName: "Test" });
    const sgNode = new TrustNode({ jurisdiction: "SG", operatorName: "Test" });
    deNode.connectPeer(sgNode);
    
    const vault = new SovereignVault();
    const { publicKey } = vault.unlock("TestPass123Secure");
    vault.storeIdentity({ firstName: "A", lastName: "B", email: "a@b.c", phone: "+1", country: "DE" });
    deNode.registerVault(vault.vaultId, publicKey, vault._identityCommitment, "TIER_2");
    
    const claims = { kycVerified: true, sanctionsClear: true, amlClear: true,
                     amountWithinLimits: true, corridorPermitted: true };
    
    // Send two proofs normally (counter: 1, 2)
    const p1 = vault.generateProof({ type: "PAYMENT", claims, recipientNodeId: sgNode.nodeId, amount: 50 });
    await deNode.processOutboundPayment(p1, sgNode.nodeId, "0-100");
    
    const p2 = vault.generateProof({ type: "PAYMENT", claims, recipientNodeId: sgNode.nodeId, amount: 50 });
    await deNode.processOutboundPayment(p2, sgNode.nodeId, "0-100");
    
    // Attacker replays p1 (counter: 1, which is < current counter 2)
    const replay = await deNode.processOutboundPayment(p1, sgNode.nodeId, "0-100");
    expect(replay.success).toBe(false);
    // Will be REPLAY_DETECTED (same proofId)
    expect(replay.error).toBe("REPLAY_DETECTED");
    
    vault.lock();
  });

  test("VULN-103: Foreign regulator cannot access local PII", () => {
    const deNode = new TrustNode({ jurisdiction: "DE", operatorName: "Test" });
    
    // Chinese regulator tries to audit German node
    const result = deNode.handleAuditRequest({
      regulatorId: "PBOC",
      jurisdiction: "CN",
      scope: "ALL"
    });
    
    expect(result.success).toBe(false);
    expect(result.reason).toBe("JURISDICTION_MISMATCH");
    expect(result.message).toContain("contact the CN Trust Node");
  });

  test("VULN-104: Unregistered vault rejected", async () => {
    const deNode = new TrustNode({ jurisdiction: "DE", operatorName: "Test" });
    const sgNode = new TrustNode({ jurisdiction: "SG", operatorName: "Test" });
    deNode.connectPeer(sgNode);
    
    // Vault NOT registered with DE node
    const rogueVault = new SovereignVault();
    rogueVault.unlock("RoguePass2024!");
    rogueVault.storeIdentity({ firstName: "X", lastName: "Y", email: "x@y.z", phone: "+1", country: "DE" });
    
    const proof = rogueVault.generateProof({
      type: "PAYMENT",
      claims: { kycVerified: true, sanctionsClear: true, amlClear: true,
                amountWithinLimits: true, corridorPermitted: true },
      recipientNodeId: sgNode.nodeId,
      amount: 100
    });
    
    const result = await deNode.processOutboundPayment(proof, sgNode.nodeId, "0-100");
    expect(result.success).toBe(false);
    expect(result.error).toBe("VAULT_NOT_REGISTERED");
    
    rogueVault.lock();
  });
});
