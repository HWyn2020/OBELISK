/**
 * INTEGRATION TESTS — End-to-End Pipeline
 * 
 * These tests prove all 5 layers are connected:
 *   Payment Engine ← → KYC ← → AML ← → TimeLock ← → SPP (Vault/Trust/Mesh)
 * 
 * Before the orchestrator, these were 5 isolated islands.
 * Now: one pipeline drives everything.
 */

const { PaymentOrchestrator } = require("../src/core/orchestrator");
const { PaymentEngine } = require("../src/core/payment-engine");
const { KYCFramework } = require("../src/kyc/framework");
const { AMLFramework } = require("../src/aml/framework");
const { TimeLockEngine } = require("../src/contracts/timelock");
const { EncryptionEngine } = require("../src/crypto/encryption");
const { EnhancedSanctionsScreener } = require("../src/core/enhanced-sanctions");
const { FXService } = require("../src/core/fx-service");
const { TrustMesh } = require("../src/trust/trust-mesh");
const { TrustNode } = require("../src/trust/trust-node");

// ════════════════════════════════════════════════════════════
// TEST INFRASTRUCTURE
// ════════════════════════════════════════════════════════════

function buildFullStack() {
  // In-memory payment DB
  const db = {
    _store: new Map(),
    create: async (p) => db._store.set(p.id, JSON.parse(JSON.stringify(p))),
    findById: async (id) => {
      const p = db._store.get(id);
      return p ? JSON.parse(JSON.stringify(p)) : null;
    },
    findByIdempotencyKey: async (key) => {
      for (const p of db._store.values()) {
        if (p.idempotencyKey === key) return JSON.parse(JSON.stringify(p));
      }
      return null;
    },
    update: async (p) => db._store.set(p.id, JSON.parse(JSON.stringify(p)))
  };
  
  // Services
  const masterKey = EncryptionEngine.generateMasterKey();
  const encryption = new EncryptionEngine({ masterKey });
  const fxService = new FXService();
  const sanctions = new EnhancedSanctionsScreener();
  sanctions.loadLists();
  
  const paymentEngine = new PaymentEngine({
    db, fxService, sanctionsScreener: sanctions,
    config: { maxAmount: 1000000 }
  });
  
  const kycFramework = new KYCFramework({ encryption, db: null, sanctionsScreener: sanctions });
  const amlFramework = new AMLFramework({ reportingThreshold: 10000 });
  const timeLockEngine = new TimeLockEngine({ fxService, paymentEngine });
  
  // Trust Mesh
  const trustMesh = new TrustMesh();
  const deNode = new TrustNode({ jurisdiction: "DE", operatorName: "Deutsche Bank" });
  const sgNode = new TrustNode({ jurisdiction: "SG", operatorName: "DBS Bank" });
  const usNode = new TrustNode({ jurisdiction: "US", operatorName: "JPMorgan" });
  
  trustMesh.addNode(deNode);
  trustMesh.addNode(sgNode);
  trustMesh.addNode(usNode);
  trustMesh.openCorridor(deNode, sgNode);
  trustMesh.openCorridor(deNode, usNode);
  trustMesh.openCorridor(sgNode, usNode);
  
  // Orchestrator
  const orchestrator = new PaymentOrchestrator({
    paymentEngine, kycFramework, amlFramework,
    timeLockEngine, encryption, trustMesh, fxService
  });
  
  return { orchestrator, trustMesh, deNode, sgNode, usNode, db };
}

const PASSPHRASE = "IntegrationTest2024!Secure";

// ════════════════════════════════════════════════════════════
// INTEGRATION TESTS
// ════════════════════════════════════════════════════════════

describe("End-to-End Integration", () => {
  let stack;
  
  beforeEach(() => {
    stack = buildFullStack();
  });
  
  test("INT-001: Full lifecycle — onboard → pay → settle", async () => {
    /**
     * The big one. Proves all 5 layers are connected:
     *   1. KYC onboarding creates encrypted profile
     *   2. Vault stores identity (never transmitted)
     *   3. Trust Node registers vault
     *   4. Payment triggers AML check
     *   5. Vault generates Sovereign Proof (zero PII)
     *   6. Trust Node validates proof + creates commitment
     *   7. Receiver node accepts commitment
     *   8. Payment Engine runs state machine
     *   9. Settlement via bilateral netting
     */
    const { orchestrator, deNode, sgNode } = stack;
    
    // Step 1: Onboard customer (KYC + Vault + Trust Node)
    const onboard = await orchestrator.onboardCustomer({
      firstName: "Alice",
      lastName: "Müller",
      email: "alice@example.de",
      phone: "+49170000000",
      country: "DE"
    }, PASSPHRASE);
    
    expect(onboard.success).toBe(true);
    expect(onboard.customerId).toBeDefined();
    expect(onboard.vaultId).toBeDefined();
    expect(onboard.nodeId).toBeDefined(); // Registered with DE node
    expect(onboard.kycTier).toBe("TIER_1");
    expect(onboard.identityCommitment).toBeDefined();
    
    // Step 2: Execute sovereign payment (ALL layers)
    const payment = await orchestrator.executeSovereignPayment({
      senderCustomerId: onboard.customerId,
      receiverNodeId: sgNode.nodeId,
      amount: 500,
      sendCurrency: "EUR",
      receiveCurrency: "SGD",
      beneficiary: {
        name: "Bob Tan",
        country: "SG"
      },
      purpose: "Family support"
    });
    
    expect(payment.success).toBe(true);
    
    // Payment Engine completed
    expect(payment.paymentId).toBeDefined();
    expect(payment.state).toBe("COMPLETED");
    expect(payment.settlementReference).toBeDefined();
    
    // FX executed
    expect(payment.sendAmount).toBe(500);
    expect(payment.receiveAmount).toBeGreaterThan(0);
    expect(payment.rate).toBeDefined();
    
    // Sovereign Proof generated (ZERO PII)
    expect(payment.proof.id).toBeDefined();
    expect(payment.proof.containsPII).toBe(false);
    expect(payment.proof.attestations).toContain("kyc");
    expect(payment.proof.attestations).toContain("sanctions");
    expect(payment.proof.attestations).toContain("aml");
    
    // Trust Mesh commitment
    expect(payment.mesh).not.toBeNull();
    expect(payment.mesh.commitmentId).toBeDefined();
    expect(payment.mesh.acknowledgmentId).toBeDefined();
    expect(payment.mesh.senderNode).toBe(onboard.nodeId);
    expect(payment.mesh.receiverNode).toBe(sgNode.nodeId);
    
    // Compliance
    expect(payment.compliance.kycLimitCheck).toBe("PASSED");
    expect(payment.compliance.amlAction).toBe("PASS");
    expect(payment.compliance.sanctionsStatus).toBe("CLEAR");
    
    // Settlement
    expect(payment.settlement.method).toBe("BILATERAL_NETTING");
    
    // Step 3: Settle the mesh
    const settlement = orchestrator.settleAll();
    expect(settlement.settledAt).toBeDefined();
  });
  
  test("INT-002: KYC limit enforcement blocks oversized payment", async () => {
    const { orchestrator, sgNode } = stack;
    
    const onboard = await orchestrator.onboardCustomer({
      firstName: "Bob", lastName: "Smith",
      email: "bob@example.com", phone: "+1234567890",
      country: "DE"
    }, PASSPHRASE);
    
    expect(onboard.success).toBe(true);
    expect(onboard.kycTier).toBe("TIER_1"); // Limit: €1,000/transaction
    
    // Try to send €5,000 on TIER_1
    const payment = await orchestrator.executeSovereignPayment({
      senderCustomerId: onboard.customerId,
      receiverNodeId: sgNode.nodeId,
      amount: 5000,
      sendCurrency: "EUR",
      receiveCurrency: "SGD",
      beneficiary: { name: "Test", country: "SG" }
    });
    
    expect(payment.success).toBe(false);
    expect(payment.phase).toBe("KYC_LIMITS");
    expect(payment.error).toBe("LIMIT_EXCEEDED");
  });
  
  test("INT-003: AML blocks high-risk corridor payment", async () => {
    /**
     * Customer in good KYC standing attempts payment to a high-risk
     * jurisdiction. AML should detect and block.
     */
    const { orchestrator, sgNode } = stack;
    
    const onboard = await orchestrator.onboardCustomer({
      firstName: "Carol", lastName: "Davis",
      email: "carol@example.de", phone: "+49170111111",
      country: "DE"
    }, PASSPHRASE);
    
    // Pay to a FATF high-risk country
    const payment = await orchestrator.executeSovereignPayment({
      senderCustomerId: onboard.customerId,
      receiverNodeId: sgNode.nodeId,
      amount: 100,
      sendCurrency: "EUR",
      receiveCurrency: "KPW",
      beneficiary: { name: "Test", country: "KP" } // North Korea
    });
    
    expect(payment.success).toBe(false);
    expect(payment.phase).toBe("AML");
    expect(payment.error).toBe("AML_BLOCKED");
  });
  
  test("INT-004: Sanctions match blocks at onboarding", async () => {
    const { orchestrator } = stack;
    
    // Name that matches sanctions list
    const onboard = await orchestrator.onboardCustomer({
      firstName: "Ivan",
      lastName: "Petrov",
      email: "ivan@example.com",
      phone: "+79001234567",
      country: "DE" // Country doesn't matter, name matches
    }, PASSPHRASE);
    
    expect(onboard.success).toBe(false);
    expect(onboard.phase).toBe("KYC");
    expect(onboard.error).toBe("BLOCKED_SANCTIONS");
  });
  
  test("INT-005: Multiple payments accumulate in AML history", async () => {
    const { orchestrator, sgNode } = stack;
    
    const onboard = await orchestrator.onboardCustomer({
      firstName: "Eve", lastName: "Johnson",
      email: "eve@example.de", phone: "+49170222222",
      country: "DE"
    }, PASSPHRASE);
    
    // Send 3 payments — each should succeed and add to AML history
    for (let i = 0; i < 3; i++) {
      const payment = await orchestrator.executeSovereignPayment({
        senderCustomerId: onboard.customerId,
        receiverNodeId: sgNode.nodeId,
        amount: 200,
        sendCurrency: "EUR",
        receiveCurrency: "SGD",
        beneficiary: { name: "Recipient", country: "SG" }
      });
      expect(payment.success).toBe(true);
    }
    
    // Verify transaction history accumulated
    const status = orchestrator.getCustomerStatus(onboard.customerId);
    expect(status.transactionCount).toBe(3);
  });
  
  test("INT-006: TimeLock payment runs compliance then creates contract", async () => {
    const { orchestrator, sgNode } = stack;
    
    const onboard = await orchestrator.onboardCustomer({
      firstName: "Frank", lastName: "Weber",
      email: "frank@example.de", phone: "+49170333333",
      country: "DE"
    }, PASSPHRASE);
    
    const result = await orchestrator.executeTimeLockPayment({
      senderCustomerId: onboard.customerId,
      receiverNodeId: sgNode.nodeId,
      amount: 500,
      sendCurrency: "EUR",
      receiveCurrency: "SGD",
      beneficiary: { name: "Test", country: "SG" },
      fallbackTier: "DEDUCTED",
      maxDurationHours: 24
    });
    
    expect(result.success).toBe(true);
    expect(result.type).toBe("TIMELOCK");
    expect(result.contractId).toBeDefined();
    expect(result.contract.breakEvenRate).toBeGreaterThan(0);
    expect(result.contract.state).toMatch(/CREATED|ACTIVE/);
    
    // All 3 tier options should be present
    expect(result.options.instant).toBeDefined();
    expect(result.options.deducted).toBeDefined();
    expect(result.options.timeLock).toBeDefined();
    
    // Compliance was checked
    expect(result.compliance.kycTier).toBe("TIER_1");
    expect(result.compliance.amlAction).toBe("PASS");
    
    // Proof was generated
    expect(result.proof.id).toBeDefined();
  });
  
  test("INT-007: Mesh topology visible and verifiable", async () => {
    const { orchestrator } = stack;
    
    const topology = orchestrator.getMeshTopology();
    
    expect(topology.nodeCount).toBe(3); // DE, SG, US
    expect(topology.corridorCount).toBe(3); // DE-SG, DE-US, SG-US
    expect(topology.nodes.length).toBe(3);
    expect(topology.corridors.length).toBe(3);
    
    // Each node should have 2 peers (fully connected 3-node mesh)
    for (const node of topology.nodes) {
      expect(node.peers).toBe(2);
    }
  });
  
  test("INT-008: Chain integrity verifiable after payment", async () => {
    const { orchestrator, sgNode, deNode } = stack;
    
    const onboard = await orchestrator.onboardCustomer({
      firstName: "Grace", lastName: "Kim",
      email: "grace@example.de", phone: "+49170444444",
      country: "DE"
    }, PASSPHRASE);
    
    await orchestrator.executeSovereignPayment({
      senderCustomerId: onboard.customerId,
      receiverNodeId: sgNode.nodeId,
      amount: 300,
      sendCurrency: "EUR",
      receiveCurrency: "SGD",
      beneficiary: { name: "Test", country: "SG" }
    });
    
    // Verify DE node chain integrity
    const integrity = orchestrator.verifyNodeIntegrity(deNode.nodeId);
    expect(integrity.valid).toBe(true);
    expect(integrity.height).toBeGreaterThan(0);
  });
  
  test("INT-009: Unknown customer rejected", async () => {
    const { orchestrator, sgNode } = stack;
    
    const payment = await orchestrator.executeSovereignPayment({
      senderCustomerId: "00000000-0000-0000-0000-000000000000",
      receiverNodeId: sgNode.nodeId,
      amount: 100,
      sendCurrency: "EUR",
      receiveCurrency: "SGD",
      beneficiary: { name: "Test", country: "SG" }
    });
    
    expect(payment.success).toBe(false);
    expect(payment.error).toBe("CUSTOMER_NOT_FOUND");
  });
  
  test("INT-010: Full flow — proof contains ZERO PII even with rich identity", async () => {
    /**
     * The protocol's core promise: PII never leaves the vault.
     * This test uses Arabic names and addresses to verify no script leaks.
     */
    const { orchestrator, sgNode } = stack;
    
    const onboard = await orchestrator.onboardCustomer({
      firstName: "أحمد",        // Ahmed (not on sanctions list)
      lastName: "السعيد",      // Al-Saeed
      email: "ahmed@test.sa",
      phone: "+966501234567",
      country: "DE", // Living in Germany
      address: "الرياض, المملكة العربية السعودية"
    }, PASSPHRASE);
    
    expect(onboard.success).toBe(true);
    
    const payment = await orchestrator.executeSovereignPayment({
      senderCustomerId: onboard.customerId,
      receiverNodeId: sgNode.nodeId,
      amount: 800,
      sendCurrency: "EUR",
      receiveCurrency: "SGD",
      beneficiary: { name: "Test", country: "SG" }
    });
    
    expect(payment.success).toBe(true);
    
    // Stringify entire payment response and check for PII
    const responseJson = JSON.stringify(payment);
    expect(responseJson).not.toContain("أحمد");
    expect(responseJson).not.toContain("السعيد");
    expect(responseJson).not.toContain("ahmed");
    expect(responseJson).not.toContain("test.sa");
    expect(responseJson).not.toContain("+966");
    expect(responseJson).not.toContain("الرياض");
  });
});

describe("Pipeline Connectivity Proof", () => {
  
  test("INT-011: Orchestrator has all 5 layer references", () => {
    const stack = buildFullStack();
    const o = stack.orchestrator;
    
    // All 5 islands are connected
    expect(o.payments).toBeDefined();     // Island 1: Payment Engine
    expect(o.kyc).toBeDefined();          // Island 2: KYC Framework
    expect(o.aml).toBeDefined();          // Island 3: AML Framework
    expect(o.timeLock).toBeDefined();     // Island 4: TimeLock Engine
    expect(o.mesh).toBeDefined();         // Island 5: Trust Mesh (Vault + Nodes)
    expect(o.encryption).toBeDefined();   // Cross-cutting: Encryption
    expect(o.fx).toBeDefined();           // Cross-cutting: FX Service
  });
  
  test("INT-012: Single payment touches all 5 layers", async () => {
    /**
     * The definitive connectivity test. One payment must:
     *   ✓ Create KYC profile (Island 2)
     *   ✓ Check AML patterns (Island 3)  
     *   ✓ Generate Sovereign Proof via Vault (Island 5)
     *   ✓ Process through Trust Node (Island 5)
     *   ✓ Run Payment Engine state machine (Island 1)
     *   ✓ Use Encryption for storage (Cross-cutting)
     *   ✓ Use FX Service for rate (Cross-cutting)
     */
    const stack = buildFullStack();
    const { orchestrator, sgNode, deNode, db } = stack;
    
    // Onboard (KYC + Vault + Trust Node)
    const onboard = await orchestrator.onboardCustomer({
      firstName: "Test", lastName: "User",
      email: "test@example.de", phone: "+49170555555",
      country: "DE"
    }, PASSPHRASE);
    
    // Pay (AML + Proof + Trust Mesh + Payment Engine)
    const payment = await orchestrator.executeSovereignPayment({
      senderCustomerId: onboard.customerId,
      receiverNodeId: sgNode.nodeId,
      amount: 250,
      sendCurrency: "EUR",
      receiveCurrency: "SGD",
      beneficiary: { name: "Receiver", country: "SG" }
    });
    
    // ── Verify all 5 layers were touched ──────────────
    
    // Island 1: Payment Engine — record exists in DB
    expect(payment.paymentId).toBeDefined();
    const dbPayment = await db.findById(payment.paymentId);
    expect(dbPayment).not.toBeNull();
    expect(dbPayment.state).toBe("COMPLETED");
    expect(dbPayment.stateHistory.length).toBeGreaterThanOrEqual(6); // All transitions
    
    // Island 2: KYC — tier was checked
    expect(payment.compliance.kycTier).toBe("TIER_1");
    expect(payment.compliance.kycLimitCheck).toBe("PASSED");
    
    // Island 3: AML — analysis ran
    expect(payment.compliance.amlAction).toBe("PASS");
    
    // Island 4: (TimeLock not used in this path, but available)
    // Tested separately in INT-006
    
    // Island 5: SPP — proof generated, mesh processed
    expect(payment.proof.id).toBeDefined();
    expect(payment.proof.containsPII).toBe(false);
    expect(payment.mesh.commitmentId).toBeDefined();
    
    // Cross-cutting: FX rate applied
    expect(payment.rate).toBeDefined();
    expect(payment.receiveAmount).toBeGreaterThan(0);
    
    // Cross-cutting: Encryption used (sender name is encrypted in DB)
    expect(dbPayment.sender.name).toMatch(/^v\d+:/); // Encrypted format
    
    // Cross-cutting: DE node chain grew
    expect(deNode.commitmentChain.length).toBeGreaterThan(0);
    
    // Cross-cutting: SG node received commitment
    expect(sgNode.auditLog.length).toBeGreaterThan(0);
  });
});
