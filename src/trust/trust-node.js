/**
 * Trust Node
 * 
 * A jurisdiction-aware settlement peer in the decentralized mesh.
 * Each node represents one jurisdiction (DE, FR, SG, etc.).
 * 
 * Responsibilities:
 *   - Verify Sovereign Proofs from local citizens (has PII)
 *   - Verify Sovereign Proofs from foreign citizens (proof-only, no PII)
 *   - Maintain a hash-linked commitment chain (tamper-evident log)
 *   - Bilateral netting with connected peer nodes
 *   - Respond to regulator audit requests (local PII only)
 *   - Propagate settlement commitments to peer nodes
 * 
 * Trust model:
 *   Each node is operated by a licensed institution in its jurisdiction.
 *   Nodes trust each other's PROOFS, not each other's data.
 *   Byzantine fault tolerant: system works if ≤ ⅓ of nodes are compromised.
 */

const crypto = require("crypto");
const logger = require("../utils/logger");
const { SovereignVault } = require("../vault/sovereign-vault");

// Settlement windows
const SETTLEMENT_INTERVAL_MS = 3600000; // 1 hour
const COMMITMENT_EXPIRY_MS = 86400000;  // 24 hours

// Commitment states
const COMMITMENT_STATES = {
  PENDING: "PENDING",         // Waiting for receiver's node to acknowledge
  ACKNOWLEDGED: "ACKNOWLEDGED", // Receiver's node accepted
  SETTLED: "SETTLED",          // Net settlement complete
  DISPUTED: "DISPUTED",       // Proof verification failed
  EXPIRED: "EXPIRED"
};

class TrustNode {
  /**
   * @param {Object} options
   * @param {string} options.jurisdiction - ISO 3166-1 alpha-2 (e.g., "DE")
   * @param {string} options.nodeId - Unique node identifier
   * @param {string} options.operatorName - Licensed institution name
   */
  constructor(options) {
    this.jurisdiction = options.jurisdiction;
    this.nodeId = options.nodeId || `TN-${options.jurisdiction}-${crypto.randomBytes(4).toString("hex")}`;
    this.operatorName = options.operatorName;
    
    // Node signing key pair (Ed25519)
    this._keyPair = crypto.generateKeyPairSync("ed25519");
    this.publicKey = this._keyPair.publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64");
    
    // Connected peer nodes
    this.peers = new Map(); // nodeId → { jurisdiction, publicKey, lastSeen }
    
    // Commitment chain (hash-linked, like blockchain but bilateral)
    this.commitmentChain = [];
    this.chainHead = "0".repeat(64); // Genesis hash
    
    // Bilateral netting ledgers (per peer)
    this.nettingLedgers = new Map(); // peerNodeId → { owed, owing, commitments[] }
    
    // Known vault public keys (for local citizens)
    this.registeredVaults = new Map(); // vaultId → { publicKey, identityCommitment, kycTier }
    
    // Audit log (for regulator requests)
    this.auditLog = [];
    
    // Replay protection
    this._seenProofIds = new Set();
    this._seenCounters = new Map(); // vaultId → lastCounter
    this._seenCommitmentIds = new Set(); // FIX PEN-401: Track commitment IDs on receiver
    
    // FIX PEN-600: Bounded size for replay protection sets
    this._maxSeenProofIds = 50000;
    this._maxSeenCommitmentIds = 50000;
    
    logger.info("Trust Node initialized", {
      nodeId: this.nodeId,
      jurisdiction: this.jurisdiction,
      operator: this.operatorName
    });
  }
  
  /**
   * Register a local citizen's vault
   * Only the citizen's HOME jurisdiction node holds their PII mapping
   */
  registerVault(vaultId, publicKey, identityCommitment, kycTier) {
    // SECURITY: Reject duplicate identity commitments (prevents multi-vault bypass)
    for (const [existingId, existing] of this.registeredVaults) {
      if (existing.identityCommitment === identityCommitment && existingId !== vaultId) {
        return {
          registered: false,
          error: "DUPLICATE_IDENTITY",
          reason: "Identity commitment already registered on this node"
        };
      }
    }
    
    this.registeredVaults.set(vaultId, {
      publicKey,
      identityCommitment,
      kycTier,
      registeredAt: new Date().toISOString(),
      lastActivity: null
    });
    
    logger.info("Vault registered with Trust Node", {
      nodeId: this.nodeId,
      vaultId,
      tier: kycTier
    });
    
    return { registered: true, nodeId: this.nodeId, jurisdiction: this.jurisdiction };
  }
  
  /**
   * Connect to a peer Trust Node
   */
  connectPeer(peerNode) {
    this.peers.set(peerNode.nodeId, {
      jurisdiction: peerNode.jurisdiction,
      publicKey: peerNode.publicKey,
      lastSeen: new Date().toISOString()
    });
    
    // Initialize bilateral netting ledger
    if (!this.nettingLedgers.has(peerNode.nodeId)) {
      this.nettingLedgers.set(peerNode.nodeId, {
        owed: 0,     // They owe us
        owing: 0,    // We owe them
        commitments: [],
        lastSettlement: null
      });
    }
    
    // Mutual connection
    if (!peerNode.peers.has(this.nodeId)) {
      peerNode.connectPeer(this);
    }
    
    logger.info("Peer connected", {
      nodeId: this.nodeId,
      peerId: peerNode.nodeId,
      corridor: `${this.jurisdiction}↔${peerNode.jurisdiction}`
    });
  }
  
  /**
   * Process an outbound payment (sender is on this node)
   * 
   * 1. Verify the sender's Sovereign Proof (we have their PII)
   * 2. Create a Settlement Commitment
   * 3. Send commitment to receiver's Trust Node
   */
  async processOutboundPayment(proof, receiverNodeId, amountRange) {
    // Step 1: Verify proof
    const verification = SovereignVault.verifyProof(proof);
    if (!verification.valid) {
      return {
        success: false,
        error: "PROOF_INVALID",
        reason: verification.reason
      };
    }
    
    // Replay protection
    if (this._seenProofIds.has(verification.proofId)) {
      return { success: false, error: "REPLAY_DETECTED", reason: "Proof ID already used" };
    }
    this._seenProofIds.add(verification.proofId);
    // FIX PEN-600: Evict oldest entries when set exceeds max size
    if (this._seenProofIds.size > this._maxSeenProofIds) {
      const first = this._seenProofIds.values().next().value;
      this._seenProofIds.delete(first);
    }
    
    // Counter monotonicity check
    const lastCounter = this._seenCounters.get(proof.payload.vaultId) || 0;
    if (verification.counter <= lastCounter) {
      return { success: false, error: "COUNTER_REGRESSION", reason: "Proof counter not monotonically increasing" };
    }
    this._seenCounters.set(proof.payload.vaultId, verification.counter);
    
    // Step 2: Verify vault is registered locally
    const vault = this.registeredVaults.get(proof.payload.vaultId);
    if (!vault) {
      return { success: false, error: "VAULT_NOT_REGISTERED", reason: "Sender not registered on this node" };
    }
    
    // Verify identity commitment matches
    if (vault.identityCommitment !== verification.identityCommitment) {
      return { success: false, error: "IDENTITY_MISMATCH", reason: "Identity commitment doesn't match registration" };
    }
    
    // SECURITY: Verify proof's signing key matches registered vault key
    if (proof.publicKey !== vault.publicKey) {
      return { success: false, error: "PUBLIC_KEY_MISMATCH", reason: "Proof signed by unregistered key" };
    }
    
    // Step 3: Verify attestations
    const att = verification.attestations;
    if (!att.kyc?.value) return { success: false, error: "KYC_NOT_VERIFIED" };
    if (!att.sanctions?.value) return { success: false, error: "SANCTIONS_FLAGGED" };
    if (!att.aml?.value) return { success: false, error: "AML_FLAGGED" };
    if (!att.limits?.value) return { success: false, error: "LIMIT_EXCEEDED" };
    if (!att.corridor?.value) return { success: false, error: "CORRIDOR_BLOCKED" };
    
    // Step 4: Check receiver node exists in our peer list
    if (!this.peers.has(receiverNodeId)) {
      return { success: false, error: "PEER_NOT_CONNECTED", reason: `Not connected to ${receiverNodeId}` };
    }
    
    // SECURITY: Verify proof was intended for this receiver (recipient binding)
    if (proof.payload.recipientNodeId !== receiverNodeId) {
      return { success: false, error: "RECIPIENT_MISMATCH", reason: "Proof not intended for this receiver node" };
    }
    
    // Step 5: Create Settlement Commitment
    const commitment = this._createCommitment({
      proofHash: crypto.createHash("sha256").update(JSON.stringify(proof.payload)).digest("hex"),
      senderNodeId: this.nodeId,
      senderJurisdiction: this.jurisdiction,
      receiverNodeId,
      receiverJurisdiction: this.peers.get(receiverNodeId).jurisdiction,
      amountRange,
      proofId: verification.proofId
    });
    
    // Step 6: Update netting ledger
    const ledger = this.nettingLedgers.get(receiverNodeId);
    ledger.owing += 1; // Increment obligation count (amount is committed, not revealed)
    ledger.commitments.push(commitment.id);
    
    // Step 7: Audit log
    this.auditLog.push({
      type: "OUTBOUND_PAYMENT",
      commitmentId: commitment.id,
      proofId: verification.proofId,
      vaultId: proof.payload.vaultId,
      receiverNode: receiverNodeId,
      amountRange,
      timestamp: new Date().toISOString()
    });
    
    logger.info("Outbound payment processed", {
      nodeId: this.nodeId,
      commitmentId: commitment.id,
      corridor: `${this.jurisdiction}→${this.peers.get(receiverNodeId).jurisdiction}`
    });
    
    return {
      success: true,
      commitmentId: commitment.id,
      commitment,
      chain: {
        height: this.commitmentChain.length,
        head: this.chainHead
      }
    };
  }
  
  /**
   * Receive a commitment from a peer node (inbound payment)
   */
  async receiveCommitment(commitment, senderNodeSignature) {
    // Verify sender node's signature on the commitment
    const senderNode = this.peers.get(commitment.senderNodeId);
    if (!senderNode) {
      return { accepted: false, reason: "UNKNOWN_SENDER_NODE" };
    }
    
    const pubKey = crypto.createPublicKey({
      key: Buffer.from(senderNode.publicKey, "base64"),
      type: "spki",
      format: "der"
    });
    
    const commitmentBytes = Buffer.from(JSON.stringify(commitment), "utf8");
    const sigBuffer = Buffer.from(senderNodeSignature, "base64");
    
    const valid = crypto.verify(null, commitmentBytes, pubKey, sigBuffer);
    if (!valid) {
      return { accepted: false, reason: "INVALID_NODE_SIGNATURE" };
    }
    
    // SECURITY: Replay protection — reject duplicate commitment IDs
    if (this._seenCommitmentIds.has(commitment.id)) {
      return { accepted: false, reason: "COMMITMENT_REPLAY_DETECTED" };
    }
    this._seenCommitmentIds.add(commitment.id);
    
    // Verify commitment hasn't expired
    if (new Date(commitment.expiresAt) < new Date()) {
      return { accepted: false, reason: "COMMITMENT_EXPIRED" };
    }
    
    // Update netting ledger
    let ledger = this.nettingLedgers.get(commitment.senderNodeId);
    if (!ledger) {
      ledger = { owed: 0, owing: 0, commitments: [], lastSettlement: null };
      this.nettingLedgers.set(commitment.senderNodeId, ledger);
    }
    ledger.owed += 1;
    ledger.commitments.push(commitment.id);
    
    // Audit log
    this.auditLog.push({
      type: "INBOUND_COMMITMENT",
      commitmentId: commitment.id,
      senderNode: commitment.senderNodeId,
      amountRange: commitment.amountRange,
      timestamp: new Date().toISOString()
    });
    
    logger.info("Inbound commitment accepted", {
      nodeId: this.nodeId,
      commitmentId: commitment.id,
      from: commitment.senderJurisdiction
    });
    
    return {
      accepted: true,
      acknowledgmentId: crypto.randomUUID(),
      nodeId: this.nodeId
    };
  }
  
  /**
   * Perform bilateral netting settlement with a peer
   * 
   * Instead of settling each payment individually:
   *   If DE owes SG 50 payments and SG owes DE 30 payments,
   *   the net settlement is DE → SG for 20 payments' worth.
   */
  settleWithPeer(peerNodeId) {
    const ledger = this.nettingLedgers.get(peerNodeId);
    if (!ledger) {
      return { success: false, reason: "No ledger with this peer" };
    }
    
    const netPosition = ledger.owed - ledger.owing;
    
    const settlement = {
      id: `SETTLE-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
      nodeA: this.nodeId,
      nodeB: peerNodeId,
      
      // Net position
      nodeA_owed: ledger.owed,
      nodeA_owing: ledger.owing,
      netDirection: netPosition > 0 ? `${peerNodeId}→${this.nodeId}` : `${this.nodeId}→${peerNodeId}`,
      netObligations: Math.abs(netPosition),
      
      // Settlement details
      commitmentsCovered: ledger.commitments.length,
      settledAt: new Date().toISOString(),
      
      // Instructions for actual fund movement
      fundMovement: {
        method: "BANKING_RAILS", // TARGET2 for EU, FAST for SG, etc.
        from: netPosition > 0 ? peerNodeId : this.nodeId,
        to: netPosition > 0 ? this.nodeId : peerNodeId,
        note: "Net settlement via traditional banking — no PII in settlement"
      }
    };
    
    // Reset ledger
    ledger.owed = 0;
    ledger.owing = 0;
    ledger.commitments = [];
    ledger.lastSettlement = settlement.settledAt;
    
    // Audit
    this.auditLog.push({
      type: "SETTLEMENT",
      settlementId: settlement.id,
      peerNode: peerNodeId,
      netObligations: settlement.netObligations,
      timestamp: settlement.settledAt
    });
    
    logger.info("Settlement completed", {
      nodeId: this.nodeId,
      peer: peerNodeId,
      net: settlement.netObligations,
      direction: settlement.netDirection
    });
    
    return settlement;
  }
  
  /**
   * Sign a commitment with this node's key
   */
  signCommitment(commitment) {
    const commitmentBytes = Buffer.from(JSON.stringify(commitment), "utf8");
    const signature = crypto.sign(null, commitmentBytes, this._keyPair.privateKey);
    return signature.toString("base64");
  }
  
  /**
   * Respond to a regulator audit request
   * 
   * CRITICAL: This only returns data for LOCAL citizens.
   * Foreign citizen data is NEVER held here.
   */
  handleAuditRequest(request) {
    const { regulatorId, jurisdiction, scope, timeRange } = request;
    
    // Only respond to our own jurisdiction's regulator
    if (jurisdiction !== this.jurisdiction) {
      return {
        success: false,
        reason: "JURISDICTION_MISMATCH",
        message: `This node operates in ${this.jurisdiction}, not ${jurisdiction}. Please contact the ${jurisdiction} Trust Node.`
      };
    }
    
    // Filter audit log by scope and time
    let records = this.auditLog;
    
    if (timeRange) {
      const start = new Date(timeRange.from).getTime();
      const end = new Date(timeRange.to).getTime();
      records = records.filter(r => {
        const t = new Date(r.timestamp).getTime();
        return t >= start && t <= end;
      });
    }
    
    if (scope === "OUTBOUND_ONLY") {
      records = records.filter(r => r.type === "OUTBOUND_PAYMENT");
    } else if (scope === "INBOUND_ONLY") {
      records = records.filter(r => r.type === "INBOUND_COMMITMENT");
    } else if (scope === "SETTLEMENTS") {
      records = records.filter(r => r.type === "SETTLEMENT");
    }
    
    return {
      success: true,
      nodeId: this.nodeId,
      jurisdiction: this.jurisdiction,
      respondedAt: new Date().toISOString(),
      recordCount: records.length,
      records,
      note: "PII for local citizens available upon separate data access request through proper legal channels."
    };
  }
  
  /**
   * Get node status and mesh topology
   */
  getStatus() {
    const peerList = [];
    for (const [id, peer] of this.peers) {
      const ledger = this.nettingLedgers.get(id);
      peerList.push({
        nodeId: id,
        jurisdiction: peer.jurisdiction,
        lastSeen: peer.lastSeen,
        netPosition: ledger ? ledger.owed - ledger.owing : 0,
        pendingCommitments: ledger ? ledger.commitments.length : 0
      });
    }
    
    return {
      nodeId: this.nodeId,
      jurisdiction: this.jurisdiction,
      operator: this.operatorName,
      
      chain: {
        height: this.commitmentChain.length,
        head: this.chainHead
      },
      
      peers: peerList,
      peerCount: this.peers.size,
      
      registeredVaults: this.registeredVaults.size,
      auditLogEntries: this.auditLog.length,
      
      uptime: process.uptime(),
      timestamp: new Date().toISOString()
    };
  }
  
  // ========== INTERNAL METHODS ==========
  
  /**
   * Create a hash-linked commitment (like a blockchain block)
   */
  _createCommitment(data) {
    const commitment = {
      id: `CMT-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
      previousHash: this.chainHead,
      height: this.commitmentChain.length,
      
      ...data,
      
      state: COMMITMENT_STATES.PENDING,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + COMMITMENT_EXPIRY_MS).toISOString()
    };
    
    // Hash this commitment (includes previous hash → chain linkage)
    commitment.hash = crypto
      .createHash("sha256")
      .update(JSON.stringify(commitment))
      .digest("hex");
    
    // Append to chain
    this.commitmentChain.push(commitment);
    this.chainHead = commitment.hash;
    
    return commitment;
  }
}

module.exports = { TrustNode, COMMITMENT_STATES };
