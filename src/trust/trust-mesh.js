/**
 * Trust Mesh
 * 
 * Orchestrates the decentralized settlement network.
 * 
 * Think of this as the "network layer" — it manages:
 *   - Node discovery and connection
 *   - Commitment propagation between nodes
 *   - Settlement scheduling across the mesh
 *   - Network health monitoring
 *   - Byzantine fault detection
 * 
 * TOPOLOGY:
 * 
 *   Unlike Bitcoin's fully-connected gossip network, the Trust Mesh
 *   uses a corridor-based topology. Nodes only connect to jurisdictions
 *   they have bilateral settlement agreements with.
 *   
 *   DE ─── FR ─── NL
 *   │      │      │
 *   AT ─── IT ─── BE
 *   │             │
 *   CH ─── SG ─── US
 * 
 *   A payment from DE → SG follows the path:
 *   DE ─── (direct if connected) ─── SG
 *   OR
 *   DE ─── AT ─── CH ─── SG (routed through intermediaries)
 * 
 * SETTLEMENT:
 * 
 *   Instead of settling each payment individually (like SWIFT),
 *   nodes accumulate obligations and net them bilaterally:
 *   
 *   If DE→SG has 50 payments and SG→DE has 30 payments,
 *   the net settlement is ONE fund movement: DE sends SG the
 *   net difference via existing banking rails (TARGET2, FAST, etc.)
 *   
 *   This dramatically reduces actual fund movements while maintaining
 *   real-time payment UX for end users (payment is confirmed on
 *   commitment acceptance, not on settlement).
 */

const logger = require("../utils/logger");
const { TrustNode } = require("./trust-node");
const { SovereignVault } = require("../vault/sovereign-vault");

class TrustMesh {
  constructor() {
    this.nodes = new Map(); // nodeId → TrustNode
    this.corridors = new Map(); // "DE-SG" → { active, volume, lastSettlement }
    this.meshId = `MESH-${Date.now()}`;
    
    logger.info("Trust Mesh initialized", { meshId: this.meshId });
  }
  
  /**
   * Add a Trust Node to the mesh
   */
  addNode(node) {
    if (!(node instanceof TrustNode)) {
      throw new Error("Must be a TrustNode instance");
    }
    this.nodes.set(node.nodeId, node);
    
    logger.info("Node added to mesh", {
      nodeId: node.nodeId,
      jurisdiction: node.jurisdiction,
      totalNodes: this.nodes.size
    });
    
    return node;
  }
  
  /**
   * Establish a corridor between two nodes
   */
  openCorridor(nodeA, nodeB) {
    if (!this.nodes.has(nodeA.nodeId) || !this.nodes.has(nodeB.nodeId)) {
      throw new Error("Both nodes must be in the mesh");
    }
    
    nodeA.connectPeer(nodeB);
    
    const corridorId = [nodeA.jurisdiction, nodeB.jurisdiction].sort().join("-");
    this.corridors.set(corridorId, {
      nodeA: nodeA.nodeId,
      nodeB: nodeB.nodeId,
      active: true,
      established: new Date().toISOString(),
      totalVolume: 0,
      lastSettlement: null
    });
    
    logger.info("Corridor opened", {
      corridor: corridorId,
      nodes: [nodeA.nodeId, nodeB.nodeId]
    });
    
    return { corridorId, active: true };
  }
  
  /**
   * Execute a full cross-border payment through the mesh
   * 
   * This is the complete flow:
   * 1. Sender's vault generates Sovereign Proof
   * 2. Sender's Trust Node validates and creates commitment
   * 3. Commitment propagated to receiver's Trust Node
   * 4. Receiver's node acknowledges
   * 5. Both nodes update netting ledgers
   */
  async executePayment(params) {
    const {
      senderVault,
      senderNodeId,
      receiverNodeId,
      amount,
      currency,
      claims
    } = params;
    
    const senderNode = this.nodes.get(senderNodeId);
    const receiverNode = this.nodes.get(receiverNodeId);
    
    if (!senderNode) return { success: false, error: "SENDER_NODE_NOT_FOUND" };
    if (!receiverNode) return { success: false, error: "RECEIVER_NODE_NOT_FOUND" };
    
    // Step 1: Generate Sovereign Proof on sender's device
    const proof = senderVault.generateProof({
      type: "PAYMENT",
      claims,
      recipientNodeId: receiverNodeId,
      amount
    });
    
    // Step 2: Sender's node processes outbound payment
    const outbound = await senderNode.processOutboundPayment(
      proof,
      receiverNodeId,
      this._amountToRange(amount)
    );
    
    if (!outbound.success) {
      return {
        success: false,
        error: outbound.error,
        reason: outbound.reason,
        phase: "SENDER_NODE_VALIDATION"
      };
    }
    
    // Step 3: Sign commitment with sender node's key
    const senderSignature = senderNode.signCommitment(outbound.commitment);
    
    // Step 4: Propagate to receiver's node
    const inbound = await receiverNode.receiveCommitment(
      outbound.commitment,
      senderSignature
    );
    
    if (!inbound.accepted) {
      return {
        success: false,
        error: "RECEIVER_REJECTED",
        reason: inbound.reason,
        phase: "RECEIVER_NODE_VALIDATION"
      };
    }
    
    // Step 5: Update corridor stats
    const corridorId = [senderNode.jurisdiction, receiverNode.jurisdiction].sort().join("-");
    const corridor = this.corridors.get(corridorId);
    if (corridor) {
      corridor.totalVolume++;
    }
    
    logger.info("Cross-border payment executed through mesh", {
      meshId: this.meshId,
      commitmentId: outbound.commitmentId,
      corridor: `${senderNode.jurisdiction}→${receiverNode.jurisdiction}`,
      chainHeight: outbound.chain.height
    });
    
    return {
      success: true,
      paymentId: outbound.commitmentId,
      acknowledgmentId: inbound.acknowledgmentId,
      
      proof: {
        id: proof.payload.proofId,
        type: proof.payload.type,
        attestationCount: Object.keys(proof.payload.attestations).length,
        containsPII: false // This is the whole point
      },
      
      commitment: {
        id: outbound.commitment.id,
        senderJurisdiction: senderNode.jurisdiction,
        receiverJurisdiction: receiverNode.jurisdiction,
        chainHeight: outbound.chain.height
      },
      
      settlement: {
        method: "BILATERAL_NETTING",
        window: "HOURLY",
        note: "Payment confirmed immediately. Settlement nets at next window."
      }
    };
  }
  
  /**
   * Trigger settlement across all corridors
   */
  settleAll() {
    const settlements = [];
    
    for (const [corridorId, corridor] of this.corridors) {
      if (!corridor.active) continue;
      
      const nodeA = this.nodes.get(corridor.nodeA);
      const nodeB = this.nodes.get(corridor.nodeB);
      
      if (!nodeA || !nodeB) continue;
      
      // Settle A→B direction
      const settlement = nodeA.settleWithPeer(nodeB.nodeId);
      if (settlement.netObligations > 0) {
        settlements.push(settlement);
      }
      
      corridor.lastSettlement = new Date().toISOString();
    }
    
    logger.info("Mesh-wide settlement complete", {
      corridors: this.corridors.size,
      settlementsGenerated: settlements.length
    });
    
    return {
      settlements,
      settledAt: new Date().toISOString(),
      corridorsSettled: settlements.length
    };
  }
  
  /**
   * Find the shortest route between two jurisdictions
   * (for when direct corridor doesn't exist)
   */
  findRoute(fromJurisdiction, toJurisdiction) {
    // BFS through the corridor graph
    const fromNode = this._findNodeByJurisdiction(fromJurisdiction);
    const toNode = this._findNodeByJurisdiction(toJurisdiction);
    
    if (!fromNode || !toNode) return null;
    if (fromNode.nodeId === toNode.nodeId) return [fromNode.nodeId];
    
    const queue = [[fromNode.nodeId]];
    const visited = new Set([fromNode.nodeId]);
    
    while (queue.length > 0) {
      const path = queue.shift();
      const current = this.nodes.get(path[path.length - 1]);
      
      for (const [peerId] of current.peers) {
        if (peerId === toNode.nodeId) {
          return [...path, peerId];
        }
        
        if (!visited.has(peerId)) {
          visited.add(peerId);
          queue.push([...path, peerId]);
        }
      }
    }
    
    return null; // No route found
  }
  
  /**
   * Get mesh topology and health
   */
  getTopology() {
    const nodes = [];
    for (const [id, node] of this.nodes) {
      nodes.push({
        nodeId: id,
        jurisdiction: node.jurisdiction,
        operator: node.operatorName,
        peers: node.peers.size,
        registeredVaults: node.registeredVaults.size,
        chainHeight: node.commitmentChain.length
      });
    }
    
    const corridors = [];
    for (const [id, corridor] of this.corridors) {
      corridors.push({
        corridorId: id,
        active: corridor.active,
        totalVolume: corridor.totalVolume,
        lastSettlement: corridor.lastSettlement
      });
    }
    
    return {
      meshId: this.meshId,
      nodeCount: this.nodes.size,
      corridorCount: this.corridors.size,
      nodes,
      corridors,
      timestamp: new Date().toISOString()
    };
  }
  
  /**
   * Verify chain integrity for a node
   */
  verifyChainIntegrity(nodeId) {
    const node = this.nodes.get(nodeId);
    if (!node) return { valid: false, reason: "Node not found" };
    
    const chain = node.commitmentChain;
    if (chain.length === 0) return { valid: true, height: 0, message: "Empty chain" };
    
    // Verify hash linkage AND content integrity
    let expectedPrevious = "0".repeat(64);
    for (let i = 0; i < chain.length; i++) {
      if (chain[i].previousHash !== expectedPrevious) {
        return {
          valid: false,
          brokenAt: i,
          reason: `Hash chain broken at height ${i}`,
          expected: expectedPrevious,
          found: chain[i].previousHash
        };
      }
      
      // SECURITY: Recompute hash from content to detect tampering (FIX PEN-404)
      const storedHash = chain[i].hash;
      const commitCopy = { ...chain[i] };
      delete commitCopy.hash; // Hash was computed without itself
      const recomputedHash = require("crypto")
        .createHash("sha256")
        .update(JSON.stringify(commitCopy))
        .digest("hex");
      if (recomputedHash !== storedHash) {
        return {
          valid: false,
          brokenAt: i,
          reason: `Content tampered at height ${i}: hash mismatch`,
          expected: recomputedHash,
          found: storedHash
        };
      }
      
      expectedPrevious = chain[i].hash;
    }
    
    return {
      valid: true,
      height: chain.length,
      head: node.chainHead,
      message: "Chain integrity verified"
    };
  }
  
  _findNodeByJurisdiction(jurisdiction) {
    for (const [, node] of this.nodes) {
      if (node.jurisdiction === jurisdiction) return node;
    }
    return null;
  }
  
  _amountToRange(amount) {
    if (amount <= 100) return "0-100";
    if (amount <= 1000) return "100-1000";
    if (amount <= 10000) return "1000-10000";
    if (amount <= 100000) return "10000-100000";
    return "100000+";
  }
}

module.exports = { TrustMesh };
