/**
 * Sovereign Payment API Routes
 * 
 * End-to-end pipeline: KYC → AML → Proof → Trust Mesh → Settlement
 * 
 * These routes connect ALL layers. Before this file existed,
 * payments, KYC, AML, TimeLock, and SPP were isolated islands.
 */

const { z } = require("zod");

const onboardSchema = z.object({
  firstName: z.string().min(1).max(100),
  lastName: z.string().min(1).max(100),
  email: z.string().email(),
  phone: z.string().min(6).max(20),
  country: z.string().length(2).toUpperCase(),
  dateOfBirth: z.string().optional(),
  address: z.string().max(500).optional(),
  passphrase: z.string().min(12).max(128)
});

const paymentSchema = z.object({
  senderCustomerId: z.string().uuid(),
  receiverNodeId: z.string().optional(),
  amount: z.number().positive().max(1000000),
  sendCurrency: z.string().length(3).toUpperCase(),
  receiveCurrency: z.string().length(3).toUpperCase(),
  beneficiary: z.object({
    name: z.string().min(2).max(255),
    iban: z.string().optional(),
    swift: z.string().optional(),
    country: z.string().length(2).toUpperCase()
  }),
  purpose: z.string().max(255).optional(),
  idempotencyKey: z.string().max(128).optional()
});

const timeLockSchema = paymentSchema.extend({
  fallbackTier: z.enum(["INSTANT", "DEDUCTED"]).default("DEDUCTED"),
  maxDurationHours: z.number().min(1).max(72).optional()
});

async function sovereignRoutes(fastify, { orchestrator }) {
  
  // ══════════════════════════════════════════════════════
  // CUSTOMER ONBOARDING (KYC + Vault + Trust Node)
  // ══════════════════════════════════════════════════════
  
  fastify.post("/sovereign/onboard", async (request, reply) => {
    const parsed = onboardSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({
        error: "VALIDATION_ERROR",
        details: parsed.error.issues.map(i => ({ field: i.path.join("."), message: i.message }))
      });
    }
    
    const { passphrase, ...customerData } = parsed.data;
    
    try {
      const result = await orchestrator.onboardCustomer(customerData, passphrase);
      
      if (!result.success) {
        const status = result.error === "BLOCKED_SANCTIONS" ? 403 : 422;
        return reply.status(status).send(result);
      }
      
      return reply.status(201).send(result);
    } catch (err) {
      return reply.status(500).send({
        error: "ONBOARDING_ERROR",
        message: err.message
      });
    }
  });
  
  // ══════════════════════════════════════════════════════
  // SOVEREIGN PAYMENT (Full pipeline)
  // ══════════════════════════════════════════════════════
  
  fastify.post("/sovereign/payments", async (request, reply) => {
    const parsed = paymentSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({
        error: "VALIDATION_ERROR",
        details: parsed.error.issues.map(i => ({ field: i.path.join("."), message: i.message }))
      });
    }
    
    try {
      const result = await orchestrator.executeSovereignPayment(parsed.data);
      
      if (!result.success) {
        const statusMap = {
          KYC_LIMITS: 403, AML: 403, VAULT: 401,
          TRUST_NODE: 502, RECEIVER_NODE: 502,
          LOOKUP: 404, VALIDATION: 422
        };
        const status = statusMap[result.phase] || 400;
        return reply.status(status).send(result);
      }
      
      return reply.status(201).send(result);
    } catch (err) {
      return reply.status(500).send({
        error: "PAYMENT_ERROR",
        message: err.message
      });
    }
  });
  
  // ══════════════════════════════════════════════════════
  // TIMELOCK PAYMENT (FX speculation path)
  // ══════════════════════════════════════════════════════
  
  fastify.post("/sovereign/payments/timelock", async (request, reply) => {
    const parsed = timeLockSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({
        error: "VALIDATION_ERROR",
        details: parsed.error.issues.map(i => ({ field: i.path.join("."), message: i.message }))
      });
    }
    
    try {
      const result = await orchestrator.executeTimeLockPayment(parsed.data);
      
      if (!result.success) {
        return reply.status(result.phase === "AML" ? 403 : 400).send(result);
      }
      
      return reply.status(201).send(result);
    } catch (err) {
      return reply.status(500).send({
        error: "TIMELOCK_ERROR",
        message: err.message
      });
    }
  });
  
  // ══════════════════════════════════════════════════════
  // MESH OPERATIONS
  // ══════════════════════════════════════════════════════
  
  // Mesh topology
  fastify.get("/sovereign/mesh", async (request, reply) => {
    return reply.send(orchestrator.getMeshTopology());
  });
  
  // Trigger settlement
  fastify.post("/sovereign/mesh/settle", async (request, reply) => {
    const result = orchestrator.settleAll();
    return reply.send(result);
  });
  
  // Node integrity check
  fastify.get("/sovereign/mesh/nodes/:nodeId/integrity", async (request, reply) => {
    const result = orchestrator.verifyNodeIntegrity(request.params.nodeId);
    return reply.send(result);
  });
  
  // Customer status (no PII)
  fastify.get("/sovereign/customers/:id/status", async (request, reply) => {
    const status = orchestrator.getCustomerStatus(request.params.id);
    if (!status) {
      return reply.status(404).send({ error: "CUSTOMER_NOT_FOUND" });
    }
    return reply.send(status);
  });
}

module.exports = sovereignRoutes;
