/**
 * TimeLock Contract API Routes
 * 
 * Three-tier fee options, contract creation, monitoring, execution.
 */

const { z } = require("zod");

const optionsSchema = z.object({
  amount: z.number().positive(),
  sendCurrency: z.string().length(3).toUpperCase(),
  receiveCurrency: z.string().length(3).toUpperCase()
});

const createContractSchema = z.object({
  paymentId: z.string().uuid(),
  customerId: z.string().uuid(),
  amount: z.number().positive(),
  sendCurrency: z.string().length(3).toUpperCase(),
  receiveCurrency: z.string().length(3).toUpperCase(),
  fallbackTier: z.enum(["INSTANT", "DEDUCTED"]),
  maxDurationHours: z.number().min(1).max(168).optional()
});

async function timeLockRoutes(fastify, { timeLockEngine }) {
  
  // Get fee tier options for a transfer
  fastify.post("/transfers/options", async (request, reply) => {
    const parsed = optionsSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({
        error: "VALIDATION_ERROR",
        details: parsed.error.issues
      });
    }
    
    try {
      const { amount, sendCurrency, receiveCurrency } = parsed.data;
      const options = await timeLockEngine.calculateOptions(amount, sendCurrency, receiveCurrency);
      return reply.send(options);
    } catch (err) {
      return reply.status(400).send({ error: "OPTIONS_ERROR", message: err.message });
    }
  });
  
  // Create a TimeLock contract
  fastify.post("/contracts/timelock", async (request, reply) => {
    const parsed = createContractSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({
        error: "VALIDATION_ERROR",
        details: parsed.error.issues
      });
    }
    
    try {
      const contract = await timeLockEngine.createContract(parsed.data);
      return reply.status(201).send({ contract });
    } catch (err) {
      return reply.status(400).send({ error: "CONTRACT_ERROR", message: err.message });
    }
  });
  
  // Activate a TimeLock contract (start FX monitoring)
  fastify.post("/contracts/timelock/:id/activate", async (request, reply) => {
    try {
      const contract = timeLockEngine.activeContracts.get(request.params.id);
      if (!contract) {
        return reply.status(404).send({ error: "Contract not found or not in CREATED state" });
      }
      
      const activated = await timeLockEngine.activateContract(contract);
      return reply.send({ contract: activated });
    } catch (err) {
      return reply.status(400).send({ error: "ACTIVATION_ERROR", message: err.message });
    }
  });
  
  // Get contract status with real-time FX data
  fastify.get("/contracts/timelock/:id", async (request, reply) => {
    const contract = timeLockEngine.activeContracts.get(request.params.id);
    if (!contract) {
      return reply.status(404).send({ error: "Contract not found" });
    }
    
    const status = await timeLockEngine.getContractStatus(contract);
    return reply.send(status);
  });
  
  // Cancel a TimeLock contract
  fastify.post("/contracts/timelock/:id/cancel", async (request, reply) => {
    try {
      const contract = timeLockEngine.activeContracts.get(request.params.id);
      if (!contract) {
        return reply.status(404).send({ error: "Contract not found" });
      }
      
      const revertTo = request.body?.revertToTier;
      const result = await timeLockEngine.cancelContract(contract, revertTo);
      return reply.send(result);
    } catch (err) {
      return reply.status(400).send({ error: "CANCEL_ERROR", message: err.message });
    }
  });
  
  // List active contracts
  fastify.get("/contracts/timelock", async (request, reply) => {
    const contracts = [];
    for (const [id, contract] of timeLockEngine.activeContracts) {
      contracts.push({
        id,
        state: contract.state,
        principal: contract.principal,
        pair: `${contract.sendCurrency}/${contract.receiveCurrency}`,
        entryRate: contract.entryRate,
        breakEvenRate: contract.breakEvenRate,
        expiresAt: contract.expiresAt
      });
    }
    return reply.send({ activeContracts: contracts, count: contracts.length });
  });
  
  // Derivative book summary
  fastify.get("/derivatives/book", async (request, reply) => {
    const book = {};
    for (const [id, contract] of timeLockEngine.activeContracts) {
      const pair = `${contract.sendCurrency}/${contract.receiveCurrency}`;
      if (!book[pair]) {
        book[pair] = {
          pair,
          contracts: 0,
          totalNotional: 0,
          avgStrike: 0,
          totalTheoreticalValue: 0,
          strikes: []
        };
      }
      book[pair].contracts++;
      book[pair].totalNotional += contract.principal;
      book[pair].strikes.push(contract.breakEvenRate);
      
      const tv = contract.derivativeProfile?.theoreticalValue;
      if (tv) book[pair].totalTheoreticalValue += tv.theoreticalValue || 0;
    }
    
    // Calculate weighted average strikes
    for (const pair of Object.values(book)) {
      pair.avgStrike = pair.strikes.length > 0
        ? pair.strikes.reduce((a, b) => a + b, 0) / pair.strikes.length
        : 0;
      delete pair.strikes;
    }
    
    return reply.send({
      book: Object.values(book),
      totalContracts: timeLockEngine.activeContracts.size,
      timestamp: new Date().toISOString()
    });
  });
}

module.exports = timeLockRoutes;
