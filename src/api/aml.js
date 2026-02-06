/**
 * AML API Routes
 * 
 * Transaction analysis, alert management, SAR filing.
 */

async function amlRoutes(fastify, { amlFramework }) {
  
  // Analyze a transaction
  fastify.post("/aml/analyze", async (request, reply) => {
    const { transaction, customer, history } = request.body;
    
    if (!transaction || !customer) {
      return reply.status(400).send({
        error: "VALIDATION_ERROR",
        message: "Transaction and customer objects are required"
      });
    }
    
    const result = await amlFramework.analyzeTransaction(
      transaction, customer, history || []
    );
    
    // Return appropriate status based on action
    const status = result.action === "BLOCK" ? 403
      : result.action === "HOLD" ? 202
      : result.action === "SAR" ? 202
      : 200;
    
    return reply.status(status).send(result);
  });
  
  // Get AML alert by ID (in production: from DB)
  fastify.get("/aml/alerts/:id", async (request, reply) => {
    return reply.send({ message: "Alert retrieval - DB integration pending" });
  });
  
  // List open alerts
  fastify.get("/aml/alerts", async (request, reply) => {
    const { status, severity, limit } = request.query;
    return reply.send({
      message: "Alert listing - DB integration pending",
      filters: { status, severity, limit }
    });
  });
  
  // Resolve an alert
  fastify.post("/aml/alerts/:id/resolve", async (request, reply) => {
    const { resolution, notes } = request.body;
    return reply.send({
      message: "Alert resolution - DB integration pending",
      alertId: request.params.id,
      resolution
    });
  });
}

module.exports = amlRoutes;
