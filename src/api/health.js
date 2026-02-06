/**
 * Health & Metrics Routes
 */

async function healthRoutes(fastify, { db }) {
  
  // Liveness probe
  fastify.get("/health", async (request, reply) => {
    return reply.send({
      status: "ok",
      service: "obelisk",
      timestamp: new Date().toISOString(),
      uptime: Math.floor(process.uptime())
    });
  });
  
  // Readiness probe (checks dependencies)
  fastify.get("/ready", async (request, reply) => {
    const checks = {};
    
    // PostgreSQL
    try {
      const { pool } = require("../../db/migrate");
      const start = Date.now();
      await pool.query("SELECT 1");
      checks.database = { status: "ok", latencyMs: Date.now() - start };
    } catch (err) {
      checks.database = { status: "error", message: err.message };
    }
    
    const allOk = Object.values(checks).every(c => c.status === "ok");
    
    return reply.status(allOk ? 200 : 503).send({
      ready: allOk,
      checks,
      timestamp: new Date().toISOString()
    });
  });
  
  // System metrics
  fastify.get("/metrics", async (request, reply) => {
    const mem = process.memoryUsage();
    
    return reply.send({
      system: {
        uptimeSeconds: Math.floor(process.uptime()),
        memory: {
          heapUsedMB: Math.round(mem.heapUsed / 1048576),
          heapTotalMB: Math.round(mem.heapTotal / 1048576),
          rssMB: Math.round(mem.rss / 1048576),
          externalMB: Math.round(mem.external / 1048576)
        },
        nodeVersion: process.version,
        pid: process.pid
      },
      timestamp: new Date().toISOString()
    });
  });
}

module.exports = healthRoutes;
