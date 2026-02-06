/**
 * OBELISK — Sovereign Proof Protocol
 * 
 * Cross-border payment orchestration with:
 * - AES-256-GCM field-level encryption
 * - Multi-list sanctions screening (OFAC/EU/UN/UK)
 * - 4-tier KYC verification framework
 * - Real-time AML pattern detection (7 patterns + SAR auto-draft)
 * - TimeLock contracts (FX speculation to avoid fees)
 * - Sovereign Proof Protocol (zero-knowledge compliance)
 * - Trust Mesh (decentralized settlement network)
 * - Payment Orchestrator (full-pipeline integration)
 * 
 * Author: Henry Wyndham
 * Stack: Fastify 5, PostgreSQL 16, Redis 7, Zod, Pino
 */

require("dotenv").config();

const fastify = require("fastify")({
  logger: {
    level: process.env.LOG_LEVEL || "info",
    transport: process.env.NODE_ENV !== "production"
      ? { target: "pino-pretty", options: { colorize: true } }
      : undefined
  },
  requestId: true,
  trustProxy: true
});

const { migrate, pool } = require("./db/migrate");
const { PaymentRepository } = require("./db/repositories/payments");
const { PaymentEngine } = require("./core/payment-engine");
const { FXService } = require("./core/fx-service");
const { EncryptionEngine } = require("./crypto/encryption");
const { EnhancedSanctionsScreener } = require("./core/enhanced-sanctions");
const { KYCFramework } = require("./kyc/framework");
const { AMLFramework } = require("./aml/framework");
const { TimeLockEngine } = require("./contracts/timelock");

const paymentRoutes = require("./api/payments");
const healthRoutes = require("./api/health");
const kycRoutes = require("./api/kyc");
const amlRoutes = require("./api/aml");
const timeLockRoutes = require("./api/timelock");
const sovereignRoutes = require("./api/sovereign");

const { TrustMesh } = require("./trust/trust-mesh");
const { TrustNode } = require("./trust/trust-node");
const { PaymentOrchestrator } = require("./core/orchestrator");

const PORT = parseInt(process.env.PORT || "3000");

async function build() {
  // Security plugins
  await fastify.register(require("@fastify/helmet"), {
    contentSecurityPolicy: {
      directives: { defaultSrc: ["'self'"], frameSrc: ["'none'"], objectSrc: ["'none'"] }
    }
  });
  
  await fastify.register(require("@fastify/cors"), {
    origin: process.env.ALLOWED_ORIGINS?.split(",") || false,
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Request-ID", "X-Idempotency-Key"]
  });
  
  await fastify.register(require("@fastify/rate-limit"), {
    max: parseInt(process.env.RATE_LIMIT_MAX || "100"),
    timeWindow: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "900000"),
    errorResponseBuilder: () => ({ error: "RATE_LIMITED", message: "Too many requests." })
  });
  
  // Initialize all services
  const masterKey = process.env.ENCRYPTION_MASTER_KEY || EncryptionEngine.generateMasterKey();
  if (!process.env.ENCRYPTION_MASTER_KEY) {
    fastify.log.warn("No ENCRYPTION_MASTER_KEY — using ephemeral key. Data unrecoverable after restart!");
  }
  const encryption = new EncryptionEngine({ masterKey, keyVersion: parseInt(process.env.ENCRYPTION_KEY_VERSION || "1") });
  
  const fxService = new FXService({
    cacheTTLSeconds: parseInt(process.env.FX_CACHE_TTL_SECONDS || "300"),
    markupBps: parseInt(process.env.FX_MARKUP_BPS || "50")
  });
  
  const sanctionsScreener = new EnhancedSanctionsScreener();
  await sanctionsScreener.loadLists();
  
  const paymentRepo = new PaymentRepository();
  const paymentEngine = new PaymentEngine({
    db: paymentRepo, fxService, sanctionsScreener,
    config: { maxAmount: parseInt(process.env.MAX_PAYMENT_AMOUNT || "1000000"), ttlHours: parseInt(process.env.PAYMENT_TTL_HOURS || "72") }
  });
  
  const kycFramework = new KYCFramework({ encryption, db: null, sanctionsScreener });
  const amlFramework = new AMLFramework({ reportingThreshold: parseInt(process.env.AML_REPORTING_THRESHOLD || "10000") });
  const timeLockEngine = new TimeLockEngine({
    fxService, paymentEngine,
    config: { feeBps: parseInt(process.env.TIMELOCK_FEE_BPS || "120"), maxDurationHours: parseInt(process.env.TIMELOCK_MAX_HOURS || "72") }
  });
  
  // ══════════════════════════════════════════════════════
  // V3: Sovereign Proof Protocol — Trust Mesh + Orchestrator
  // ══════════════════════════════════════════════════════
  
  // Initialize Trust Mesh with configured jurisdiction nodes
  const trustMesh = new TrustMesh();
  const jurisdictions = (process.env.MESH_JURISDICTIONS || "DE,FR,NL,SG,US").split(",");
  const nodeMap = {};
  
  for (const jurisdiction of jurisdictions) {
    const j = jurisdiction.trim();
    const node = new TrustNode({
      jurisdiction: j,
      operatorName: `${j} Settlement Node`
    });
    trustMesh.addNode(node);
    nodeMap[j] = node;
  }
  
  // Auto-connect corridors (production: configured per bilateral agreement)
  const jurisdictionList = Object.keys(nodeMap);
  for (let i = 0; i < jurisdictionList.length; i++) {
    for (let j = i + 1; j < jurisdictionList.length; j++) {
      trustMesh.openCorridor(nodeMap[jurisdictionList[i]], nodeMap[jurisdictionList[j]]);
    }
  }
  
  fastify.log.info(`Trust Mesh: ${jurisdictionList.length} nodes, ${trustMesh.corridors.size} corridors`);
  
  // Initialize Payment Orchestrator (connects ALL layers)
  const orchestrator = new PaymentOrchestrator({
    paymentEngine,
    kycFramework,
    amlFramework,
    timeLockEngine,
    encryption,
    trustMesh,
    fxService
  });
  
  // Routes
  await fastify.register(paymentRoutes, { prefix: "/api/v1", paymentEngine });
  await fastify.register(kycRoutes, { prefix: "/api/v1", kycFramework });
  await fastify.register(amlRoutes, { prefix: "/api/v1", amlFramework });
  await fastify.register(timeLockRoutes, { prefix: "/api/v1", timeLockEngine });
  await fastify.register(sovereignRoutes, { prefix: "/api/v1", orchestrator });
  await fastify.register(healthRoutes, { prefix: "", db: pool });
  
  fastify.setErrorHandler((error, request, reply) => {
    fastify.log.error({ error: error.message, stack: error.stack, requestId: request.id, url: request.url });
    reply.status(error.statusCode || 500).send({
      error: error.code || "INTERNAL_ERROR",
      message: process.env.NODE_ENV === "production" ? "An unexpected error occurred" : error.message
    });
  });
  
  return fastify;
}

async function start() {
  try {
    await migrate("up");
    fastify.log.info("Database migrations complete");
    const app = await build();
    await app.listen({ port: PORT, host: "0.0.0.0" });
    fastify.log.info(`OBELISK on port ${PORT}`);
    fastify.log.info("Active: Encryption | Sanctions | KYC | AML | TimeLock | Sovereign Proof Protocol | Trust Mesh");
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

const signals = ["SIGTERM", "SIGINT"];
for (const signal of signals) {
  process.on(signal, async () => {
    fastify.log.info(`${signal} received, shutting down`);
    await fastify.close();
    await pool.end();
    process.exit(0);
  });
}

start();
module.exports = { build };
