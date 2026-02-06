/**
 * Payment API Routes
 * 
 * RESTful endpoints for the payment lifecycle.
 * All monetary amounts in the API are major units (e.g., 1000.50 EUR).
 * Internally converted to minor units for math.
 */

const { z } = require("zod");

const createPaymentSchema = z.object({
  amount: z.number().positive().max(1000000),
  sendCurrency: z.string().length(3).toUpperCase(),
  receiveCurrency: z.string().length(3).toUpperCase(),
  sender: z.object({
    name: z.string().min(2).max(255),
    iban: z.string().optional(),
    swift: z.string().optional(),
    country: z.string().length(2).toUpperCase(),
    reference: z.string().max(128).optional()
  }),
  beneficiary: z.object({
    name: z.string().min(2).max(255),
    iban: z.string().optional(),
    swift: z.string().optional(),
    country: z.string().length(2).toUpperCase(),
    reference: z.string().max(128).optional()
  }),
  purpose: z.string().max(255).optional(),
  memo: z.string().max(1000).optional(),
  webhookUrl: z.string().url().optional(),
  idempotencyKey: z.string().max(128).optional()
});

async function paymentRoutes(fastify, { paymentEngine }) {
  
  // Create payment
  fastify.post("/payments", async (request, reply) => {
    const parsed = createPaymentSchema.safeParse(request.body);
    
    if (!parsed.success) {
      return reply.status(400).send({
        error: "VALIDATION_ERROR",
        details: parsed.error.issues.map(i => ({
          field: i.path.join("."),
          message: i.message
        }))
      });
    }
    
    const payment = await paymentEngine.create(parsed.data);
    return reply.status(201).send({ payment });
  });
  
  // Get payment
  fastify.get("/payments/:id", async (request, reply) => {
    try {
      const payment = await paymentEngine.get(request.params.id);
      return reply.send({ payment });
    } catch (err) {
      return reply.status(404).send({ error: "NOT_FOUND", message: err.message });
    }
  });
  
  // Validate payment
  fastify.post("/payments/:id/validate", async (request, reply) => {
    try {
      const result = await paymentEngine.validate(request.params.id);
      const status = result.valid ? 200 : 422;
      return reply.status(status).send(result);
    } catch (err) {
      return reply.status(400).send({ error: "VALIDATION_FAILED", message: err.message });
    }
  });
  
  // Screen payment (sanctions)
  fastify.post("/payments/:id/screen", async (request, reply) => {
    try {
      const result = await paymentEngine.screen(request.params.id);
      return reply.send(result);
    } catch (err) {
      return reply.status(400).send({ error: "SCREENING_FAILED", message: err.message });
    }
  });
  
  // Get FX quote
  fastify.post("/payments/:id/quote", async (request, reply) => {
    try {
      const result = await paymentEngine.quote(request.params.id);
      return reply.send(result);
    } catch (err) {
      return reply.status(400).send({ error: "QUOTE_FAILED", message: err.message });
    }
  });
  
  // Confirm payment
  fastify.post("/payments/:id/confirm", async (request, reply) => {
    try {
      const result = await paymentEngine.confirm(request.params.id);
      if (!result.confirmed) {
        return reply.status(410).send(result); // 410 Gone for expired quotes
      }
      return reply.send(result);
    } catch (err) {
      return reply.status(400).send({ error: "CONFIRM_FAILED", message: err.message });
    }
  });
  
  // Process payment
  fastify.post("/payments/:id/process", async (request, reply) => {
    try {
      const result = await paymentEngine.process(request.params.id);
      return reply.send(result);
    } catch (err) {
      return reply.status(400).send({ error: "PROCESS_FAILED", message: err.message });
    }
  });
  
  // Cancel payment
  fastify.post("/payments/:id/cancel", async (request, reply) => {
    try {
      const reason = request.body?.reason || "Cancelled by user";
      const result = await paymentEngine.cancel(request.params.id, reason);
      return reply.send(result);
    } catch (err) {
      return reply.status(400).send({ error: "CANCEL_FAILED", message: err.message });
    }
  });
  
  // FX rate lookup (standalone, no payment required)
  fastify.get("/fx/:from/:to", async (request, reply) => {
    try {
      const { from, to } = request.params;
      const fxService = paymentEngine.fx;
      const rate = await fxService.getRate(from.toUpperCase(), to.toUpperCase());
      return reply.send(rate);
    } catch (err) {
      return reply.status(400).send({ error: "FX_ERROR", message: err.message });
    }
  });
  
  // IBAN validation (standalone utility)
  fastify.get("/validate/iban/:iban", async (request, reply) => {
    const { IBANValidator } = require("../../core/validator");
    const result = IBANValidator.validate(decodeURIComponent(request.params.iban));
    return reply.send(result);
  });
  
  // SWIFT validation (standalone utility)
  fastify.get("/validate/swift/:bic", async (request, reply) => {
    const { SWIFTValidator } = require("../../core/validator");
    const result = SWIFTValidator.validate(request.params.bic);
    return reply.send(result);
  });
}

module.exports = paymentRoutes;
