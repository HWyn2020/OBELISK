/**
 * KYC API Routes
 * 
 * Customer onboarding, document verification, tier upgrades.
 */

const { z } = require("zod");

const onboardSchema = z.object({
  firstName: z.string().min(1).max(100),
  lastName: z.string().min(1).max(100),
  email: z.string().email(),
  phone: z.string().min(6).max(20),
  country: z.string().length(2).toUpperCase(),
  dateOfBirth: z.string().optional(),
  type: z.enum(["INDIVIDUAL", "CORPORATE"]).default("INDIVIDUAL")
});

const documentSchema = z.object({
  type: z.enum(["GOVERNMENT_ID", "ADDRESS_PROOF", "SOURCE_OF_FUNDS", "SELFIE_WITH_ID",
                 "COMPANY_REGISTRATION", "UBO_DECLARATION", "FINANCIAL_STATEMENTS", "BOARD_RESOLUTION"]),
  idType: z.enum(["PASSPORT", "NATIONAL_ID", "DRIVERS_LICENSE", "RESIDENCE_PERMIT"]).optional(),
  number: z.string().max(20).optional(),
  issuingCountry: z.string().length(2).toUpperCase().optional(),
  expiryDate: z.string().optional()
});

async function kycRoutes(fastify, { kycFramework }) {
  
  // Onboard new customer
  fastify.post("/customers", async (request, reply) => {
    const parsed = onboardSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({
        error: "VALIDATION_ERROR",
        details: parsed.error.issues.map(i => ({ field: i.path.join("."), message: i.message }))
      });
    }
    
    const result = await kycFramework.onboardCustomer(parsed.data);
    
    if (!result.success && result.status === "BLOCKED_SANCTIONS") {
      return reply.status(403).send(result);
    }
    
    if (!result.success) {
      return reply.status(422).send(result);
    }
    
    return reply.status(201).send(result);
  });
  
  // Submit verification document
  fastify.post("/customers/:id/documents", async (request, reply) => {
    const parsed = documentSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({
        error: "VALIDATION_ERROR",
        details: parsed.error.issues
      });
    }
    
    try {
      const result = await kycFramework.submitDocument(request.params.id, parsed.data);
      return reply.status(result.success ? 201 : 422).send(result);
    } catch (err) {
      return reply.status(400).send({ error: "DOCUMENT_ERROR", message: err.message });
    }
  });
  
  // Check transaction limits
  fastify.post("/customers/:id/check-limits", async (request, reply) => {
    const { amount } = request.body;
    if (!amount || amount <= 0) {
      return reply.status(400).send({ error: "Amount required" });
    }
    
    // In production: fetch customer from DB
    const customer = { kycTier: request.body.tier || "TIER_1", monthlyTransactionVolume: 0 };
    const result = kycFramework.checkTransactionLimits(customer, amount);
    return reply.send(result);
  });
}

module.exports = kycRoutes;
