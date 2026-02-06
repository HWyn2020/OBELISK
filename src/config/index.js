/**
 * Configuration
 * 
 * All environment variables validated at startup with Zod.
 * Fail fast if anything is missing or malformed.
 */

const { z } = require("zod");

const envSchema = z.object({
  // Server
  PORT: z.coerce.number().default(3000),
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  
  // PostgreSQL
  DB_HOST: z.string().default("localhost"),
  DB_PORT: z.coerce.number().default(5432),
  DB_NAME: z.string().default("obelisk"),
  DB_USER: z.string().default("obelisk_admin"),
  DB_PASSWORD: z.string().min(1, "DB_PASSWORD is required"),
  DB_SSL: z.coerce.boolean().default(false),
  DB_POOL_MIN: z.coerce.number().default(2),
  DB_POOL_MAX: z.coerce.number().default(20),
  
  // Redis (for FX rate caching + idempotency)
  REDIS_URL: z.string().default("redis://localhost:6379"),
  
  // API Security
  API_KEY_HASH: z.string().min(64, "API_KEY_HASH must be SHA-256 hex").optional(),
  
  // FX Provider
  FX_PROVIDER_URL: z.string().url().default("https://api.exchangerate.host/latest"),
  FX_CACHE_TTL_SECONDS: z.coerce.number().default(300),
  FX_MARKUP_BPS: z.coerce.number().default(50), // 50 basis points = 0.5%
  
  // Payment Processing
  MAX_PAYMENT_AMOUNT: z.coerce.number().default(1000000),
  PAYMENT_TTL_HOURS: z.coerce.number().default(72),
  IDEMPOTENCY_TTL_HOURS: z.coerce.number().default(24),
  
  // Sanctions
  SANCTIONS_LIST_REFRESH_HOURS: z.coerce.number().default(6),
  
  // Rate Limiting
  RATE_LIMIT_MAX: z.coerce.number().default(100),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(900000),
  
  // Webhooks
  WEBHOOK_TIMEOUT_MS: z.coerce.number().default(10000),
  WEBHOOK_MAX_RETRIES: z.coerce.number().default(5),
});

function loadConfig() {
  require("dotenv").config();
  
  const result = envSchema.safeParse(process.env);
  
  if (!result.success) {
    console.error("Configuration validation failed:");
    for (const issue of result.error.issues) {
      console.error(`  ${issue.path.join(".")}: ${issue.message}`);
    }
    process.exit(1);
  }
  
  return result.data;
}

module.exports = { loadConfig, envSchema };
