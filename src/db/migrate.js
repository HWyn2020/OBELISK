/**
 * Database Migrations
 * 
 * Versioned schema migrations for PostgreSQL.
 * Run: node src/db/migrate.js up
 * Rollback: node src/db/migrate.js down
 */

const { Pool } = require("pg");
const logger = require("../utils/logger");

const pool = new Pool({
  host: process.env.DB_HOST || "localhost",
  port: parseInt(process.env.DB_PORT || "5432"),
  database: process.env.DB_NAME || "obelisk",
  user: process.env.DB_USER || "obelisk_admin",
  password: process.env.DB_PASSWORD,
  max: parseInt(process.env.DB_POOL_MAX || "20"),
  min: parseInt(process.env.DB_POOL_MIN || "2"),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false
});

pool.on("error", (err) => {
  logger.error("Unexpected database pool error", { error: err.message });
});

const MIGRATIONS = [
  {
    version: 1,
    name: "create_payments",
    up: `
      CREATE TYPE payment_state AS ENUM (
        'INITIATED', 'VALIDATED', 'SCREENED', 'HELD', 'QUOTED',
        'CONFIRMED', 'PROCESSING', 'SETTLED', 'COMPLETED',
        'FAILED', 'REJECTED', 'CANCELLED', 'EXPIRED', 'REFUNDED'
      );

      CREATE TABLE payments (
        id UUID PRIMARY KEY,
        idempotency_key VARCHAR(128) UNIQUE,
        state payment_state NOT NULL DEFAULT 'INITIATED',
        
        -- Amounts (stored as BIGINT minor units to avoid float errors)
        send_amount NUMERIC(18,6) NOT NULL,
        send_currency CHAR(3) NOT NULL,
        receive_amount NUMERIC(18,6),
        receive_currency CHAR(3) NOT NULL,
        
        -- FX
        quoted_rate NUMERIC(18,8),
        quote_expires_at TIMESTAMPTZ,
        
        -- Parties (JSONB for flexibility across payment types)
        sender JSONB NOT NULL,
        beneficiary JSONB NOT NULL,
        
        -- Compliance
        sanctions_result JSONB,
        
        -- Settlement
        settlement_reference VARCHAR(128),
        
        -- Metadata
        purpose VARCHAR(255),
        memo TEXT,
        webhook_url VARCHAR(512),
        
        -- Audit
        state_history JSONB NOT NULL DEFAULT '[]',
        
        -- Timestamps
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMPTZ,
        
        -- Constraints
        CONSTRAINT positive_send_amount CHECK (send_amount > 0),
        CONSTRAINT valid_send_currency CHECK (send_currency ~ '^[A-Z]{3}$'),
        CONSTRAINT valid_receive_currency CHECK (receive_currency ~ '^[A-Z]{3}$')
      );

      -- Performance indexes
      CREATE INDEX idx_payments_state ON payments(state);
      CREATE INDEX idx_payments_created ON payments(created_at DESC);
      CREATE INDEX idx_payments_sender_country ON payments((sender->>'country'));
      CREATE INDEX idx_payments_beneficiary_country ON payments((beneficiary->>'country'));
      CREATE INDEX idx_payments_currencies ON payments(send_currency, receive_currency);
      CREATE INDEX idx_payments_idempotency ON payments(idempotency_key) WHERE idempotency_key IS NOT NULL;
      
      -- Partial index for active payments (non-terminal states)
      CREATE INDEX idx_payments_active ON payments(state, updated_at)
        WHERE state NOT IN ('COMPLETED', 'FAILED', 'REJECTED', 'CANCELLED', 'EXPIRED', 'REFUNDED');
    `,
    down: `
      DROP TABLE IF EXISTS payments;
      DROP TYPE IF EXISTS payment_state;
    `
  },
  {
    version: 2,
    name: "create_audit_log",
    up: `
      CREATE TABLE payment_audit_log (
        id BIGSERIAL PRIMARY KEY,
        payment_id UUID NOT NULL REFERENCES payments(id),
        action VARCHAR(50) NOT NULL,
        from_state payment_state,
        to_state payment_state,
        reason TEXT,
        actor VARCHAR(128),
        ip_address INET,
        metadata JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX idx_audit_payment ON payment_audit_log(payment_id);
      CREATE INDEX idx_audit_created ON payment_audit_log(created_at DESC);
      CREATE INDEX idx_audit_action ON payment_audit_log(action);
    `,
    down: `DROP TABLE IF EXISTS payment_audit_log;`
  },
  {
    version: 3,
    name: "create_fx_rates_cache",
    up: `
      CREATE TABLE fx_rates (
        id SERIAL PRIMARY KEY,
        base_currency CHAR(3) NOT NULL DEFAULT 'EUR',
        rates JSONB NOT NULL,
        source VARCHAR(50) NOT NULL,
        fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
      );

      CREATE INDEX idx_fx_expires ON fx_rates(expires_at DESC);
    `,
    down: `DROP TABLE IF EXISTS fx_rates;`
  },
  {
    version: 4,
    name: "create_idempotency_store",
    up: `
      CREATE TABLE idempotency_keys (
        key VARCHAR(128) PRIMARY KEY,
        payment_id UUID REFERENCES payments(id),
        response JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
      );

      CREATE INDEX idx_idempotency_expires ON idempotency_keys(expires_at);
    `,
    down: `DROP TABLE IF EXISTS idempotency_keys;`
  },
  {
    version: 5,
    name: "create_webhooks",
    up: `
      CREATE TABLE webhook_deliveries (
        id BIGSERIAL PRIMARY KEY,
        payment_id UUID NOT NULL REFERENCES payments(id),
        url VARCHAR(512) NOT NULL,
        event VARCHAR(50) NOT NULL,
        payload JSONB NOT NULL,
        status_code INTEGER,
        response_body TEXT,
        attempt INTEGER NOT NULL DEFAULT 1,
        max_attempts INTEGER NOT NULL DEFAULT 5,
        next_retry_at TIMESTAMPTZ,
        delivered BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX idx_webhooks_pending ON webhook_deliveries(next_retry_at)
        WHERE delivered = FALSE;
      CREATE INDEX idx_webhooks_payment ON webhook_deliveries(payment_id);
    `,
    down: `DROP TABLE IF EXISTS webhook_deliveries;`
  },
  {
    version: 6,
    name: "create_cleanup_procedures",
    up: `
      -- Expire stale payments
      CREATE OR REPLACE FUNCTION expire_stale_payments(ttl_hours INTEGER DEFAULT 72)
      RETURNS INTEGER AS $$
      DECLARE expired_count INTEGER;
      BEGIN
        UPDATE payments
        SET state = 'EXPIRED',
            updated_at = NOW(),
            state_history = state_history || jsonb_build_array(jsonb_build_object(
              'from', state::TEXT,
              'to', 'EXPIRED',
              'reason', 'TTL exceeded',
              'timestamp', NOW()
            ))
        WHERE state IN ('INITIATED', 'VALIDATED', 'QUOTED')
        AND created_at < NOW() - (ttl_hours || ' hours')::INTERVAL;
        
        GET DIAGNOSTICS expired_count = ROW_COUNT;
        RETURN expired_count;
      END;
      $$ LANGUAGE plpgsql;

      -- Clean up expired idempotency keys
      CREATE OR REPLACE FUNCTION cleanup_idempotency_keys()
      RETURNS INTEGER AS $$
      DECLARE deleted_count INTEGER;
      BEGIN
        DELETE FROM idempotency_keys WHERE expires_at < NOW();
        GET DIAGNOSTICS deleted_count = ROW_COUNT;
        RETURN deleted_count;
      END;
      $$ LANGUAGE plpgsql;
    `,
    down: `
      DROP FUNCTION IF EXISTS expire_stale_payments;
      DROP FUNCTION IF EXISTS cleanup_idempotency_keys;
    `
  }
];

async function migrate(direction = "up") {
  const client = await pool.connect();
  
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        applied_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    
    const { rows: applied } = await client.query(
      "SELECT version FROM schema_migrations ORDER BY version"
    );
    const appliedVersions = new Set(applied.map(r => r.version));
    
    if (direction === "up") {
      for (const migration of MIGRATIONS) {
        if (appliedVersions.has(migration.version)) continue;
        
        logger.info(`Applying migration ${migration.version}: ${migration.name}`);
        await client.query("BEGIN");
        
        try {
          await client.query(migration.up);
          await client.query(
            "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
            [migration.version, migration.name]
          );
          await client.query("COMMIT");
          logger.info(`Migration ${migration.version} applied`);
        } catch (err) {
          await client.query("ROLLBACK");
          logger.error(`Migration ${migration.version} failed: ${err.message}`);
          throw err;
        }
      }
    } else if (direction === "down") {
      const reversed = [...MIGRATIONS].reverse();
      for (const migration of reversed) {
        if (!appliedVersions.has(migration.version)) continue;
        
        logger.info(`Rolling back migration ${migration.version}: ${migration.name}`);
        await client.query("BEGIN");
        
        try {
          await client.query(migration.down);
          await client.query("DELETE FROM schema_migrations WHERE version = $1", [migration.version]);
          await client.query("COMMIT");
          logger.info(`Migration ${migration.version} rolled back`);
        } catch (err) {
          await client.query("ROLLBACK");
          throw err;
        }
      }
    }
    
    logger.info("Migrations complete");
  } finally {
    client.release();
  }
}

// CLI support
if (require.main === module) {
  require("dotenv").config();
  const direction = process.argv[2] || "up";
  migrate(direction).then(() => process.exit(0)).catch(() => process.exit(1));
}

module.exports = { pool, migrate };
