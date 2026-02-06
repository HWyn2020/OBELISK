/**
 * V2 Database Migrations
 * 
 * New tables for KYC, AML, TimeLock contracts, and derivative instruments.
 */

const V2_MIGRATIONS = [
  {
    version: 7,
    name: "create_customers",
    up: `
      CREATE TYPE kyc_tier AS ENUM ('TIER_1', 'TIER_2', 'TIER_3', 'TIER_4');
      CREATE TYPE kyc_status AS ENUM (
        'PENDING_VERIFICATION', 'VERIFIED', 'UNDER_REVIEW',
        'SUSPENDED', 'BLOCKED_SANCTIONS', 'CLOSED'
      );
      CREATE TYPE risk_level AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
      CREATE TYPE customer_type AS ENUM ('INDIVIDUAL', 'CORPORATE');

      CREATE TABLE customers (
        id UUID PRIMARY KEY,
        customer_type customer_type NOT NULL DEFAULT 'INDIVIDUAL',
        
        -- Encrypted PII (AES-256-GCM, decrypted only when needed)
        first_name_enc TEXT NOT NULL,
        last_name_enc TEXT NOT NULL,
        email_enc TEXT NOT NULL,
        phone_enc TEXT NOT NULL,
        date_of_birth_enc TEXT,
        
        -- Searchable hashes (HMAC-SHA256, for lookups without decryption)
        email_hash CHAR(64) NOT NULL,
        phone_hash CHAR(64) NOT NULL,
        name_hash CHAR(64) NOT NULL,
        
        -- Plaintext (non-PII, needed for queries and compliance)
        country CHAR(2) NOT NULL,
        kyc_tier kyc_tier NOT NULL DEFAULT 'TIER_1',
        kyc_status kyc_status NOT NULL DEFAULT 'PENDING_VERIFICATION',
        
        -- Risk assessment
        risk_score SMALLINT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
        risk_level risk_level NOT NULL DEFAULT 'LOW',
        risk_factors JSONB NOT NULL DEFAULT '[]',
        
        -- Sanctions
        sanctions_status VARCHAR(20) NOT NULL DEFAULT 'CLEAR',
        last_sanctions_screen TIMESTAMPTZ,
        
        -- Limits (cached from tier, can be overridden)
        limit_per_transaction NUMERIC(18,2),
        limit_per_month NUMERIC(18,2),
        limit_per_year NUMERIC(18,2),
        
        -- Activity
        total_transaction_count INTEGER NOT NULL DEFAULT 0,
        total_transaction_volume NUMERIC(18,2) NOT NULL DEFAULT 0,
        monthly_transaction_volume NUMERIC(18,2) NOT NULL DEFAULT 0,
        monthly_volume_reset_at TIMESTAMPTZ NOT NULL DEFAULT DATE_TRUNC('month', NOW()) + INTERVAL '1 month',
        
        -- Timestamps
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_activity_at TIMESTAMPTZ,
        next_review_at TIMESTAMPTZ,
        
        -- Constraints
        CONSTRAINT unique_email_hash UNIQUE (email_hash),
        CONSTRAINT unique_phone_hash UNIQUE (phone_hash)
      );

      CREATE INDEX idx_customers_country ON customers(country);
      CREATE INDEX idx_customers_tier ON customers(kyc_tier);
      CREATE INDEX idx_customers_status ON customers(kyc_status);
      CREATE INDEX idx_customers_risk ON customers(risk_level);
      CREATE INDEX idx_customers_review ON customers(next_review_at)
        WHERE kyc_status NOT IN ('CLOSED', 'BLOCKED_SANCTIONS');
      CREATE INDEX idx_customers_email ON customers(email_hash);
      CREATE INDEX idx_customers_sanctions ON customers(sanctions_status)
        WHERE sanctions_status != 'CLEAR';
    `,
    down: `
      DROP TABLE IF EXISTS customers CASCADE;
      DROP TYPE IF EXISTS kyc_tier;
      DROP TYPE IF EXISTS kyc_status;
      DROP TYPE IF EXISTS risk_level;
      DROP TYPE IF EXISTS customer_type;
    `
  },
  {
    version: 8,
    name: "create_kyc_documents",
    up: `
      CREATE TYPE document_status AS ENUM (
        'PENDING_REVIEW', 'VERIFIED', 'REJECTED', 'EXPIRED'
      );

      CREATE TABLE kyc_documents (
        id UUID PRIMARY KEY,
        customer_id UUID NOT NULL REFERENCES customers(id),
        
        -- Document metadata (plaintext for querying)
        document_type VARCHAR(50) NOT NULL,
        id_type VARCHAR(30),
        issuing_country CHAR(2),
        expiry_date DATE,
        
        -- Encrypted content
        document_number_enc TEXT,
        
        -- Verification
        status document_status NOT NULL DEFAULT 'PENDING_REVIEW',
        format_valid BOOLEAN,
        expiry_valid BOOLEAN,
        verified_at TIMESTAMPTZ,
        verified_by VARCHAR(128),
        rejection_reason TEXT,
        
        -- Timestamps
        submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX idx_kyc_docs_customer ON kyc_documents(customer_id);
      CREATE INDEX idx_kyc_docs_status ON kyc_documents(status);
      CREATE INDEX idx_kyc_docs_expiry ON kyc_documents(expiry_date)
        WHERE status = 'VERIFIED';
    `,
    down: `
      DROP TABLE IF EXISTS kyc_documents;
      DROP TYPE IF EXISTS document_status;
    `
  },
  {
    version: 9,
    name: "create_aml_alerts",
    up: `
      CREATE TYPE aml_action AS ENUM ('PASS', 'FLAG', 'HOLD', 'BLOCK', 'SAR');
      CREATE TYPE aml_severity AS ENUM ('NONE', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
      CREATE TYPE alert_status AS ENUM ('OPEN', 'UNDER_REVIEW', 'RESOLVED', 'ESCALATED', 'FILED');

      CREATE TABLE aml_alerts (
        id BIGSERIAL PRIMARY KEY,
        payment_id UUID REFERENCES payments(id),
        customer_id UUID NOT NULL REFERENCES customers(id),
        
        -- Detection
        action aml_action NOT NULL,
        severity aml_severity NOT NULL,
        risk_score SMALLINT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
        
        -- Indicators
        indicators JSONB NOT NULL DEFAULT '[]',
        indicator_count SMALLINT NOT NULL DEFAULT 0,
        patterns_triggered TEXT[] NOT NULL DEFAULT '{}',
        
        -- Review workflow
        status alert_status NOT NULL DEFAULT 'OPEN',
        assigned_to VARCHAR(128),
        reviewed_at TIMESTAMPTZ,
        resolution_notes TEXT,
        
        -- SAR
        sar_required BOOLEAN NOT NULL DEFAULT FALSE,
        sar_draft JSONB,
        sar_filed_at TIMESTAMPTZ,
        sar_reference VARCHAR(64),
        
        -- Timestamps
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX idx_aml_alerts_customer ON aml_alerts(customer_id);
      CREATE INDEX idx_aml_alerts_payment ON aml_alerts(payment_id);
      CREATE INDEX idx_aml_alerts_status ON aml_alerts(status)
        WHERE status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED');
      CREATE INDEX idx_aml_alerts_severity ON aml_alerts(severity, created_at DESC);
      CREATE INDEX idx_aml_alerts_sar ON aml_alerts(sar_required)
        WHERE sar_required = TRUE AND sar_filed_at IS NULL;
      CREATE INDEX idx_aml_alerts_patterns ON aml_alerts USING GIN(patterns_triggered);
    `,
    down: `
      DROP TABLE IF EXISTS aml_alerts;
      DROP TYPE IF EXISTS aml_action;
      DROP TYPE IF EXISTS aml_severity;
      DROP TYPE IF EXISTS alert_status;
    `
  },
  {
    version: 10,
    name: "create_timelock_contracts",
    up: `
      CREATE TYPE contract_state AS ENUM (
        'CREATED', 'ACTIVE', 'EXECUTING', 'EXECUTED',
        'EXPIRED', 'CANCELLED', 'REVERTED'
      );
      CREATE TYPE fee_tier AS ENUM ('INSTANT', 'DEDUCTED', 'TIMELOCK');

      CREATE TABLE timelock_contracts (
        id VARCHAR(64) PRIMARY KEY,
        payment_id UUID NOT NULL REFERENCES payments(id),
        customer_id UUID NOT NULL REFERENCES customers(id),
        state contract_state NOT NULL DEFAULT 'CREATED',
        
        -- Financial terms
        principal NUMERIC(18,6) NOT NULL,
        send_currency CHAR(3) NOT NULL,
        receive_currency CHAR(3) NOT NULL,
        fee_amount_if_charged NUMERIC(18,6) NOT NULL,
        fee_bps SMALLINT NOT NULL,
        
        -- FX terms
        entry_rate NUMERIC(18,8) NOT NULL,
        break_even_rate NUMERIC(18,8) NOT NULL,
        rate_movement_required NUMERIC(8,4) NOT NULL,
        best_rate_seen NUMERIC(18,8),
        worst_rate_seen NUMERIC(18,8),
        execution_rate NUMERIC(18,8),
        
        -- Time terms
        max_duration_hours SMALLINT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        
        -- Fallback
        fallback_tier fee_tier NOT NULL DEFAULT 'DEDUCTED',
        
        -- Execution result
        execution_savings JSONB,
        
        -- Rate history (sampled snapshots)
        rate_snapshots JSONB NOT NULL DEFAULT '[]',
        
        -- Derivative metadata
        derivative_profile JSONB,
        
        -- Audit
        state_history JSONB NOT NULL DEFAULT '[]',
        
        -- Timestamps
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        executed_at TIMESTAMPTZ,
        
        -- Constraints
        CONSTRAINT positive_principal CHECK (principal > 0),
        CONSTRAINT valid_duration CHECK (max_duration_hours BETWEEN 1 AND 168)
      );

      CREATE INDEX idx_tlc_state ON timelock_contracts(state);
      CREATE INDEX idx_tlc_active ON timelock_contracts(expires_at)
        WHERE state = 'ACTIVE';
      CREATE INDEX idx_tlc_customer ON timelock_contracts(customer_id);
      CREATE INDEX idx_tlc_payment ON timelock_contracts(payment_id);
      CREATE INDEX idx_tlc_pair ON timelock_contracts(send_currency, receive_currency);
    `,
    down: `
      DROP TABLE IF EXISTS timelock_contracts;
      DROP TYPE IF EXISTS contract_state;
      DROP TYPE IF EXISTS fee_tier;
    `
  },
  {
    version: 11,
    name: "create_derivative_book",
    up: `
      -- Aggregated TimeLock positions for derivative trading
      -- Each row = a pool of TimeLock contracts on the same corridor
      
      CREATE TABLE derivative_positions (
        id BIGSERIAL PRIMARY KEY,
        
        -- Corridor
        send_currency CHAR(3) NOT NULL,
        receive_currency CHAR(3) NOT NULL,
        
        -- Aggregated exposure
        total_notional NUMERIC(18,2) NOT NULL DEFAULT 0,
        contract_count INTEGER NOT NULL DEFAULT 0,
        weighted_avg_strike NUMERIC(18,8),
        earliest_expiry TIMESTAMPTZ,
        latest_expiry TIMESTAMPTZ,
        
        -- Theoretical valuation
        total_theoretical_value NUMERIC(18,2) NOT NULL DEFAULT 0,
        implied_volatility NUMERIC(8,6),
        delta_exposure NUMERIC(18,2),
        
        -- P&L tracking
        realized_pnl NUMERIC(18,2) NOT NULL DEFAULT 0,
        unrealized_pnl NUMERIC(18,2) NOT NULL DEFAULT 0,
        fees_earned NUMERIC(18,2) NOT NULL DEFAULT 0,
        fees_waived NUMERIC(18,2) NOT NULL DEFAULT 0,
        
        -- Stats
        contracts_executed INTEGER NOT NULL DEFAULT 0,
        contracts_expired INTEGER NOT NULL DEFAULT 0,
        contracts_cancelled INTEGER NOT NULL DEFAULT 0,
        execution_rate_pct NUMERIC(5,2),
        
        -- Timestamps
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE UNIQUE INDEX idx_deriv_corridor ON derivative_positions(send_currency, receive_currency);
      
      -- Materialized view for real-time dashboard
      CREATE OR REPLACE VIEW active_contract_summary AS
      SELECT
        send_currency,
        receive_currency,
        COUNT(*) as active_contracts,
        SUM(principal) as total_exposure,
        AVG(rate_movement_required) as avg_movement_needed,
        MIN(expires_at) as next_expiry,
        AVG(EXTRACT(EPOCH FROM (expires_at - NOW())) / 3600) as avg_hours_remaining
      FROM timelock_contracts
      WHERE state = 'ACTIVE'
      GROUP BY send_currency, receive_currency;
    `,
    down: `
      DROP VIEW IF EXISTS active_contract_summary;
      DROP TABLE IF EXISTS derivative_positions;
    `
  },
  {
    version: 12,
    name: "create_encryption_key_registry",
    up: `
      -- Tracks encryption key versions for rotation
      CREATE TABLE encryption_keys (
        version INTEGER PRIMARY KEY,
        purpose VARCHAR(30) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        rotated_at TIMESTAMPTZ,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        
        -- Key fingerprint (NOT the key itself — keys are in HSM/secrets manager)
        fingerprint CHAR(64) NOT NULL,
        algorithm VARCHAR(20) NOT NULL DEFAULT 'AES-256-GCM'
      );

      CREATE INDEX idx_enc_keys_active ON encryption_keys(active) WHERE active = TRUE;
    `,
    down: `DROP TABLE IF EXISTS encryption_keys;`
  },
  {
    version: 13,
    name: "add_customer_foreign_key_to_payments",
    up: `
      ALTER TABLE payments ADD COLUMN customer_id UUID REFERENCES customers(id);
      ALTER TABLE payments ADD COLUMN fee_tier VARCHAR(10);
      ALTER TABLE payments ADD COLUMN timelock_contract_id VARCHAR(64);
      ALTER TABLE payments ADD COLUMN aml_action VARCHAR(10);
      ALTER TABLE payments ADD COLUMN aml_risk_score SMALLINT;
      
      CREATE INDEX idx_payments_customer ON payments(customer_id);
      CREATE INDEX idx_payments_timelock ON payments(timelock_contract_id)
        WHERE timelock_contract_id IS NOT NULL;
    `,
    down: `
      ALTER TABLE payments DROP COLUMN IF EXISTS customer_id;
      ALTER TABLE payments DROP COLUMN IF EXISTS fee_tier;
      ALTER TABLE payments DROP COLUMN IF EXISTS timelock_contract_id;
      ALTER TABLE payments DROP COLUMN IF EXISTS aml_action;
      ALTER TABLE payments DROP COLUMN IF EXISTS aml_risk_score;
    `
  }
];

module.exports = { V2_MIGRATIONS };
