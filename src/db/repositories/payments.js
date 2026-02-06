/**
 * Payment Repository
 * 
 * Data access layer for payments. Handles serialization between
 * application objects and PostgreSQL rows, including JSONB fields.
 */

const { pool } = require("../migrate");
const logger = require("../../utils/logger");

class PaymentRepository {
  async create(payment) {
    const result = await pool.query(
      `INSERT INTO payments (
        id, idempotency_key, state, send_amount, send_currency,
        receive_amount, receive_currency, quoted_rate, quote_expires_at,
        sender, beneficiary, sanctions_result, settlement_reference,
        purpose, memo, webhook_url, state_history, created_at, updated_at, completed_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
      ) RETURNING *`,
      [
        payment.id,
        payment.idempotencyKey,
        payment.state,
        payment.sendAmount,
        payment.sendCurrency,
        payment.receiveAmount,
        payment.receiveCurrency,
        payment.quotedRate,
        payment.quoteExpiresAt,
        JSON.stringify(payment.sender),
        JSON.stringify(payment.beneficiary),
        payment.sanctionsResult ? JSON.stringify(payment.sanctionsResult) : null,
        payment.settlementReference || null,
        payment.purpose,
        payment.memo,
        payment.webhookUrl,
        JSON.stringify(payment.stateHistory),
        payment.createdAt,
        payment.updatedAt,
        payment.completedAt
      ]
    );
    
    return this._deserialize(result.rows[0]);
  }
  
  async update(payment) {
    const result = await pool.query(
      `UPDATE payments SET
        state = $2,
        receive_amount = $3,
        quoted_rate = $4,
        quote_expires_at = $5,
        sanctions_result = $6,
        settlement_reference = $7,
        state_history = $8,
        updated_at = $9,
        completed_at = $10
      WHERE id = $1
      RETURNING *`,
      [
        payment.id,
        payment.state,
        payment.receiveAmount,
        payment.quotedRate,
        payment.quoteExpiresAt,
        payment.sanctionsResult ? JSON.stringify(payment.sanctionsResult) : null,
        payment.settlementReference || null,
        JSON.stringify(payment.stateHistory),
        payment.updatedAt,
        payment.completedAt
      ]
    );
    
    if (result.rows.length === 0) {
      throw new Error(`Payment not found: ${payment.id}`);
    }
    
    return this._deserialize(result.rows[0]);
  }
  
  async findById(id) {
    const result = await pool.query("SELECT * FROM payments WHERE id = $1", [id]);
    return result.rows.length > 0 ? this._deserialize(result.rows[0]) : null;
  }
  
  async findByIdempotencyKey(key) {
    const result = await pool.query(
      "SELECT * FROM payments WHERE idempotency_key = $1", [key]
    );
    return result.rows.length > 0 ? this._deserialize(result.rows[0]) : null;
  }
  
  async findByState(state, limit = 50) {
    const result = await pool.query(
      "SELECT * FROM payments WHERE state = $1 ORDER BY created_at DESC LIMIT $2",
      [state, limit]
    );
    return result.rows.map(r => this._deserialize(r));
  }
  
  async findRecent(limit = 20, offset = 0) {
    const result = await pool.query(
      "SELECT * FROM payments ORDER BY created_at DESC LIMIT $1 OFFSET $2",
      [limit, offset]
    );
    return result.rows.map(r => this._deserialize(r));
  }
  
  async getStats() {
    const result = await pool.query(`
      SELECT 
        state,
        COUNT(*) as count,
        SUM(send_amount) as total_amount,
        AVG(send_amount) as avg_amount,
        COUNT(DISTINCT send_currency || receive_currency) as currency_pairs
      FROM payments
      WHERE created_at > NOW() - INTERVAL '24 hours'
      GROUP BY state
      ORDER BY count DESC
    `);
    return result.rows;
  }
  
  _deserialize(row) {
    if (!row) return null;
    
    return {
      id: row.id,
      idempotencyKey: row.idempotency_key,
      state: row.state,
      sendAmount: parseFloat(row.send_amount),
      sendCurrency: row.send_currency,
      receiveAmount: row.receive_amount ? parseFloat(row.receive_amount) : null,
      receiveCurrency: row.receive_currency,
      quotedRate: row.quoted_rate ? parseFloat(row.quoted_rate) : null,
      quoteExpiresAt: row.quote_expires_at,
      sender: typeof row.sender === "string" ? JSON.parse(row.sender) : row.sender,
      beneficiary: typeof row.beneficiary === "string" ? JSON.parse(row.beneficiary) : row.beneficiary,
      sanctionsResult: row.sanctions_result ? (typeof row.sanctions_result === "string" ? JSON.parse(row.sanctions_result) : row.sanctions_result) : null,
      settlementReference: row.settlement_reference,
      purpose: row.purpose,
      memo: row.memo,
      webhookUrl: row.webhook_url,
      stateHistory: typeof row.state_history === "string" ? JSON.parse(row.state_history) : row.state_history,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      completedAt: row.completed_at
    };
  }
}

module.exports = { PaymentRepository };
