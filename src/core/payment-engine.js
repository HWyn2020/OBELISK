/**
 * Payment Engine
 * 
 * Orchestrates the full payment lifecycle through a strict state machine.
 * Every transition is validated, logged, and persisted atomically.
 * 
 * State Machine:
 * 
 *   INITIATED
 *     │
 *     ▼
 *   VALIDATED ──────────> REJECTED (validation failed)
 *     │
 *     ▼
 *   SCREENED ────────────> HELD (sanctions match, pending review)
 *     │                      │
 *     ▼                      ▼
 *   QUOTED                 REJECTED (review confirmed match)
 *     │                   or
 *     ▼                   SCREENED (review cleared, continues)
 *   CONFIRMED
 *     │
 *     ▼
 *   PROCESSING
 *     │
 *     ├──────────────────> FAILED (processing error)
 *     ▼
 *   SETTLED
 *     │
 *     ▼
 *   COMPLETED
 * 
 * Additional states:
 *   CANCELLED - User-initiated cancellation (from INITIATED, VALIDATED, QUOTED)
 *   EXPIRED   - TTL exceeded without confirmation
 *   REFUNDED  - Post-settlement reversal
 */

const { v4: uuidv4 } = require("uuid");
const { IBANValidator, SWIFTValidator } = require("./validator");
const { isValidCurrency } = require("../utils/currency");
const logger = require("../utils/logger");

// Valid state transitions
const STATE_MACHINE = {
  INITIATED:  ["VALIDATED", "REJECTED", "CANCELLED"],
  VALIDATED:  ["SCREENED", "REJECTED", "CANCELLED"],
  SCREENED:   ["QUOTED", "HELD", "CANCELLED"],
  HELD:       ["SCREENED", "REJECTED"],
  QUOTED:     ["CONFIRMED", "CANCELLED", "EXPIRED"],
  CONFIRMED:  ["PROCESSING"],
  PROCESSING: ["SETTLED", "FAILED"],
  SETTLED:    ["COMPLETED", "REFUNDED"],
  COMPLETED:  [],
  FAILED:     ["INITIATED"], // retry
  REJECTED:   [],
  CANCELLED:  [],
  EXPIRED:    [],
  REFUNDED:   []
};

const TERMINAL_STATES = ["COMPLETED", "FAILED", "REJECTED", "CANCELLED", "EXPIRED", "REFUNDED"];
const CANCELLABLE_STATES = ["INITIATED", "VALIDATED", "QUOTED"];

class PaymentEngine {
  constructor({ db, fxService, sanctionsScreener, config }) {
    this.db = db;
    this.fx = fxService;
    this.sanctions = sanctionsScreener;
    this.maxAmount = config?.maxAmount || 1000000;
    this.ttlHours = config?.ttlHours || 72;
  }
  
  /**
   * Create a new payment
   * @param {Object} params - Payment parameters
   * @returns {Object} Created payment with ID and initial state
   */
  async create(params) {
    const paymentId = uuidv4();
    const idempotencyKey = params.idempotencyKey || null;
    
    // Check idempotency key
    if (idempotencyKey) {
      const existing = await this.db.findByIdempotencyKey(idempotencyKey);
      if (existing) {
        logger.info("Idempotent request matched", { paymentId: existing.id, idempotencyKey });
        return existing;
      }
    }
    
    const payment = {
      id: paymentId,
      idempotencyKey,
      state: "INITIATED",
      
      // Amounts
      sendAmount: params.amount,
      sendCurrency: params.sendCurrency,
      receiveCurrency: params.receiveCurrency,
      receiveAmount: null,
      
      // Parties
      sender: {
        name: params.sender.name,
        iban: params.sender.iban || null,
        swift: params.sender.swift || null,
        country: params.sender.country,
        reference: params.sender.reference || null
      },
      beneficiary: {
        name: params.beneficiary.name,
        iban: params.beneficiary.iban || null,
        swift: params.beneficiary.swift || null,
        country: params.beneficiary.country,
        reference: params.beneficiary.reference || null
      },
      
      // FX
      quotedRate: null,
      quoteExpiresAt: null,
      
      // Compliance
      sanctionsResult: null,
      
      // Metadata
      purpose: params.purpose || null,
      memo: params.memo || null,
      webhookUrl: params.webhookUrl || null,
      
      // Timestamps
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      completedAt: null,
      
      // Audit trail
      stateHistory: [{
        from: null,
        to: "INITIATED",
        reason: "Payment created",
        timestamp: new Date().toISOString()
      }]
    };
    
    await this.db.create(payment);
    
    logger.info("Payment created", {
      paymentId,
      sendCurrency: payment.sendCurrency,
      receiveCurrency: payment.receiveCurrency,
      state: payment.state
    });
    
    return payment;
  }
  
  /**
   * Validate payment data (INITIATED -> VALIDATED)
   */
  async validate(paymentId) {
    const payment = await this._getPayment(paymentId);
    const errors = [];
    
    // Amount validation
    if (!payment.sendAmount || payment.sendAmount <= 0) {
      errors.push("Send amount must be positive");
    }
    if (payment.sendAmount > this.maxAmount) {
      errors.push(`Amount exceeds maximum of ${this.maxAmount}`);
    }
    
    // Currency validation
    if (!isValidCurrency(payment.sendCurrency)) {
      errors.push(`Invalid send currency: ${payment.sendCurrency}`);
    }
    if (!isValidCurrency(payment.receiveCurrency)) {
      errors.push(`Invalid receive currency: ${payment.receiveCurrency}`);
    }
    
    // IBAN validation (if provided)
    if (payment.sender.iban) {
      const ibanResult = IBANValidator.validate(payment.sender.iban);
      if (!ibanResult.valid) errors.push(`Sender IBAN: ${ibanResult.errors.join(", ")}`);
    }
    if (payment.beneficiary.iban) {
      const ibanResult = IBANValidator.validate(payment.beneficiary.iban);
      if (!ibanResult.valid) errors.push(`Beneficiary IBAN: ${ibanResult.errors.join(", ")}`);
    }
    
    // SWIFT validation (if provided)
    if (payment.sender.swift) {
      const swiftResult = SWIFTValidator.validate(payment.sender.swift);
      if (!swiftResult.valid) errors.push(`Sender SWIFT: ${swiftResult.errors.join(", ")}`);
    }
    if (payment.beneficiary.swift) {
      const swiftResult = SWIFTValidator.validate(payment.beneficiary.swift);
      if (!swiftResult.valid) errors.push(`Beneficiary SWIFT: ${swiftResult.errors.join(", ")}`);
    }
    
    // Party name validation
    if (!payment.sender.name || payment.sender.name.trim().length < 2) {
      errors.push("Sender name is required (min 2 characters)");
    }
    if (!payment.beneficiary.name || payment.beneficiary.name.trim().length < 2) {
      errors.push("Beneficiary name is required (min 2 characters)");
    }
    
    if (errors.length > 0) {
      await this._transition(payment, "REJECTED", `Validation failed: ${errors.join("; ")}`);
      return { valid: false, errors, state: "REJECTED" };
    }
    
    await this._transition(payment, "VALIDATED", "All validations passed");
    return { valid: true, errors: [], state: "VALIDATED" };
  }
  
  /**
   * Screen against sanctions lists (VALIDATED -> SCREENED or HELD)
   */
  async screen(paymentId) {
    const payment = await this._getPayment(paymentId);
    
    const result = this.sanctions.screenPayment(payment);
    
    // Store screening result
    payment.sanctionsResult = {
      clear: result.clear,
      screenedAt: result.screenedAt,
      senderMatches: result.sender.matches.length,
      beneficiaryMatches: result.beneficiary.matches.length,
      details: result
    };
    
    if (!result.clear) {
      await this._transition(payment, "HELD", 
        `Sanctions match detected: ${result.sender.matches.length} sender, ${result.beneficiary.matches.length} beneficiary`
      );
      return { clear: false, state: "HELD", matches: result };
    }
    
    await this._transition(payment, "SCREENED", "Sanctions screening clear");
    return { clear: true, state: "SCREENED" };
  }
  
  /**
   * Get FX quote (SCREENED -> QUOTED)
   */
  async quote(paymentId) {
    const payment = await this._getPayment(paymentId);
    
    const conversion = await this.fx.convert(
      payment.sendAmount,
      payment.sendCurrency,
      payment.receiveCurrency
    );
    
    // Quote valid for 30 seconds
    const quoteExpiry = new Date(Date.now() + 30000);
    
    payment.quotedRate = conversion.rate.rate;
    payment.receiveAmount = conversion.to.amount;
    payment.quoteExpiresAt = quoteExpiry.toISOString();
    
    await this._transition(payment, "QUOTED", 
      `Rate ${conversion.rate.pair}: ${conversion.rate.rate}, receive ${conversion.to.amount} ${conversion.to.currency}`
    );
    
    return {
      state: "QUOTED",
      sendAmount: payment.sendAmount,
      sendCurrency: payment.sendCurrency,
      receiveAmount: payment.receiveAmount,
      receiveCurrency: payment.receiveCurrency,
      rate: conversion.rate,
      expiresAt: payment.quoteExpiresAt
    };
  }
  
  /**
   * Confirm payment at quoted rate (QUOTED -> CONFIRMED)
   */
  async confirm(paymentId) {
    const payment = await this._getPayment(paymentId);
    
    // Check quote expiry
    if (payment.quoteExpiresAt && new Date(payment.quoteExpiresAt) < new Date()) {
      await this._transition(payment, "EXPIRED", "FX quote expired");
      return { confirmed: false, state: "EXPIRED", reason: "Quote expired. Request a new quote." };
    }
    
    await this._transition(payment, "CONFIRMED", "Payment confirmed by user");
    return { confirmed: true, state: "CONFIRMED" };
  }
  
  /**
   * Process the payment (CONFIRMED -> PROCESSING -> SETTLED)
   * In production: this integrates with banking rails (SWIFT, SEPA, etc.)
   */
  async process(paymentId) {
    const payment = await this._getPayment(paymentId);
    
    await this._transition(payment, "PROCESSING", "Payment submitted to banking network");
    
    // Simulate processing (in production: SWIFT/SEPA API calls)
    // This is where the actual banking integration happens
    try {
      // Generate settlement reference
      const settlementRef = `CPAY-${Date.now()}-${paymentId.slice(0, 8)}`;
      
      payment.settlementReference = settlementRef;
      payment.completedAt = new Date().toISOString();
      
      await this._transition(payment, "SETTLED", `Settlement ref: ${settlementRef}`);
      await this._transition(payment, "COMPLETED", "Payment delivered");
      
      return { state: "COMPLETED", settlementReference: settlementRef };
    } catch (err) {
      await this._transition(payment, "FAILED", `Processing error: ${err.message}`);
      return { state: "FAILED", error: err.message };
    }
  }
  
  /**
   * Cancel a payment (from cancellable states only)
   */
  async cancel(paymentId, reason) {
    const payment = await this._getPayment(paymentId);
    
    if (!CANCELLABLE_STATES.includes(payment.state)) {
      throw new Error(`Cannot cancel payment in state: ${payment.state}`);
    }
    
    await this._transition(payment, "CANCELLED", reason || "Cancelled by user");
    return { state: "CANCELLED" };
  }
  
  /**
   * Get payment by ID
   */
  async get(paymentId) {
    return this._getPayment(paymentId);
  }
  
  /**
   * Internal: load payment and verify it exists
   */
  async _getPayment(paymentId) {
    const payment = await this.db.findById(paymentId);
    if (!payment) throw new Error(`Payment not found: ${paymentId}`);
    return payment;
  }
  
  /**
   * Internal: validate and execute state transition
   */
  async _transition(payment, newState, reason) {
    const currentState = payment.state;
    const validTransitions = STATE_MACHINE[currentState];
    
    if (!validTransitions) {
      throw new Error(`Unknown state: ${currentState}`);
    }
    
    if (!validTransitions.includes(newState)) {
      throw new Error(
        `Invalid transition: ${currentState} -> ${newState}. ` +
        `Valid transitions: ${validTransitions.join(", ") || "none (terminal state)"}`
      );
    }
    
    const transition = {
      from: currentState,
      to: newState,
      reason,
      timestamp: new Date().toISOString()
    };
    
    payment.state = newState;
    payment.updatedAt = transition.timestamp;
    payment.stateHistory.push(transition);
    
    await this.db.update(payment);
    
    logger.info("Payment state transition", {
      paymentId: payment.id,
      from: currentState,
      to: newState,
      reason
    });
  }
}

module.exports = { PaymentEngine, STATE_MACHINE, TERMINAL_STATES, CANCELLABLE_STATES };
