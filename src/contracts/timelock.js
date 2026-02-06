/**
 * TimeLock Contract Engine
 * 
 * Three-tier FX fee model for cross-border payments.
 * 
 * ═══════════════════════════════════════════════════════════════════
 * TIER 1: INSTANT (Pay the fee upfront)
 * ═══════════════════════════════════════════════════════════════════
 * 
 *   User sends $20 USD → Singapore
 *   Fee: 1.2% of $20 = $0.24
 *   User pays: $20.24 total
 *   Receiver gets: full $20 USD equivalent in SGD
 *   Rate: live spot rate at execution
 *   Settlement: immediate
 * 
 * ═══════════════════════════════════════════════════════════════════
 * TIER 2: DEDUCTED (Fee taken from transfer amount)
 * ═══════════════════════════════════════════════════════════════════
 * 
 *   User sends $20 USD → Singapore
 *   Fee: 1.2% of $20 = $0.24
 *   Net transfer: $20 - $0.24 = $19.76
 *   Receiver gets: $19.76 USD equivalent in SGD ($25.10 at 1.27)
 *   Rate: live spot rate at execution
 *   Settlement: immediate
 * 
 * ═══════════════════════════════════════════════════════════════════
 * TIER 3: TIMELOCK (Gamble on FX movement to avoid the fee)
 * ═══════════════════════════════════════════════════════════════════
 * 
 *   User sends $20 USD → Singapore
 *   No fee charged IF the FX rate moves favorably enough to cover it.
 *   
 *   Mechanism:
 *   1. User requests TimeLock. No money moves yet.
 *   2. System creates a contract:
 *      - Locked amount: $20 USD
 *      - Target: send full $20 to receiver
 *      - Fee to cover: 1.2% = $0.24 USD
 *      - Entry rate: 1.2700 USD/SGD (spot at contract creation)
 *      - Break-even rate: 1.2854 USD/SGD (rate where SGD weakens
 *        enough that the $0.24 is covered by the FX difference)
 *      - Max duration: 72 hours (configurable)
 *      - User can cancel anytime (reverts to Tier 1 or 2)
 *   
 *   3. FX Monitor watches the USD/SGD rate:
 *      
 *      IF rate reaches break-even (1.2854+):
 *        → EXECUTE: Send $20 at the favorable rate.
 *          The FX gain covers the fee. User paid nothing extra.
 *          Receiver gets full amount. We keep the spread.
 *      
 *      IF rate moves AGAINST the user (USD weakens vs SGD):
 *        → User gets notified. Can choose to:
 *          a) Keep waiting (if time remains)
 *          b) Cancel and pay the 1.2% fee (Tier 1)
 *          c) Cancel and deduct from amount (Tier 2)
 *      
 *      IF contract expires (72 hours):
 *        → AUTO-REVERT to Tier 2 (fee deducted from amount)
 *        → Or user pre-selected fallback behavior
 * 
 * ═══════════════════════════════════════════════════════════════════
 * DERIVATIVE POTENTIAL (TimeLock as Tradeable Instrument)
 * ═══════════════════════════════════════════════════════════════════
 * 
 *   Each TimeLock contract is essentially a micro FX option:
 *   - Notional: the transfer amount
 *   - Strike: the break-even rate
 *   - Expiry: the max duration
 *   - Underlying: the currency pair
 *   
 *   These contracts could be:
 *   1. Aggregated into pools (like MBS but for FX micro-forwards)
 *   2. Sold to market makers who want exposure to specific corridors
 *   3. Used as hedging instruments by FX desks
 *   4. Tokenized on-chain as ERC-721 or ERC-1155 (each contract = NFT)
 *   
 *   Revenue model:
 *   - Spread between break-even rate and actual execution rate
 *   - Premium from derivative buyers
 *   - Aggregation fees for pool management
 *   
 *   Regulatory note: This would require financial instrument licensing
 *   (MiFID II in EU, MAS licensing in SG, SEC/CFTC in US).
 *   Current implementation does NOT create tradeable instruments —
 *   it only manages the user-facing TimeLock mechanic.
 */

const crypto = require("crypto");
const logger = require("../utils/logger");

// Contract states
const CONTRACT_STATES = {
  CREATED:    "CREATED",       // Contract generated, not yet active
  ACTIVE:     "ACTIVE",        // Monitoring FX rate
  EXECUTING:  "EXECUTING",     // Break-even hit, processing transfer
  EXECUTED:   "EXECUTED",      // Transfer complete, user paid no fee
  EXPIRED:    "EXPIRED",       // Max duration reached, fallback triggered
  CANCELLED:  "CANCELLED",     // User cancelled
  REVERTED:   "REVERTED"       // Fell back to Tier 1 or Tier 2
};

// Fee model
const DEFAULT_FEE_BPS = 120; // 1.2% = 120 basis points
const MAX_TIMELOCK_HOURS = 72;
const MIN_TIMELOCK_HOURS = 1;
const FX_CHECK_INTERVAL_MS = 60000; // Check rate every 60 seconds

// ═══════════════════════════════════════════════════════════════════
// ANTI-EXPLOITATION: Three-layer defense against free optionality
// ═══════════════════════════════════════════════════════════════════

// FIX 1: Minimum lock-in period — kills "peek and bail" attack
const MIN_LOCK_IN_HOURS = 48; // Cannot cancel within 48 hours of creation

// FIX 2: Per-customer contract cap — kills "spray and pray" attack
const TRUST_TIERS = {
  NEW:         { maxDailyContracts: 1, label: "New Customer" },
  ESTABLISHED: { maxDailyContracts: 3, label: "Established Customer" },
  TRUSTED:     { maxDailyContracts: 5, label: "Trusted Customer" }
};
const DEFAULT_TRUST_TIER = "NEW";

// FIX 3: Non-refundable contract fee — makes optionality non-free
const CONTRACT_FEE_FLAT = 1.00;  // $1 flat fee per contract
const CONTRACT_FEE_BPS = 120;    // 1.2% of principal (same as transfer fee)
// Total cost = 1.2% + $1. Not refunded on cancel. Credited if contract executes.

class TimeLockEngine {
  constructor({ fxService, paymentEngine, securityQuestions, config = {} }) {
    this.fx = fxService;
    this.payments = paymentEngine;
    this.securityQuestions = securityQuestions || null;
    this.feeBps = config.feeBps || DEFAULT_FEE_BPS;
    this.maxDurationHours = config.maxDurationHours || MAX_TIMELOCK_HOURS;
    this.minLockInHours = config.minLockInHours !== undefined ? config.minLockInHours : MIN_LOCK_IN_HOURS;
    this.contractFeeBps = config.contractFeeBps !== undefined ? config.contractFeeBps : CONTRACT_FEE_BPS;
    this.contractFeeFlat = config.contractFeeFlat !== undefined ? config.contractFeeFlat : CONTRACT_FEE_FLAT;
    
    // Active contracts being monitored
    this.activeContracts = new Map();
    
    // FIX 2: Per-customer daily contract tracking
    this.customerContractLog = new Map(); // customerId → [{ contractId, createdAt, corridor }]
    this.customerTrustTiers = new Map();  // customerId → "NEW" | "ESTABLISHED" | "TRUSTED"
    
    // Encryption engine for hiding derivative internals
    this.encryptionEngine = config.encryptionEngine || null;
    
    // FX monitoring interval
    this.monitorInterval = null;
  }
  
  /**
   * Calculate all three fee tier options for a transfer
   */
  async calculateOptions(amount, sendCurrency, receiveCurrency) {
    const rate = await this.fx.getRate(sendCurrency, receiveCurrency, false);
    const feeAmount = amount * (this.feeBps / 10000);
    const feePercent = this.feeBps / 100;
    
    // TIER 1: Instant (user pays fee on top)
    const tier1 = {
      tier: "INSTANT",
      sendAmount: amount,
      feeAmount,
      totalUserPays: amount + feeAmount,
      receiverGets: amount * rate.rate,
      receiveCurrency,
      rate: rate.rate,
      feePercent,
      settlement: "IMMEDIATE"
    };
    
    // TIER 2: Deducted (fee taken from amount)
    const netAmount = amount - feeAmount;
    const tier2 = {
      tier: "DEDUCTED",
      sendAmount: amount,
      feeAmount,
      totalUserPays: amount,
      netTransferAmount: netAmount,
      receiverGets: netAmount * rate.rate,
      receiveCurrency,
      rate: rate.rate,
      feePercent,
      settlement: "IMMEDIATE"
    };
    
    // TIER 3: TimeLock (gamble on FX movement)
    const breakEvenRate = this._calculateBreakEvenRate(
      amount, feeAmount, sendCurrency, receiveCurrency, rate.rate
    );
    
    const tier3 = {
      tier: "TIMELOCK",
      sendAmount: amount,
      feeAmount: 0, // Potentially zero
      totalUserPays: amount, // Only the principal
      receiverGets: amount * rate.rate, // Full amount if FX moves favorably
      receiveCurrency,
      currentRate: rate.rate,
      breakEvenRate: breakEvenRate.rate,
      rateMovementNeeded: breakEvenRate.movementPercent,
      maxDurationHours: this.maxDurationHours,
      settlement: "CONDITIONAL",
      riskDisclosure: `If ${sendCurrency} strengthens ${breakEvenRate.movementPercent}% against ${receiveCurrency} within ${this.maxDurationHours} hours, the transfer executes with no fee. Otherwise, falls back to your chosen alternative.`
    };
    
    return {
      transferAmount: amount,
      sendCurrency,
      receiveCurrency,
      currentRate: rate.rate,
      rateSource: rate.source,
      rateTimestamp: rate.rateTimestamp,
      options: { instant: tier1, deducted: tier2, timeLock: tier3 },
      calculatedAt: new Date().toISOString()
    };
  }
  
  /**
   * Create a TimeLock contract
   */
  async createContract(params) {
    const {
      paymentId,
      customerId,
      amount,
      sendCurrency,
      receiveCurrency,
      fallbackTier,          // 'INSTANT' or 'DEDUCTED' when contract expires
      maxDurationHours,
      securityChallengeToken  // Required: proof of security question verification
    } = params;
    
    // Validate basics
    if (!paymentId) throw new Error("Payment ID is required");
    if (!customerId) throw new Error("Customer ID is required");
    if (!amount || amount <= 0) throw new Error("Amount must be positive");
    if (!['INSTANT', 'DEDUCTED'].includes(fallbackTier)) {
      throw new Error("Fallback tier must be INSTANT or DEDUCTED");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // FIX 1 (GATE): Security question verification
    // Customer must pass a 3-question challenge before creating
    // ═══════════════════════════════════════════════════════════════
    if (this.securityQuestions) {
      if (!securityChallengeToken) {
        throw new Error(
          "Security challenge verification required to create TimeLock contract. " +
          "Call generateChallenge('TIMELOCK_CREATE') first."
        );
      }
      // Token validation happens upstream — if we got here, the orchestrator
      // already verified the challenge. We just enforce the token exists.
      // In production: verify token signature + expiry + customer binding.
    }
    
    // ═══════════════════════════════════════════════════════════════
    // FIX 2: Per-customer daily contract cap
    // NEW customers: 1/day. ESTABLISHED: 3/day. TRUSTED: 5/day.
    // ═══════════════════════════════════════════════════════════════
    const dailyLimitCheck = this._checkDailyContractLimit(customerId);
    if (!dailyLimitCheck.allowed) {
      throw new Error(
        `Daily TimeLock contract limit reached. ` +
        `Your tier (${dailyLimitCheck.tier}) allows ${dailyLimitCheck.maxDaily} contract(s) per day. ` +
        `You have used ${dailyLimitCheck.usedToday}. ` +
        `Next available: ${dailyLimitCheck.nextAvailable}`
      );
    }
    
    const duration = Math.min(
      Math.max(maxDurationHours || this.maxDurationHours, MIN_TIMELOCK_HOURS),
      MAX_TIMELOCK_HOURS
    );
    
    // Get current spot rate
    const spotRate = await this.fx.getRate(sendCurrency, receiveCurrency, false);
    const feeAmount = amount * (this.feeBps / 10000);
    const breakEven = this._calculateBreakEvenRate(
      amount, feeAmount, sendCurrency, receiveCurrency, spotRate.rate
    );
    
    // ═══════════════════════════════════════════════════════════════
    // FIX 3: Non-refundable contract fee (1.2% + $1)
    // Charged at creation. Credited if contract executes successfully.
    // NOT refunded on cancel or expiry.
    // ═══════════════════════════════════════════════════════════════
    const contractFeePercent = amount * (this.contractFeeBps / 10000);
    const contractFeeTotal = contractFeePercent + this.contractFeeFlat;
    
    const contractId = `TLC-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
    
    // Calculate lock-in expiry (FIX 1: 48-hour minimum before cancel allowed)
    const lockInExpiresAt = new Date(Date.now() + this.minLockInHours * 3600000).toISOString();
    
    // Build derivative profile (INTERNAL ONLY — never exposed to client)
    const derivativeProfileInternal = {
      notional: amount,
      notionalCurrency: sendCurrency,
      strike: breakEven.rate,
      expiry: new Date(Date.now() + duration * 3600000).toISOString(),
      underlying: `${sendCurrency}/${receiveCurrency}`,
      direction: breakEven.direction,
      optionType: "EUROPEAN_DIGITAL",
      theoreticalValue: this._estimateContractValue(amount, breakEven, duration)
    };
    
    // Encrypt derivative profile so it never appears in client responses
    let derivativeProfileSealed = null;
    if (this.encryptionEngine) {
      derivativeProfileSealed = this.encryptionEngine.encrypt(
        JSON.stringify(derivativeProfileInternal), "financial"
      );
    } else {
      // Mark as internal-only (production MUST use encryption)
      derivativeProfileSealed = {
        _sealed: true,
        _warning: "INTERNAL_ONLY_NOT_FOR_CLIENT",
        _data: derivativeProfileInternal
      };
    }
    
    const contract = {
      id: contractId,
      paymentId,
      customerId,
      state: CONTRACT_STATES.CREATED,
      
      // Financial terms
      principal: amount,
      sendCurrency,
      receiveCurrency,
      feeAmountIfCharged: feeAmount,
      feeBps: this.feeBps,
      
      // FIX 3: Non-refundable contract fee
      contractFee: {
        percentComponent: Math.round(contractFeePercent * 100) / 100,
        flatComponent: this.contractFeeFlat,
        total: Math.round(contractFeeTotal * 100) / 100,
        currency: sendCurrency,
        refundable: false,
        creditedOnExecution: true,
        chargedAt: new Date().toISOString()
      },
      
      // FX terms
      entryRate: spotRate.rate,
      breakEvenRate: breakEven.rate,
      rateMovementRequired: breakEven.movementPercent,
      bestRateSeen: spotRate.rate,
      worstRateSeen: spotRate.rate,
      
      // Time terms
      maxDurationHours: duration,
      expiresAt: new Date(Date.now() + duration * 3600000).toISOString(),
      
      // FIX 1: Lock-in period — cancel blocked until this timestamp
      lockInExpiresAt,
      lockInHours: this.minLockInHours,
      
      // Fallback
      fallbackTier,
      
      // Execution tracking
      executionRate: null,
      executionSavings: null,
      
      // Rate history (sampled)
      rateSnapshots: [{
        rate: spotRate.rate,
        timestamp: new Date().toISOString(),
        source: spotRate.source
      }],
      
      // State history
      stateHistory: [{
        from: null,
        to: CONTRACT_STATES.CREATED,
        reason: "Contract created",
        timestamp: new Date().toISOString()
      }],
      
      // Derivative metadata — SEALED, never in client responses
      _derivativeProfileSealed: derivativeProfileSealed,
      
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    // FIX 2: Record this contract against customer's daily limit
    this._recordContractCreation(customerId, contractId, `${sendCurrency}/${receiveCurrency}`);
    
    logger.info("TimeLock contract created", {
      contractId,
      paymentId,
      amount,
      pair: `${sendCurrency}/${receiveCurrency}`,
      entryRate: spotRate.rate,
      breakEvenRate: breakEven.rate,
      movementNeeded: `${breakEven.movementPercent}%`,
      contractFee: contractFeeTotal,
      lockInUntil: lockInExpiresAt,
      expiresAt: contract.expiresAt,
      customerTier: this._getCustomerTier(customerId)
    });
    
    return contract;
  }
  
  /**
   * Activate a contract (start monitoring FX)
   */
  async activateContract(contract) {
    if (contract.state !== CONTRACT_STATES.CREATED) {
      throw new Error(`Cannot activate contract in state: ${contract.state}`);
    }
    
    contract.state = CONTRACT_STATES.ACTIVE;
    contract.stateHistory.push({
      from: CONTRACT_STATES.CREATED,
      to: CONTRACT_STATES.ACTIVE,
      reason: "Contract activated, FX monitoring started",
      timestamp: new Date().toISOString()
    });
    contract.updatedAt = new Date().toISOString();
    
    this.activeContracts.set(contract.id, contract);
    
    // Start global monitor if not running
    if (!this.monitorInterval) {
      this._startMonitor();
    }
    
    logger.info("TimeLock activated", {
      contractId: contract.id,
      monitoring: `${contract.sendCurrency}/${contract.receiveCurrency}`
    });
    
    return contract;
  }
  
  /**
   * Check a contract against current FX rate
   * Called by the monitor loop
   */
  async checkContract(contract) {
    if (contract.state !== CONTRACT_STATES.ACTIVE) return null;
    
    // Check expiry first
    if (new Date(contract.expiresAt) <= new Date()) {
      return this._expireContract(contract);
    }
    
    // Get current rate
    const currentRate = await this.fx.getRate(
      contract.sendCurrency,
      contract.receiveCurrency,
      false
    );
    
    const rate = currentRate.rate;
    
    // Update tracking
    contract.bestRateSeen = Math.max(contract.bestRateSeen, rate);
    contract.worstRateSeen = Math.min(contract.worstRateSeen, rate);
    contract.rateSnapshots.push({
      rate,
      timestamp: new Date().toISOString(),
      source: currentRate.source
    });
    
    // Keep only last 1000 snapshots (memory management)
    if (contract.rateSnapshots.length > 1000) {
      // Keep first, last, and evenly sampled middle points
      const sampled = [contract.rateSnapshots[0]];
      const step = Math.floor(contract.rateSnapshots.length / 100);
      for (let i = step; i < contract.rateSnapshots.length - 1; i += step) {
        sampled.push(contract.rateSnapshots[i]);
      }
      sampled.push(contract.rateSnapshots[contract.rateSnapshots.length - 1]);
      contract.rateSnapshots = sampled;
    }
    
    // Check break-even
    const breakEvenHit = this._isBreakEvenReached(contract, rate);
    
    if (breakEvenHit) {
      return this._executeContract(contract, rate);
    }
    
    contract.updatedAt = new Date().toISOString();
    return { action: "MONITORING", currentRate: rate, contract };
  }
  
  /**
   * User cancels the contract
   */
  async cancelContract(contract, revertToTier) {
    if (![CONTRACT_STATES.CREATED, CONTRACT_STATES.ACTIVE].includes(contract.state)) {
      throw new Error(`Cannot cancel contract in state: ${contract.state}`);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // FIX 1: Enforce 48-hour minimum lock-in period
    // Cannot cancel until lockInExpiresAt has passed
    // ═══════════════════════════════════════════════════════════════
    if (contract.lockInExpiresAt) {
      const lockInExpiry = new Date(contract.lockInExpiresAt);
      if (lockInExpiry > new Date()) {
        const remainingMs = lockInExpiry.getTime() - Date.now();
        const remainingHours = Math.ceil(remainingMs / 3600000);
        throw new Error(
          `Cannot cancel: contract is in lock-in period. ` +
          `Cancellation available in ${remainingHours} hour(s) ` +
          `(after ${contract.lockInExpiresAt}). ` +
          `This protects against free optionality exploitation.`
        );
      }
    }
    
    const tier = revertToTier || contract.fallbackTier;
    
    contract.state = CONTRACT_STATES.CANCELLED;
    contract.stateHistory.push({
      from: contract.state,
      to: CONTRACT_STATES.CANCELLED,
      reason: `User cancelled after lock-in period, reverting to ${tier}`,
      timestamp: new Date().toISOString()
    });
    contract.updatedAt = new Date().toISOString();
    
    this.activeContracts.delete(contract.id);
    
    // ═══════════════════════════════════════════════════════════════
    // FIX 3: Contract fee is NOT refunded on cancellation
    // The 1.2% + $1 contract fee was charged at creation.
    // Cancelling forfeits this fee. This is by design.
    // ═══════════════════════════════════════════════════════════════
    const contractFeeForfeited = contract.contractFee 
      ? contract.contractFee.total 
      : 0;
    
    logger.info("TimeLock cancelled", {
      contractId: contract.id,
      revertTo: tier,
      contractFeeForfeited,
      rateAtCancellation: contract.rateSnapshots[contract.rateSnapshots.length - 1]?.rate
    });
    
    return {
      action: "CANCELLED",
      revertToTier: tier,
      contract,
      feeCharged: tier === "INSTANT"
        ? { amount: contract.feeAmountIfCharged, deductedFrom: "USER_ADDITIONAL" }
        : { amount: contract.feeAmountIfCharged, deductedFrom: "TRANSFER_AMOUNT" },
      contractFeeForfeited: {
        amount: contractFeeForfeited,
        refunded: false,
        reason: "Non-refundable contract creation fee"
      }
    };
  }
  
  /**
   * Get contract status with real-time data
   */
  async getContractStatus(contract) {
    let currentRate = null;
    let timeRemainingMs = null;
    let progressToBreakEven = null;
    
    if (contract.state === CONTRACT_STATES.ACTIVE) {
      const rateInfo = await this.fx.getRate(
        contract.sendCurrency,
        contract.receiveCurrency,
        false
      );
      currentRate = rateInfo.rate;
      
      timeRemainingMs = new Date(contract.expiresAt).getTime() - Date.now();
      
      // How close are we to break-even?
      const totalMovementNeeded = Math.abs(contract.breakEvenRate - contract.entryRate);
      const currentMovement = Math.abs(currentRate - contract.entryRate);
      progressToBreakEven = totalMovementNeeded > 0
        ? Math.min(100, Math.round(currentMovement / totalMovementNeeded * 100))
        : 0;
    }
    
    return {
      contractId: contract.id,
      state: contract.state,
      pair: `${contract.sendCurrency}/${contract.receiveCurrency}`,
      principal: contract.principal,
      
      rates: {
        entry: contract.entryRate,
        breakEven: contract.breakEvenRate,
        current: currentRate,
        best: contract.bestRateSeen,
        worst: contract.worstRateSeen
      },
      
      progress: {
        toBreakEven: progressToBreakEven,
        timeRemainingMs,
        timeRemainingHuman: timeRemainingMs
          ? this._humanDuration(timeRemainingMs)
          : null,
        rateMovementNeeded: contract.rateMovementRequired
      },
      
      outcome: contract.state === CONTRACT_STATES.EXECUTED
        ? {
            executionRate: contract.executionRate,
            savings: contract.executionSavings,
            feePaid: 0
          }
        : null,
      
      snapshotCount: contract.rateSnapshots.length,
      createdAt: contract.createdAt,
      expiresAt: contract.expiresAt
    };
  }
  
  // ========== INTERNAL METHODS ==========
  
  /**
   * Calculate the break-even FX rate
   * 
   * The break-even is the rate at which the FX gain equals the fee.
   * 
   * If sending USD to SGD:
   *   - Current rate: 1 USD = 1.27 SGD
   *   - Fee: $0.24 USD
   *   - We need the SGD to weaken (rate goes up) so $20 buys MORE SGD
   *   - At break-even: $20 at new rate - $20 at old rate >= $0.24 worth of SGD
   */
  _calculateBreakEvenRate(amount, feeAmount, sendCurrency, receiveCurrency, spotRate) {
    // Fee in receive currency terms
    const feeInReceiveCurrency = feeAmount * spotRate;
    
    // Break-even rate: we need the receive currency amount at new rate
    // to exceed the amount at spot rate by the fee amount
    // amount * breakEvenRate = amount * spotRate + feeInReceiveCurrency
    // breakEvenRate = spotRate + (feeInReceiveCurrency / amount)
    const breakEvenRate = spotRate + (feeInReceiveCurrency / amount);
    
    const movementPercent = Math.round(
      Math.abs(breakEvenRate - spotRate) / spotRate * 10000
    ) / 100;
    
    // Direction: does the receive currency need to weaken or strengthen?
    const direction = breakEvenRate > spotRate ? "RECEIVE_WEAKENS" : "RECEIVE_STRENGTHENS";
    
    return {
      rate: Math.round(breakEvenRate * 1000000) / 1000000,
      movementPercent,
      direction,
      spotRate,
      feeInReceiveCurrency: Math.round(feeInReceiveCurrency * 100) / 100
    };
  }
  
  /**
   * Check if break-even rate has been reached
   */
  _isBreakEvenReached(contract, currentRate) {
    // Break-even is always above entry rate in our model
    // (receive currency weakens = rate number goes up = sender gets more)
    return currentRate >= contract.breakEvenRate;
  }
  
  /**
   * Execute the contract at the favorable rate
   */
  _executeContract(contract, executionRate) {
    contract.state = CONTRACT_STATES.EXECUTING;
    contract.executionRate = executionRate;
    
    // Calculate actual savings
    const receiveAtSpot = contract.principal * contract.entryRate;
    const receiveAtExecution = contract.principal * executionRate;
    const fxGain = receiveAtExecution - receiveAtSpot;
    
    contract.executionSavings = {
      fxGain: Math.round(fxGain * 100) / 100,
      feeThatWouldHaveBeenCharged: contract.feeAmountIfCharged,
      netSavingsForUser: Math.round((fxGain - contract.feeAmountIfCharged * contract.entryRate) * 100) / 100,
      receiveCurrency: contract.receiveCurrency
    };
    
    contract.state = CONTRACT_STATES.EXECUTED;
    contract.stateHistory.push({
      from: CONTRACT_STATES.ACTIVE,
      to: CONTRACT_STATES.EXECUTED,
      reason: `Break-even reached. Execution rate: ${executionRate}, FX gain: ${fxGain.toFixed(2)} ${contract.receiveCurrency}`,
      timestamp: new Date().toISOString()
    });
    contract.updatedAt = new Date().toISOString();
    
    this.activeContracts.delete(contract.id);
    
    logger.info("TimeLock EXECUTED", {
      contractId: contract.id,
      executionRate,
      entryRate: contract.entryRate,
      fxGain,
      userSavedFee: contract.feeAmountIfCharged
    });
    
    return {
      action: "EXECUTED",
      contract,
      savings: contract.executionSavings
    };
  }
  
  /**
   * Expire the contract and trigger fallback
   */
  _expireContract(contract) {
    contract.state = CONTRACT_STATES.EXPIRED;
    contract.stateHistory.push({
      from: CONTRACT_STATES.ACTIVE,
      to: CONTRACT_STATES.EXPIRED,
      reason: `Contract expired after ${contract.maxDurationHours} hours. Falling back to ${contract.fallbackTier}`,
      timestamp: new Date().toISOString()
    });
    contract.updatedAt = new Date().toISOString();
    
    this.activeContracts.delete(contract.id);
    
    logger.info("TimeLock EXPIRED", {
      contractId: contract.id,
      fallback: contract.fallbackTier,
      lastRate: contract.rateSnapshots[contract.rateSnapshots.length - 1]?.rate
    });
    
    return {
      action: "EXPIRED",
      revertToTier: contract.fallbackTier,
      contract,
      feeCharged: contract.fallbackTier === "INSTANT"
        ? { amount: contract.feeAmountIfCharged, deductedFrom: "USER_ADDITIONAL" }
        : { amount: contract.feeAmountIfCharged, deductedFrom: "TRANSFER_AMOUNT" }
    };
  }
  
  /**
   * Estimate theoretical value of the contract as a derivative
   * Simplified Black-Scholes-ish estimate for the binary option
   */
  _estimateContractValue(amount, breakEven, durationHours) {
    // Very simplified probability estimate
    // Real implementation would use implied volatility from FX options market
    const annualVolatility = 0.08; // ~8% annual vol for major pairs
    const timeInYears = durationHours / 8760;
    const movementNeeded = breakEven.movementPercent / 100;
    
    // Probability of reaching break-even (simplified normal distribution)
    const expectedMove = annualVolatility * Math.sqrt(timeInYears);
    const zScore = movementNeeded / expectedMove;
    
    // Approximate P(reaching break-even) using normal CDF approximation
    const probability = 1 - this._normalCDF(zScore);
    
    return {
      estimatedProbability: Math.round(probability * 100) / 100,
      theoreticalValue: Math.round(amount * (this.feeBps / 10000) * probability * 100) / 100,
      impliedVolatility: annualVolatility,
      timeValue: Math.round(expectedMove * 10000) / 100, // As percentage
      note: "Simplified estimate. Production would use market-implied volatility."
    };
  }
  
  /**
   * Normal CDF approximation (Abramowitz & Stegun)
   */
  _normalCDF(x) {
    const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741;
    const a4 = -1.453152027, a5 = 1.061405429, p = 0.3275911;
    const sign = x < 0 ? -1 : 1;
    x = Math.abs(x) / Math.sqrt(2);
    const t = 1.0 / (1.0 + p * x);
    const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
    return 0.5 * (1.0 + sign * y);
  }
  
  _humanDuration(ms) {
    const hours = Math.floor(ms / 3600000);
    const minutes = Math.floor((ms % 3600000) / 60000);
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  }
  
  /**
   * Start the FX monitoring loop
   */
  // ═══════════════════════════════════════════════════════════════════
  // FIX 2: Per-Customer Daily Contract Limits + Trust Tiers
  // ═══════════════════════════════════════════════════════════════════
  
  /**
   * Set a customer's trust tier (called by admin or automated trust scoring)
   */
  setCustomerTrustTier(customerId, tier) {
    if (!TRUST_TIERS[tier]) {
      throw new Error(`Invalid trust tier: ${tier}. Valid: ${Object.keys(TRUST_TIERS).join(", ")}`);
    }
    this.customerTrustTiers.set(customerId, tier);
    logger.info("Customer trust tier updated", { customerId, tier, label: TRUST_TIERS[tier].label });
  }
  
  _getCustomerTier(customerId) {
    return this.customerTrustTiers.get(customerId) || DEFAULT_TRUST_TIER;
  }
  
  /**
   * Check if customer has remaining daily contract allowance
   */
  _checkDailyContractLimit(customerId) {
    const tier = this._getCustomerTier(customerId);
    const tierConfig = TRUST_TIERS[tier];
    
    // Get today's contracts
    const log = this.customerContractLog.get(customerId) || [];
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    
    const todayContracts = log.filter(entry => 
      new Date(entry.createdAt) >= todayStart
    );
    
    const allowed = todayContracts.length < tierConfig.maxDailyContracts;
    
    // Calculate next available time
    let nextAvailable = null;
    if (!allowed) {
      const tomorrow = new Date(todayStart);
      tomorrow.setDate(tomorrow.getDate() + 1);
      nextAvailable = tomorrow.toISOString();
    }
    
    return {
      allowed,
      tier,
      maxDaily: tierConfig.maxDailyContracts,
      usedToday: todayContracts.length,
      nextAvailable
    };
  }
  
  /**
   * Record a contract creation against customer's daily limit
   */
  _recordContractCreation(customerId, contractId, corridor) {
    if (!this.customerContractLog.has(customerId)) {
      this.customerContractLog.set(customerId, []);
    }
    
    this.customerContractLog.get(customerId).push({
      contractId,
      corridor,
      createdAt: new Date().toISOString()
    });
    
    // Prune entries older than 7 days (keep some history)
    const cutoff = new Date(Date.now() - 7 * 24 * 3600000);
    const log = this.customerContractLog.get(customerId);
    this.customerContractLog.set(
      customerId,
      log.filter(entry => new Date(entry.createdAt) >= cutoff)
    );
  }
  
  /**
   * Get the sanitized client-facing view of a contract.
   * Strips all internal/derivative data. NEVER returns probability or sealed data.
   */
  getClientView(contract) {
    const view = { ...contract };
    
    // CRITICAL: Remove sealed derivative profile — never exposed to clients
    delete view._derivativeProfileSealed;
    delete view.derivativeProfile;
    
    return view;
  }
  
  /**
   * Access sealed derivative data (internal analytics only).
   * Requires encryption engine to decrypt.
   */
  getDerivativeProfile(contract) {
    if (!contract._derivativeProfileSealed) return null;
    
    if (this.encryptionEngine && typeof contract._derivativeProfileSealed === "string") {
      const decrypted = this.encryptionEngine.decrypt(contract._derivativeProfileSealed, "financial");
      return JSON.parse(decrypted);
    }
    
    // Dev/test fallback
    if (contract._derivativeProfileSealed._data) {
      return contract._derivativeProfileSealed._data;
    }
    
    return null;
  }
  
  _startMonitor() {
    this.monitorInterval = setInterval(async () => {
      for (const [id, contract] of this.activeContracts) {
        try {
          await this.checkContract(contract);
        } catch (err) {
          logger.error("Contract check failed", { contractId: id, error: err.message });
        }
      }
      
      // Stop monitor if no active contracts
      if (this.activeContracts.size === 0) {
        clearInterval(this.monitorInterval);
        this.monitorInterval = null;
      }
    }, FX_CHECK_INTERVAL_MS);
    
    logger.info("FX monitor started", {
      checkIntervalMs: FX_CHECK_INTERVAL_MS,
      activeContracts: this.activeContracts.size
    });
  }
  
  /**
   * Stop the monitor (for graceful shutdown)
   */
  stopMonitor() {
    if (this.monitorInterval) {
      clearInterval(this.monitorInterval);
      this.monitorInterval = null;
    }
  }
}

module.exports = { 
  TimeLockEngine, 
  CONTRACT_STATES, 
  DEFAULT_FEE_BPS,
  MIN_LOCK_IN_HOURS,
  TRUST_TIERS,
  CONTRACT_FEE_FLAT,
  CONTRACT_FEE_BPS
};
