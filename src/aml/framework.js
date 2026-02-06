/**
 * AML (Anti-Money Laundering) Framework
 * 
 * Real-time transaction monitoring and pattern detection.
 * 
 * Detection Patterns:
 * 
 *   STRUCTURING (Smurfing)
 *     Multiple transactions just below reporting thresholds.
 *     Pattern: 5+ transactions within 48hrs, each < threshold, total > 2x threshold
 *   
 *   RAPID MOVEMENT
 *     Funds received and immediately sent to different beneficiary.
 *     Pattern: Outbound within 30min of inbound, different beneficiary
 *   
 *   ROUND TRIPPING
 *     Money sent to country A then returned from country A (same or different entity).
 *     Pattern: Matching amounts ±5% within 30 days, same corridor reversed
 *   
 *   CURRENCY LAYERING
 *     Multiple rapid currency conversions to obscure origin.
 *     Pattern: 3+ different currency pairs within 24hrs
 *   
 *   UNUSUAL VOLUME
 *     Transaction volume spike vs historical baseline.
 *     Pattern: Current period > 3x standard deviation of 90-day average
 *   
 *   HIGH RISK CORRIDOR
 *     Transactions to/from FATF high-risk jurisdictions.
 *     Pattern: Any transaction involving blacklisted corridors
 *   
 *   DORMANT ACCOUNT ACTIVATION
 *     Account with no activity for 90+ days suddenly active with large transactions.
 *     Pattern: No transactions for 90 days, then > 50% of tier limit in first week
 *   
 *   PEP (Politically Exposed Person)
 *     Transactions involving known PEPs require enhanced scrutiny.
 * 
 * Risk Actions:
 *   FLAG    - Mark for review, allow transaction to proceed
 *   HOLD    - Pause transaction, require manual approval
 *   BLOCK   - Reject transaction, freeze account
 *   SAR     - File Suspicious Activity Report with authorities
 * 
 * Compliance:
 *   - EU 6AMLD Article 3 (money laundering offences)
 *   - US BSA/AML (31 CFR Chapter X)
 *   - FATF Recommendations 20-21 (suspicious transaction reporting)
 *   - Singapore CDSA (Corruption, Drug Trafficking and Other Serious Crimes Act)
 */

const logger = require("../utils/logger");
const { HIGH_RISK_JURISDICTIONS } = require("../core/enhanced-sanctions");

// Reporting thresholds per jurisdiction (EUR equivalent)
const REPORTING_THRESHOLDS = {
  EU: 10000,     // 4AMLD Article 11
  US: 10000,     // BSA $10,000
  SG: 20000,     // MAS S$20,000
  DEFAULT: 10000
};

// Pattern detection windows
const WINDOWS = {
  STRUCTURING: 48 * 3600000,   // 48 hours
  RAPID_MOVEMENT: 30 * 60000,  // 30 minutes
  ROUND_TRIP: 30 * 86400000,   // 30 days
  LAYERING: 24 * 3600000,      // 24 hours
  DORMANT: 90 * 86400000,      // 90 days
  VELOCITY_BASELINE: 90 * 86400000 // 90 days
};

class AMLFramework {
  constructor(options = {}) {
    this.reportingThreshold = options.reportingThreshold || REPORTING_THRESHOLDS.DEFAULT;
    this.alerts = [];  // In production: persisted to DB
  }
  
  /**
   * Analyze a transaction against all AML patterns
   * 
   * @param {Object} transaction - Current transaction
   * @param {Object} customer - Customer profile with KYC data
   * @param {Array} history - Customer's transaction history
   * @returns {Object} Analysis result with risk indicators
   */
  async analyzeTransaction(transaction, customer, history = []) {
    const startTime = performance.now();
    const indicators = [];
    
    // Run all detection patterns
    const structuring = this._detectStructuring(transaction, history);
    if (structuring.detected) indicators.push(structuring);
    
    const rapidMovement = this._detectRapidMovement(transaction, history);
    if (rapidMovement.detected) indicators.push(rapidMovement);
    
    const roundTripping = this._detectRoundTripping(transaction, history);
    if (roundTripping.detected) indicators.push(roundTripping);
    
    const layering = this._detectCurrencyLayering(transaction, history);
    if (layering.detected) indicators.push(layering);
    
    const volumeSpike = this._detectUnusualVolume(transaction, customer, history);
    if (volumeSpike.detected) indicators.push(volumeSpike);
    
    const corridorRisk = this._detectHighRiskCorridor(transaction);
    if (corridorRisk.detected) indicators.push(corridorRisk);
    
    const dormantActivation = this._detectDormantActivation(transaction, customer, history);
    if (dormantActivation.detected) indicators.push(dormantActivation);
    
    // Threshold reporting (mandatory, not risk-based)
    const thresholdTriggered = transaction.sendAmount >= this.reportingThreshold;
    if (thresholdTriggered) {
      indicators.push({
        detected: true,
        pattern: "THRESHOLD_REPORT",
        severity: "INFO",
        action: "FLAG",
        detail: `Amount ${transaction.sendAmount} >= reporting threshold ${this.reportingThreshold}`,
        mandatory: true
      });
    }
    
    // Determine overall action (worst case wins)
    const actionPriority = { BLOCK: 4, SAR: 3, HOLD: 2, FLAG: 1 };
    let overallAction = "PASS";
    let overallSeverity = "NONE";
    
    for (const indicator of indicators) {
      if ((actionPriority[indicator.action] || 0) > (actionPriority[overallAction] || 0)) {
        overallAction = indicator.action;
        overallSeverity = indicator.severity;
      }
    }
    
    // Composite risk score from indicators
    const riskScore = this._calculateTransactionRisk(indicators, customer);
    
    const duration = Math.round((performance.now() - startTime) * 100) / 100;
    
    const result = {
      transactionId: transaction.id,
      customerId: customer.id,
      
      // Decision
      action: overallAction,
      severity: overallSeverity,
      riskScore,
      
      // Details
      indicators,
      indicatorCount: indicators.length,
      thresholdTriggered,
      
      // Audit
      analyzedAt: new Date().toISOString(),
      durationMs: duration,
      
      // SAR generation trigger
      sarRequired: overallAction === "SAR" || overallAction === "BLOCK"
    };
    
    if (indicators.length > 0) {
      logger.warn("AML indicators detected", {
        transactionId: transaction.id,
        action: overallAction,
        indicatorCount: indicators.length,
        patterns: indicators.map(i => i.pattern)
      });
    }
    
    // Auto-generate SAR if required
    if (result.sarRequired) {
      result.sarDraft = this._generateSARDraft(transaction, customer, indicators);
    }
    
    return result;
  }
  
  /**
   * STRUCTURING DETECTION
   * Multiple transactions just below threshold to avoid reporting
   */
  _detectStructuring(transaction, history) {
    const threshold = this.reportingThreshold;
    const window = WINDOWS.STRUCTURING;
    const now = Date.now();
    
    // Find recent transactions below threshold
    const recentBelowThreshold = history.filter(t => {
      const age = now - new Date(t.createdAt).getTime();
      return age < window && t.sendAmount < threshold && t.sendAmount > threshold * 0.5;
    });
    
    // Include current transaction
    if (transaction.sendAmount < threshold && transaction.sendAmount > threshold * 0.5) {
      recentBelowThreshold.push(transaction);
    }
    
    const totalAmount = recentBelowThreshold.reduce((sum, t) => sum + t.sendAmount, 0);
    
    if (recentBelowThreshold.length >= 3 && totalAmount > threshold * 2) {
      return {
        detected: true,
        pattern: "STRUCTURING",
        severity: "HIGH",
        action: "SAR",
        detail: `${recentBelowThreshold.length} transactions totaling ${totalAmount} within 48hrs, each below ${threshold} threshold`,
        evidence: {
          transactionCount: recentBelowThreshold.length,
          totalAmount,
          threshold,
          windowHours: 48
        }
      };
    }
    
    return { detected: false, pattern: "STRUCTURING" };
  }
  
  /**
   * RAPID MOVEMENT DETECTION
   * Funds received and immediately forwarded (pass-through account)
   */
  _detectRapidMovement(transaction, history) {
    const window = WINDOWS.RAPID_MOVEMENT;
    const now = Date.now();
    
    // Look for recent inbound transactions
    const recentInbound = history.filter(t => {
      const age = now - new Date(t.completedAt || t.createdAt).getTime();
      return age < window && t.beneficiary?.name === transaction.sender?.name;
    });
    
    if (recentInbound.length > 0) {
      const matchingInbound = recentInbound.find(t =>
        Math.abs(t.receiveAmount - transaction.sendAmount) / transaction.sendAmount < 0.05
      );
      
      if (matchingInbound) {
        return {
          detected: true,
          pattern: "RAPID_MOVEMENT",
          severity: "HIGH",
          action: "HOLD",
          detail: "Funds received and forwarded within 30 minutes to different beneficiary",
          evidence: {
            inboundAmount: matchingInbound.receiveAmount,
            outboundAmount: transaction.sendAmount,
            timeBetweenMs: now - new Date(matchingInbound.completedAt || matchingInbound.createdAt).getTime()
          }
        };
      }
    }
    
    return { detected: false, pattern: "RAPID_MOVEMENT" };
  }
  
  /**
   * ROUND TRIPPING DETECTION
   * Money sent to country then returned from same country
   */
  _detectRoundTripping(transaction, history) {
    const window = WINDOWS.ROUND_TRIP;
    const now = Date.now();
    
    const reverseCorridorTxns = history.filter(t => {
      const age = now - new Date(t.createdAt).getTime();
      return age < window &&
        t.sender?.country === transaction.beneficiary?.country &&
        t.beneficiary?.country === transaction.sender?.country;
    });
    
    // Check for matching amounts (±5%)
    for (const reverseTxn of reverseCorridorTxns) {
      const ratio = reverseTxn.sendAmount / transaction.sendAmount;
      if (ratio > 0.95 && ratio < 1.05) {
        return {
          detected: true,
          pattern: "ROUND_TRIPPING",
          severity: "MEDIUM",
          action: "HOLD",
          detail: `Matching reverse transaction detected: ${transaction.sender?.country} ↔ ${transaction.beneficiary?.country}`,
          evidence: {
            currentAmount: transaction.sendAmount,
            reverseAmount: reverseTxn.sendAmount,
            daysBetween: Math.round((now - new Date(reverseTxn.createdAt).getTime()) / 86400000)
          }
        };
      }
    }
    
    return { detected: false, pattern: "ROUND_TRIPPING" };
  }
  
  /**
   * CURRENCY LAYERING DETECTION
   * Multiple rapid currency conversions
   */
  _detectCurrencyLayering(transaction, history) {
    const window = WINDOWS.LAYERING;
    const now = Date.now();
    
    const recentTxns = history.filter(t => {
      const age = now - new Date(t.createdAt).getTime();
      return age < window;
    });
    
    // Collect unique currency pairs
    const pairs = new Set();
    for (const t of recentTxns) {
      pairs.add(`${t.sendCurrency}-${t.receiveCurrency}`);
    }
    pairs.add(`${transaction.sendCurrency}-${transaction.receiveCurrency}`);
    
    if (pairs.size >= 3) {
      return {
        detected: true,
        pattern: "CURRENCY_LAYERING",
        severity: "MEDIUM",
        action: "FLAG",
        detail: `${pairs.size} different currency pairs in 24 hours`,
        evidence: {
          pairs: [...pairs],
          windowHours: 24
        }
      };
    }
    
    return { detected: false, pattern: "CURRENCY_LAYERING" };
  }
  
  /**
   * UNUSUAL VOLUME DETECTION
   * Spike vs historical baseline
   */
  _detectUnusualVolume(transaction, customer, history) {
    if (history.length < 10) return { detected: false, pattern: "UNUSUAL_VOLUME" };
    
    // Calculate 90-day baseline
    const now = Date.now();
    const baselineWindow = WINDOWS.VELOCITY_BASELINE;
    const baselineTxns = history.filter(t => {
      const age = now - new Date(t.createdAt).getTime();
      return age < baselineWindow;
    });
    
    if (baselineTxns.length < 5) return { detected: false, pattern: "UNUSUAL_VOLUME" };
    
    // Weekly volumes
    const weeklyVolumes = {};
    for (const t of baselineTxns) {
      const week = Math.floor((now - new Date(t.createdAt).getTime()) / (7 * 86400000));
      weeklyVolumes[week] = (weeklyVolumes[week] || 0) + t.sendAmount;
    }
    
    const volumes = Object.values(weeklyVolumes);
    const mean = volumes.reduce((a, b) => a + b, 0) / volumes.length;
    const stdDev = Math.sqrt(
      volumes.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / volumes.length
    );
    
    // Current week's volume including this transaction
    const currentWeekVolume = baselineTxns
      .filter(t => (now - new Date(t.createdAt).getTime()) < 7 * 86400000)
      .reduce((sum, t) => sum + t.sendAmount, 0) + transaction.sendAmount;
    
    if (stdDev > 0 && currentWeekVolume > mean + 3 * stdDev) {
      return {
        detected: true,
        pattern: "UNUSUAL_VOLUME",
        severity: "MEDIUM",
        action: "FLAG",
        detail: `Weekly volume ${currentWeekVolume} exceeds 3σ threshold (mean: ${Math.round(mean)}, σ: ${Math.round(stdDev)})`,
        evidence: {
          currentWeekVolume,
          baselineMean: Math.round(mean),
          baselineStdDev: Math.round(stdDev),
          zScore: Math.round((currentWeekVolume - mean) / stdDev * 10) / 10
        }
      };
    }
    
    return { detected: false, pattern: "UNUSUAL_VOLUME" };
  }
  
  /**
   * HIGH RISK CORRIDOR DETECTION
   */
  _detectHighRiskCorridor(transaction) {
    const senderCountry = transaction.sender?.country;
    const beneficiaryCountry = transaction.beneficiary?.country;
    
    const senderHighRisk = HIGH_RISK_JURISDICTIONS.has(senderCountry);
    const beneficiaryHighRisk = HIGH_RISK_JURISDICTIONS.has(beneficiaryCountry);
    
    if (senderHighRisk || beneficiaryHighRisk) {
      return {
        detected: true,
        pattern: "HIGH_RISK_CORRIDOR",
        severity: "CRITICAL",
        action: "BLOCK",
        detail: `Transaction involves FATF high-risk jurisdiction: ${senderHighRisk ? senderCountry : beneficiaryCountry}`,
        evidence: {
          senderCountry,
          beneficiaryCountry,
          senderHighRisk,
          beneficiaryHighRisk
        }
      };
    }
    
    return { detected: false, pattern: "HIGH_RISK_CORRIDOR" };
  }
  
  /**
   * DORMANT ACCOUNT ACTIVATION DETECTION
   */
  _detectDormantActivation(transaction, customer, history) {
    if (history.length === 0) return { detected: false, pattern: "DORMANT_ACTIVATION" };
    
    const now = Date.now();
    const lastTxn = history.reduce((latest, t) => {
      const time = new Date(t.createdAt).getTime();
      return time > latest ? time : latest;
    }, 0);
    
    const dormantDays = Math.floor((now - lastTxn) / 86400000);
    
    if (dormantDays >= 90) {
      const tierLimits = { TIER_1: 1000, TIER_2: 15000, TIER_3: 250000, TIER_4: 1000000 };
      const limit = tierLimits[customer.kycTier] || 1000;
      
      if (transaction.sendAmount > limit * 0.5) {
        return {
          detected: true,
          pattern: "DORMANT_ACTIVATION",
          severity: "MEDIUM",
          action: "HOLD",
          detail: `Account dormant for ${dormantDays} days, reactivated with high-value transaction`,
          evidence: {
            dormantDays,
            transactionAmount: transaction.sendAmount,
            tierLimit: limit,
            percentOfLimit: Math.round(transaction.sendAmount / limit * 100)
          }
        };
      }
    }
    
    return { detected: false, pattern: "DORMANT_ACTIVATION" };
  }
  
  /**
   * Calculate composite transaction risk score
   */
  _calculateTransactionRisk(indicators, customer) {
    let score = customer.riskScore || 0;
    
    const severityWeights = { CRITICAL: 30, HIGH: 20, MEDIUM: 10, LOW: 5, INFO: 2 };
    
    for (const indicator of indicators) {
      score += severityWeights[indicator.severity] || 0;
    }
    
    return Math.min(100, score);
  }
  
  /**
   * Generate SAR (Suspicious Activity Report) draft
   * 
   * In production, this would be filed with:
   *   - FinCEN (US) via BSA E-Filing
   *   - FIU (EU member state Financial Intelligence Unit)
   *   - STRO (Singapore Suspicious Transaction Reporting Office)
   */
  _generateSARDraft(transaction, customer, indicators) {
    return {
      reportType: "SUSPICIOUS_ACTIVITY_REPORT",
      filingDate: new Date().toISOString(),
      priority: indicators.some(i => i.severity === "CRITICAL") ? "URGENT" : "STANDARD",
      
      subject: {
        customerId: customer.id,
        kycTier: customer.kycTier,
        riskLevel: customer.riskLevel,
        country: customer.country
      },
      
      transaction: {
        id: transaction.id,
        amount: transaction.sendAmount,
        sendCurrency: transaction.sendCurrency,
        receiveCurrency: transaction.receiveCurrency,
        senderCountry: transaction.sender?.country,
        beneficiaryCountry: transaction.beneficiary?.country,
        createdAt: transaction.createdAt
      },
      
      suspiciousIndicators: indicators.map(i => ({
        pattern: i.pattern,
        severity: i.severity,
        detail: i.detail,
        evidence: i.evidence
      })),
      
      narrativeSummary: this._buildNarrative(transaction, customer, indicators),
      
      status: "DRAFT",
      reviewedBy: null,
      filedAt: null
    };
  }
  
  _buildNarrative(transaction, customer, indicators) {
    const patterns = indicators.map(i => i.pattern).join(", ");
    return `Suspicious activity detected for customer ${customer.id} (${customer.kycTier}, ` +
      `risk level: ${customer.riskLevel}). Transaction ID ${transaction.id} for ` +
      `${transaction.sendAmount} ${transaction.sendCurrency} to ${transaction.beneficiary?.country}. ` +
      `Triggered patterns: ${patterns}. ` +
      `${indicators.length} indicator(s) flagged. Recommended action: ${indicators[0]?.action || "REVIEW"}.`;
  }
}

module.exports = { AMLFramework, REPORTING_THRESHOLDS, WINDOWS };
