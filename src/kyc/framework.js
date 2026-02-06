/**
 * KYC (Know Your Customer) Framework
 * 
 * Multi-tier identity verification with risk-based escalation.
 * 
 * Verification Tiers:
 *   TIER 1 - Basic:   Name + email + phone + country
 *                      Limit: €1,000/transaction, €5,000/month
 *   
 *   TIER 2 - Standard: + Government ID (passport/national ID) + address proof
 *                      Limit: €15,000/transaction, €50,000/month
 *   
 *   TIER 3 - Enhanced: + Source of funds documentation + face verification
 *                      Limit: €250,000/transaction, €1,000,000/month
 *   
 *   TIER 4 - Corporate: + Company registration + UBO (Ultimate Beneficial Owner)
 *                       + Financial statements
 *                       Limit: Custom (negotiated)
 * 
 * Risk Scoring:
 *   Each user receives a composite risk score (0-100) based on:
 *     - Country risk (FATF classification)
 *     - Transaction patterns (velocity, amounts, counterparties)
 *     - Sanctions proximity (degree of separation from sanctioned entities)
 *     - Document verification confidence
 *     - Historical flags
 *   
 *   Score thresholds:
 *     0-25:  LOW       → Standard processing
 *     26-50: MEDIUM    → Enhanced monitoring
 *     51-75: HIGH      → Manual review required
 *     76-100: CRITICAL → Block + SAR filing
 * 
 * Compliance:
 *   - EU 5AMLD / 6AMLD (Anti-Money Laundering Directives)
 *   - US Bank Secrecy Act (BSA) / FinCEN
 *   - FATF Recommendations 10-12 (Customer Due Diligence)
 *   - Singapore MAS Notice 626
 */

const crypto = require("crypto");
const logger = require("../utils/logger");
const { HIGH_RISK_JURISDICTIONS, MONITORED_JURISDICTIONS } = require("../core/enhanced-sanctions");

// Verification tier limits (in EUR equivalent)
const TIER_LIMITS = {
  TIER_1: { perTransaction: 1000, perMonth: 5000, perYear: 15000 },
  TIER_2: { perTransaction: 15000, perMonth: 50000, perYear: 250000 },
  TIER_3: { perTransaction: 250000, perMonth: 1000000, perYear: 5000000 },
  TIER_4: { perTransaction: null, perMonth: null, perYear: null } // Custom
};

// Document types accepted per tier
const REQUIRED_DOCUMENTS = {
  TIER_1: [], // No documents required
  TIER_2: ["GOVERNMENT_ID", "ADDRESS_PROOF"],
  TIER_3: ["GOVERNMENT_ID", "ADDRESS_PROOF", "SOURCE_OF_FUNDS", "SELFIE_WITH_ID"],
  TIER_4: ["COMPANY_REGISTRATION", "UBO_DECLARATION", "FINANCIAL_STATEMENTS", "BOARD_RESOLUTION"]
};

// Government ID types
const ID_TYPES = {
  PASSPORT: {
    format: /^[A-Z0-9]{6,12}$/,
    expiryRequired: true,
    mrzRequired: true
  },
  NATIONAL_ID: {
    format: /^[A-Z0-9]{6,20}$/,
    expiryRequired: true,
    mrzRequired: false
  },
  DRIVERS_LICENSE: {
    format: /^[A-Z0-9]{4,20}$/,
    expiryRequired: true,
    mrzRequired: false
  },
  RESIDENCE_PERMIT: {
    format: /^[A-Z0-9]{6,15}$/,
    expiryRequired: true,
    mrzRequired: false
  }
};

class KYCFramework {
  constructor({ encryption, db, sanctionsScreener }) {
    this.encryption = encryption;
    this.db = db;
    this.sanctions = sanctionsScreener;
  }
  
  /**
   * Onboard a new customer
   * Creates a KYC profile and starts verification at the requested tier
   */
  async onboardCustomer(customerData) {
    const customerId = crypto.randomUUID();
    
    // Validate required fields
    const errors = this._validateBasicFields(customerData);
    if (errors.length > 0) {
      return { success: false, errors, customerId: null };
    }
    
    // Initial sanctions screening
    const sanctionsResult = this.sanctions.screen(
      `${customerData.firstName} ${customerData.lastName}`,
      { country: customerData.country }
    );
    
    // Calculate initial risk score
    const riskScore = this._calculateRiskScore({
      country: customerData.country,
      sanctionsResult,
      transactionHistory: [],
      documentVerification: null
    });
    
    // Encrypt PII before storage
    const encryptedProfile = {
      id: customerId,
      
      // Encrypted fields
      firstName: this.encryption.encrypt(customerData.firstName, "pii", customerId),
      lastName: this.encryption.encrypt(customerData.lastName, "pii", customerId),
      email: this.encryption.encrypt(customerData.email, "pii", customerId),
      phone: this.encryption.encrypt(customerData.phone, "pii", customerId),
      dateOfBirth: customerData.dateOfBirth
        ? this.encryption.encrypt(customerData.dateOfBirth, "pii", customerId)
        : null,
      
      // Searchable hashes (for lookup without decryption)
      emailHash: this.encryption.hash(customerData.email.toLowerCase(), "email"),
      phoneHash: this.encryption.hash(customerData.phone, "phone"),
      nameHash: this.encryption.hash(
        `${customerData.firstName} ${customerData.lastName}`.toUpperCase(),
        "name"
      ),
      
      // Plaintext (non-PII needed for queries)
      country: customerData.country,
      customerType: customerData.type || "INDIVIDUAL", // INDIVIDUAL or CORPORATE
      
      // Verification state
      kycTier: "TIER_1",
      kycStatus: "PENDING_VERIFICATION",
      documents: [],
      verificationHistory: [],
      
      // Risk
      riskScore: riskScore.score,
      riskLevel: riskScore.level,
      riskFactors: riskScore.factors,
      
      // Sanctions
      sanctionsScreenResult: sanctionsResult.clear ? "CLEAR" : "FLAGGED",
      lastSanctionsScreen: sanctionsResult.screenedAt,
      
      // Limits
      limits: TIER_LIMITS.TIER_1,
      
      // Activity tracking
      totalTransactionCount: 0,
      totalTransactionVolume: 0,
      monthlyTransactionVolume: 0,
      
      // Timestamps
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastActivityAt: null,
      nextReviewAt: this._nextReviewDate(riskScore.level)
    };
    
    // Block if sanctions flagged
    if (!sanctionsResult.clear) {
      encryptedProfile.kycStatus = "BLOCKED_SANCTIONS";
      
      logger.warn("Customer blocked: sanctions match", {
        customerId,
        matchCount: sanctionsResult.matches.length
      });
      
      return {
        success: false,
        customerId,
        status: "BLOCKED_SANCTIONS",
        reason: "Name match found in sanctions database. Manual review required."
      };
    }
    
    logger.info("Customer onboarded", {
      customerId,
      tier: "TIER_1",
      riskLevel: riskScore.level,
      country: customerData.country
    });
    
    return {
      success: true,
      customerId,
      profile: encryptedProfile,
      tier: "TIER_1",
      limits: TIER_LIMITS.TIER_1,
      riskLevel: riskScore.level,
      requiredDocuments: REQUIRED_DOCUMENTS.TIER_2,
      message: "Basic verification complete. Submit documents for higher transaction limits."
    };
  }
  
  /**
   * Submit verification document for tier upgrade
   */
  async submitDocument(customerId, document) {
    const validationResult = this._validateDocument(document);
    
    if (!validationResult.valid) {
      return {
        success: false,
        errors: validationResult.errors
      };
    }
    
    // Encrypt document data
    const encryptedDoc = {
      id: crypto.randomUUID(),
      type: document.type,
      idType: document.idType || null,
      
      // Encrypted content
      documentNumber: document.number
        ? this.encryption.encrypt(document.number, "documents", customerId)
        : null,
      issuingCountry: document.issuingCountry,
      expiryDate: document.expiryDate,
      
      // Verification
      status: "PENDING_REVIEW",
      verifiedAt: null,
      verifiedBy: null,
      rejectionReason: null,
      
      // Automated checks
      formatValid: validationResult.formatValid,
      expiryValid: validationResult.expiryValid,
      
      submittedAt: new Date().toISOString()
    };
    
    logger.info("Document submitted for verification", {
      customerId,
      documentType: document.type,
      idType: document.idType
    });
    
    return {
      success: true,
      documentId: encryptedDoc.id,
      status: "PENDING_REVIEW",
      document: encryptedDoc
    };
  }
  
  /**
   * Upgrade KYC tier after document verification
   */
  async upgradeTier(customerId, targetTier, verifiedDocuments) {
    const required = REQUIRED_DOCUMENTS[targetTier];
    if (!required) {
      return { success: false, error: `Invalid tier: ${targetTier}` };
    }
    
    // Check all required documents are verified
    const verifiedTypes = new Set(verifiedDocuments.map(d => d.type));
    const missing = required.filter(r => !verifiedTypes.has(r));
    
    if (missing.length > 0) {
      return {
        success: false,
        error: "Missing required documents",
        missing,
        provided: [...verifiedTypes]
      };
    }
    
    const newLimits = TIER_LIMITS[targetTier];
    
    logger.info("KYC tier upgraded", {
      customerId,
      newTier: targetTier,
      limits: newLimits
    });
    
    return {
      success: true,
      customerId,
      newTier: targetTier,
      limits: newLimits,
      verifiedDocuments: verifiedDocuments.length
    };
  }
  
  /**
   * Check if a transaction is within the customer's KYC limits
   */
  checkTransactionLimits(customer, transactionAmountEUR) {
    const limits = TIER_LIMITS[customer.kycTier];
    if (!limits) return { allowed: false, reason: "Invalid KYC tier" };
    
    const violations = [];
    
    // Per-transaction limit
    if (limits.perTransaction && transactionAmountEUR > limits.perTransaction) {
      violations.push({
        type: "PER_TRANSACTION",
        limit: limits.perTransaction,
        attempted: transactionAmountEUR,
        requiredTier: this._tierForAmount(transactionAmountEUR)
      });
    }
    
    // Monthly limit
    if (limits.perMonth && (customer.monthlyTransactionVolume + transactionAmountEUR) > limits.perMonth) {
      violations.push({
        type: "MONTHLY_VOLUME",
        limit: limits.perMonth,
        current: customer.monthlyTransactionVolume,
        attempted: transactionAmountEUR,
        requiredTier: this._tierForMonthly(customer.monthlyTransactionVolume + transactionAmountEUR)
      });
    }
    
    if (violations.length > 0) {
      return {
        allowed: false,
        violations,
        suggestion: `Upgrade to ${violations[0].requiredTier} for higher limits`
      };
    }
    
    return { allowed: true, remainingPerTransaction: limits.perTransaction ? limits.perTransaction - transactionAmountEUR : null };
  }
  
  /**
   * Calculate composite risk score (0-100)
   */
  _calculateRiskScore({ country, sanctionsResult, transactionHistory, documentVerification }) {
    let score = 0;
    const factors = [];
    
    // Country risk (0-30 points)
    if (HIGH_RISK_JURISDICTIONS.has(country)) {
      score += 30;
      factors.push({ factor: "HIGH_RISK_JURISDICTION", points: 30, detail: country });
    } else if (MONITORED_JURISDICTIONS.has(country)) {
      score += 15;
      factors.push({ factor: "MONITORED_JURISDICTION", points: 15, detail: country });
    }
    
    // Sanctions proximity (0-40 points)
    if (sanctionsResult && !sanctionsResult.clear) {
      const maxConf = Math.max(...sanctionsResult.matches.map(m => m.confidence));
      const sanctionPoints = Math.round(maxConf * 40);
      score += sanctionPoints;
      factors.push({ factor: "SANCTIONS_PROXIMITY", points: sanctionPoints, detail: `${maxConf} confidence` });
    }
    
    // Transaction velocity (0-15 points)
    if (transactionHistory && transactionHistory.length > 0) {
      const last24h = transactionHistory.filter(t => {
        const age = Date.now() - new Date(t.createdAt).getTime();
        return age < 86400000;
      });
      
      if (last24h.length > 10) {
        score += 15;
        factors.push({ factor: "HIGH_VELOCITY", points: 15, detail: `${last24h.length} txns in 24h` });
      } else if (last24h.length > 5) {
        score += 7;
        factors.push({ factor: "ELEVATED_VELOCITY", points: 7, detail: `${last24h.length} txns in 24h` });
      }
    }
    
    // Document verification (0 to -15 points, reduces risk)
    if (documentVerification && documentVerification.verified) {
      score = Math.max(0, score - 15);
      factors.push({ factor: "VERIFIED_IDENTITY", points: -15, detail: "Documents verified" });
    }
    
    score = Math.min(100, Math.max(0, score));
    
    let level;
    if (score <= 25) level = "LOW";
    else if (score <= 50) level = "MEDIUM";
    else if (score <= 75) level = "HIGH";
    else level = "CRITICAL";
    
    return { score, level, factors };
  }
  
  _validateBasicFields(data) {
    const errors = [];
    if (!data.firstName || data.firstName.trim().length < 1) errors.push("First name is required");
    if (!data.lastName || data.lastName.trim().length < 1) errors.push("Last name is required");
    if (!data.email || !data.email.includes("@")) errors.push("Valid email is required");
    if (!data.phone) errors.push("Phone number is required");
    if (!data.country || data.country.length !== 2) errors.push("Valid 2-letter country code is required");
    return errors;
  }
  
  _validateDocument(doc) {
    const errors = [];
    let formatValid = true;
    let expiryValid = true;
    
    if (!doc.type) errors.push("Document type is required");
    
    if (doc.type === "GOVERNMENT_ID") {
      if (!doc.idType || !ID_TYPES[doc.idType]) {
        errors.push(`Invalid ID type. Must be one of: ${Object.keys(ID_TYPES).join(", ")}`);
      } else {
        const idSpec = ID_TYPES[doc.idType];
        
        if (doc.number && !idSpec.format.test(doc.number.replace(/[\s-]/g, "").toUpperCase())) {
          formatValid = false;
          errors.push(`Invalid ${doc.idType} number format`);
        }
        
        if (idSpec.expiryRequired) {
          if (!doc.expiryDate) {
            errors.push("Expiry date is required for this document type");
          } else if (new Date(doc.expiryDate) < new Date()) {
            expiryValid = false;
            errors.push("Document has expired");
          }
        }
      }
    }
    
    return { valid: errors.length === 0, errors, formatValid, expiryValid };
  }
  
  _tierForAmount(amount) {
    if (amount <= TIER_LIMITS.TIER_1.perTransaction) return "TIER_1";
    if (amount <= TIER_LIMITS.TIER_2.perTransaction) return "TIER_2";
    if (amount <= TIER_LIMITS.TIER_3.perTransaction) return "TIER_3";
    return "TIER_4";
  }
  
  _tierForMonthly(monthly) {
    if (monthly <= TIER_LIMITS.TIER_1.perMonth) return "TIER_1";
    if (monthly <= TIER_LIMITS.TIER_2.perMonth) return "TIER_2";
    if (monthly <= TIER_LIMITS.TIER_3.perMonth) return "TIER_3";
    return "TIER_4";
  }
  
  _nextReviewDate(riskLevel) {
    const intervals = {
      LOW: 365,      // Annual
      MEDIUM: 180,   // Semi-annual
      HIGH: 90,      // Quarterly
      CRITICAL: 30   // Monthly
    };
    const days = intervals[riskLevel] || 365;
    return new Date(Date.now() + days * 86400000).toISOString();
  }
}

module.exports = { KYCFramework, TIER_LIMITS, REQUIRED_DOCUMENTS, ID_TYPES };
