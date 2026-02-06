/**
 * Security Questions Module
 * 
 * ═══════════════════════════════════════════════════════════════════
 * OBELISK — Security Challenge System
 * ═══════════════════════════════════════════════════════════════════
 * 
 * Every customer must set up 9 security questions during account creation:
 *   - 7 preset questions (all required)
 *   - 2 custom questions (user-created)
 * 
 * Answers are normalized, hashed with per-answer salt (bcrypt-style),
 * and encrypted at rest via EncryptionEngine. Raw answers are NEVER stored.
 * 
 * Challenge triggers:
 *   - Password change: 3 random questions from the 9
 *   - TimeLock contract creation: 3 random questions from the 9
 *   - Account recovery: 5 random questions from the 9
 * 
 * Anti-enumeration:
 *   - All challenges use timing-safe comparison
 *   - Failed attempts are rate-limited per customer
 *   - After 5 consecutive failures: 15-minute lockout
 *   - After 10 total failures in 24h: account flagged for review
 */

const crypto = require("crypto");
const logger = require("../utils/logger");

// ═══════════════════════════════════════════════════════════════════
// PRESET QUESTIONS — All 7 required during account setup
// ═══════════════════════════════════════════════════════════════════

const PRESET_QUESTIONS = [
  { id: "SQ-001", text: "What was the name of the first street you remember living on?" },
  { id: "SQ-002", text: "What was the full name of a teacher who made a strong impression on you?" },
  { id: "SQ-003", text: "What was your closest childhood friend's name (first and last name)?" },
  { id: "SQ-004", text: "What city do your parents currently live in?" },
  { id: "SQ-005", text: "What was the model or color of your first vehicle?" },
  { id: "SQ-006", text: "What was the business name of your very first job?" },
  { id: "SQ-007", text: "What cuisine is your most favorite to eat — you could eat it every day?" }
];

const CUSTOM_QUESTION_SLOTS = 2; // SQ-C01, SQ-C02

// Challenge configurations
const CHALLENGE_CONFIGS = {
  PASSWORD_CHANGE:   { count: 3, label: "Password Change" },
  TIMELOCK_CREATE:   { count: 3, label: "TimeLock Contract Authorization" },
  ACCOUNT_RECOVERY:  { count: 5, label: "Account Recovery" }
};

// Rate limiting
const MAX_CONSECUTIVE_FAILURES = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
const MAX_DAILY_FAILURES = 10;
const DAILY_WINDOW_MS = 24 * 60 * 60 * 1000;

// Hashing
const HASH_ITERATIONS = 100000;
const HASH_KEY_LENGTH = 64;
const HASH_ALGORITHM = "sha512";
const SALT_LENGTH = 32;


class SecurityQuestions {
  /**
   * @param {Object} options
   * @param {Object} options.encryptionEngine - EncryptionEngine instance for at-rest encryption
   */
  constructor(options = {}) {
    this.encryptionEngine = options.encryptionEngine || null;
    
    // In-memory stores (production: PostgreSQL)
    this.customerQuestions = new Map();  // customerId → encrypted question set
    this.failureTracking = new Map();   // customerId → { consecutive, daily: [], lockedUntil }
    
    logger.info("Security questions module initialized", {
      presetQuestions: PRESET_QUESTIONS.length,
      customSlots: CUSTOM_QUESTION_SLOTS,
      totalRequired: PRESET_QUESTIONS.length + CUSTOM_QUESTION_SLOTS
    });
  }
  
  // ═══════════════════════════════════════════════════════════════════
  // ACCOUNT SETUP — Store all 9 answers during onboarding
  // ═══════════════════════════════════════════════════════════════════
  
  /**
   * Set up security questions for a customer.
   * Must provide answers to all 7 preset + 2 custom questions.
   * 
   * @param {string} customerId
   * @param {Object} params
   * @param {Object} params.presetAnswers - { "SQ-001": "answer", ... } all 7 required
   * @param {Array<Object>} params.customQuestions - [{ question: "...", answer: "..." }, ...]
   * @returns {Object} Setup confirmation
   */
  async setupQuestions(customerId, params) {
    if (!customerId) throw new Error("Customer ID is required");
    if (!params || !params.presetAnswers || !params.customQuestions) {
      throw new Error("Both preset answers and custom questions are required");
    }
    
    // Validate all 7 preset answers provided
    const missingPresets = PRESET_QUESTIONS.filter(q => !params.presetAnswers[q.id]);
    if (missingPresets.length > 0) {
      throw new Error(
        `Missing answers for preset questions: ${missingPresets.map(q => q.id).join(", ")}. All 7 are required.`
      );
    }
    
    // Validate 2 custom questions
    if (!Array.isArray(params.customQuestions) || params.customQuestions.length !== CUSTOM_QUESTION_SLOTS) {
      throw new Error(`Exactly ${CUSTOM_QUESTION_SLOTS} custom questions are required`);
    }
    
    for (const cq of params.customQuestions) {
      if (!cq.question || cq.question.trim().length < 10) {
        throw new Error("Custom questions must be at least 10 characters");
      }
      if (!cq.answer || cq.answer.trim().length < 2) {
        throw new Error("Custom question answers must be at least 2 characters");
      }
    }
    
    // Validate preset answers are meaningful
    for (const [qId, answer] of Object.entries(params.presetAnswers)) {
      if (!answer || answer.trim().length < 2) {
        throw new Error(`Answer for ${qId} must be at least 2 characters`);
      }
    }
    
    // Hash all answers with individual salts
    const questionSet = [];
    
    // Process 7 preset questions
    for (const pq of PRESET_QUESTIONS) {
      const rawAnswer = params.presetAnswers[pq.id];
      const hashed = await this._hashAnswer(rawAnswer);
      
      questionSet.push({
        id: pq.id,
        questionText: pq.text,
        answerHash: hashed.hash,
        answerSalt: hashed.salt,
        isCustom: false
      });
    }
    
    // Process 2 custom questions
    params.customQuestions.forEach((cq, index) => {
      const qId = `SQ-C0${index + 1}`;
      const hashed = this._hashAnswerSync(cq.answer);
      
      questionSet.push({
        id: qId,
        questionText: cq.question.trim(),
        answerHash: hashed.hash,
        answerSalt: hashed.salt,
        isCustom: true
      });
    });
    
    // Encrypt the entire question set at rest
    const stored = this._encryptQuestionSet(customerId, questionSet);
    this.customerQuestions.set(customerId, stored);
    
    // Initialize failure tracking
    this.failureTracking.set(customerId, {
      consecutive: 0,
      dailyFailures: [],
      lockedUntil: null
    });
    
    logger.info("Security questions configured", {
      customerId,
      presetCount: PRESET_QUESTIONS.length,
      customCount: CUSTOM_QUESTION_SLOTS,
      totalQuestions: questionSet.length
    });
    
    return {
      success: true,
      customerId,
      questionsConfigured: questionSet.length,
      questionIds: questionSet.map(q => q.id),
      configuredAt: new Date().toISOString()
    };
  }
  
  // ═══════════════════════════════════════════════════════════════════
  // CHALLENGE — Generate random questions for verification
  // ═══════════════════════════════════════════════════════════════════
  
  /**
   * Generate a security challenge (random subset of questions).
   * 
   * @param {string} customerId
   * @param {string} challengeType - "PASSWORD_CHANGE" | "TIMELOCK_CREATE" | "ACCOUNT_RECOVERY"
   * @returns {Object} Challenge with question IDs and texts (no answers!)
   */
  generateChallenge(customerId, challengeType) {
    if (!customerId) throw new Error("Customer ID is required");
    
    const config = CHALLENGE_CONFIGS[challengeType];
    if (!config) {
      throw new Error(`Invalid challenge type: ${challengeType}. Valid: ${Object.keys(CHALLENGE_CONFIGS).join(", ")}`);
    }
    
    // Check lockout
    const lockStatus = this._checkLockout(customerId);
    if (lockStatus.locked) {
      throw new Error(
        `Account security challenge locked. Too many failed attempts. ` +
        `Try again in ${Math.ceil(lockStatus.remainingMs / 60000)} minutes.`
      );
    }
    
    // Get stored questions
    const questionSet = this._decryptQuestionSet(customerId);
    if (!questionSet) {
      throw new Error("Security questions not configured for this customer");
    }
    
    // Select random questions
    const selected = this._selectRandom(questionSet, config.count);
    
    // Generate challenge token (binds this challenge to prevent replay)
    const challengeToken = crypto.randomBytes(32).toString("hex");
    const challengeExpiry = Date.now() + 5 * 60 * 1000; // 5 minutes to answer
    
    // Store pending challenge (in-memory, production: Redis with TTL)
    if (!this._pendingChallenges) this._pendingChallenges = new Map();
    this._pendingChallenges.set(challengeToken, {
      customerId,
      challengeType,
      questionIds: selected.map(q => q.id),
      expiresAt: challengeExpiry,
      createdAt: Date.now()
    });
    
    logger.info("Security challenge generated", {
      customerId,
      challengeType: config.label,
      questionCount: config.count,
      expiresInMs: 300000
    });
    
    return {
      challengeToken,
      challengeType,
      questions: selected.map(q => ({
        id: q.id,
        text: q.questionText
      })),
      expiresAt: new Date(challengeExpiry).toISOString(),
      attemptsRemaining: this._getRemainingAttempts(customerId)
    };
  }
  
  // ═══════════════════════════════════════════════════════════════════
  // VERIFY — Check answers against stored hashes
  // ═══════════════════════════════════════════════════════════════════
  
  /**
   * Verify answers to a security challenge.
   * 
   * @param {string} challengeToken - Token from generateChallenge
   * @param {Object} answers - { "SQ-001": "answer", "SQ-003": "answer", ... }
   * @returns {Object} Verification result
   */
  async verifyChallenge(challengeToken, answers) {
    if (!challengeToken) throw new Error("Challenge token is required");
    if (!answers || typeof answers !== "object") throw new Error("Answers object is required");
    
    // Retrieve pending challenge
    if (!this._pendingChallenges) this._pendingChallenges = new Map();
    const challenge = this._pendingChallenges.get(challengeToken);
    
    if (!challenge) {
      throw new Error("Invalid or expired challenge token");
    }
    
    // Check expiry
    if (Date.now() > challenge.expiresAt) {
      this._pendingChallenges.delete(challengeToken);
      throw new Error("Challenge has expired. Please request a new one.");
    }
    
    // Check lockout (could have been locked between challenge generation and verification)
    const lockStatus = this._checkLockout(challenge.customerId);
    if (lockStatus.locked) {
      this._pendingChallenges.delete(challengeToken);
      throw new Error(
        `Account locked due to too many failed attempts. ` +
        `Try again in ${Math.ceil(lockStatus.remainingMs / 60000)} minutes.`
      );
    }
    
    // Get stored questions
    const questionSet = this._decryptQuestionSet(challenge.customerId);
    
    // Verify each answer using timing-safe comparison
    let allCorrect = true;
    const results = [];
    
    for (const qId of challenge.questionIds) {
      const storedQ = questionSet.find(q => q.id === qId);
      const providedAnswer = answers[qId];
      
      if (!providedAnswer) {
        allCorrect = false;
        results.push({ id: qId, correct: false, reason: "missing" });
        continue;
      }
      
      const correct = this._verifyAnswer(providedAnswer, storedQ.answerHash, storedQ.answerSalt);
      if (!correct) allCorrect = false;
      results.push({ id: qId, correct });
    }
    
    // Consume the challenge token (one-time use)
    this._pendingChallenges.delete(challengeToken);
    
    // Update failure tracking
    if (allCorrect) {
      this._recordSuccess(challenge.customerId);
    } else {
      this._recordFailure(challenge.customerId);
    }
    
    const tracking = this.failureTracking.get(challenge.customerId);
    
    logger.info("Security challenge verified", {
      customerId: challenge.customerId,
      challengeType: challenge.challengeType,
      passed: allCorrect,
      correctCount: results.filter(r => r.correct).length,
      totalQuestions: results.length
    });
    
    return {
      verified: allCorrect,
      challengeType: challenge.challengeType,
      customerId: challenge.customerId,
      correctCount: results.filter(r => r.correct).length,
      totalQuestions: challenge.questionIds.length,
      // Don't tell them WHICH ones were wrong (anti-enumeration)
      attemptsRemaining: this._getRemainingAttempts(challenge.customerId),
      lockedOut: tracking.lockedUntil ? tracking.lockedUntil > Date.now() : false,
      verifiedAt: new Date().toISOString()
    };
  }
  
  // ═══════════════════════════════════════════════════════════════════
  // QUERY — Check if customer has questions configured
  // ═══════════════════════════════════════════════════════════════════
  
  hasQuestionsConfigured(customerId) {
    return this.customerQuestions.has(customerId);
  }
  
  getQuestionCount(customerId) {
    const qs = this._decryptQuestionSet(customerId);
    return qs ? qs.length : 0;
  }
  
  // ═══════════════════════════════════════════════════════════════════
  // INTERNAL — Hashing, encryption, rate limiting
  // ═══════════════════════════════════════════════════════════════════
  
  /**
   * Hash an answer with a random salt (async for bcrypt-level security)
   */
  async _hashAnswer(rawAnswer) {
    const normalized = this._normalizeAnswer(rawAnswer);
    const salt = crypto.randomBytes(SALT_LENGTH);
    
    const hash = await new Promise((resolve, reject) => {
      crypto.pbkdf2(normalized, salt, HASH_ITERATIONS, HASH_KEY_LENGTH, HASH_ALGORITHM, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      });
    });
    
    return {
      hash: hash.toString("base64"),
      salt: salt.toString("base64")
    };
  }
  
  /**
   * Synchronous hash (for setup — custom questions processed inline)
   */
  _hashAnswerSync(rawAnswer) {
    const normalized = this._normalizeAnswer(rawAnswer);
    const salt = crypto.randomBytes(SALT_LENGTH);
    const hash = crypto.pbkdf2Sync(normalized, salt, HASH_ITERATIONS, HASH_KEY_LENGTH, HASH_ALGORITHM);
    
    return {
      hash: hash.toString("base64"),
      salt: salt.toString("base64")
    };
  }
  
  /**
   * Verify an answer against stored hash using timing-safe comparison
   */
  _verifyAnswer(rawAnswer, storedHash, storedSalt) {
    const normalized = this._normalizeAnswer(rawAnswer);
    const salt = Buffer.from(storedSalt, "base64");
    const computed = crypto.pbkdf2Sync(normalized, salt, HASH_ITERATIONS, HASH_KEY_LENGTH, HASH_ALGORITHM);
    const stored = Buffer.from(storedHash, "base64");
    
    // Timing-safe comparison to prevent side-channel attacks
    if (computed.length !== stored.length) return false;
    return crypto.timingSafeEqual(computed, stored);
  }
  
  /**
   * Normalize answer for consistent hashing
   * - Lowercase
   * - Trim whitespace
   * - Collapse multiple spaces
   * - Remove leading/trailing punctuation
   */
  _normalizeAnswer(raw) {
    if (!raw || typeof raw !== "string") return "";
    return raw
      .toLowerCase()
      .trim()
      .replace(/\s+/g, " ")
      .replace(/^[.,!?;:'"]+|[.,!?;:'"]+$/g, "");
  }
  
  /**
   * Encrypt question set at rest
   */
  _encryptQuestionSet(customerId, questionSet) {
    if (this.encryptionEngine) {
      const serialized = JSON.stringify(questionSet);
      return {
        encrypted: true,
        data: this.encryptionEngine.encrypt(serialized, "pii"),
        customerId,
        storedAt: new Date().toISOString()
      };
    }
    
    // Fallback: store without encryption (dev/test only)
    return {
      encrypted: false,
      data: questionSet,
      customerId,
      storedAt: new Date().toISOString()
    };
  }
  
  /**
   * Decrypt question set
   */
  _decryptQuestionSet(customerId) {
    const stored = this.customerQuestions.get(customerId);
    if (!stored) return null;
    
    if (stored.encrypted && this.encryptionEngine) {
      const decrypted = this.encryptionEngine.decrypt(stored.data, "pii");
      return JSON.parse(decrypted);
    }
    
    return stored.data;
  }
  
  /**
   * Select N random questions from the set (cryptographically random)
   */
  _selectRandom(questionSet, count) {
    if (count >= questionSet.length) return [...questionSet];
    
    const indices = new Set();
    while (indices.size < count) {
      const idx = crypto.randomInt(0, questionSet.length);
      indices.add(idx);
    }
    
    return [...indices].map(i => questionSet[i]);
  }
  
  // ═══════════════════════════════════════════════════════════════════
  // RATE LIMITING — Anti-brute-force
  // ═══════════════════════════════════════════════════════════════════
  
  _checkLockout(customerId) {
    const tracking = this.failureTracking.get(customerId);
    if (!tracking) return { locked: false };
    
    if (tracking.lockedUntil && tracking.lockedUntil > Date.now()) {
      return {
        locked: true,
        remainingMs: tracking.lockedUntil - Date.now()
      };
    }
    
    // Clear expired lockout
    if (tracking.lockedUntil && tracking.lockedUntil <= Date.now()) {
      tracking.lockedUntil = null;
      tracking.consecutive = 0;
    }
    
    return { locked: false };
  }
  
  _recordFailure(customerId) {
    let tracking = this.failureTracking.get(customerId);
    if (!tracking) {
      tracking = { consecutive: 0, dailyFailures: [], lockedUntil: null };
      this.failureTracking.set(customerId, tracking);
    }
    
    tracking.consecutive++;
    tracking.dailyFailures.push(Date.now());
    
    // Prune old daily failures
    const cutoff = Date.now() - DAILY_WINDOW_MS;
    tracking.dailyFailures = tracking.dailyFailures.filter(t => t > cutoff);
    
    // Lockout after consecutive failures
    if (tracking.consecutive >= MAX_CONSECUTIVE_FAILURES) {
      tracking.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
      
      logger.warn("Security challenge lockout triggered", {
        customerId,
        consecutiveFailures: tracking.consecutive,
        lockoutMinutes: LOCKOUT_DURATION_MS / 60000
      });
    }
    
    // Flag for review after daily limit
    if (tracking.dailyFailures.length >= MAX_DAILY_FAILURES) {
      logger.error("SECURITY ALERT: Excessive challenge failures", {
        customerId,
        dailyFailures: tracking.dailyFailures.length,
        action: "ACCOUNT_FLAGGED_FOR_REVIEW"
      });
    }
  }
  
  _recordSuccess(customerId) {
    const tracking = this.failureTracking.get(customerId);
    if (tracking) {
      tracking.consecutive = 0;
    }
  }
  
  _getRemainingAttempts(customerId) {
    const tracking = this.failureTracking.get(customerId);
    if (!tracking) return MAX_CONSECUTIVE_FAILURES;
    return Math.max(0, MAX_CONSECUTIVE_FAILURES - tracking.consecutive);
  }
}


module.exports = {
  SecurityQuestions,
  PRESET_QUESTIONS,
  CHALLENGE_CONFIGS,
  CUSTOM_QUESTION_SLOTS,
  MAX_CONSECUTIVE_FAILURES,
  LOCKOUT_DURATION_MS
};
