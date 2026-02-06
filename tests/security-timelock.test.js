/**
 * OBELISK — Security Questions & TimeLock Anti-Exploitation Tests
 * 
 * Tests the three-layer defense against free optionality exploitation:
 *   FIX 1: 48-hour lock-in period (peek-and-bail prevention)
 *   FIX 2: Per-customer daily contract cap with trust tiers
 *   FIX 3: Non-refundable contract fee (1.2% + $1)
 *   GATE:  Security question challenge before TimeLock creation
 *   SEAL:  Derivative probability encrypted, never in client responses
 */

const { SecurityQuestions, PRESET_QUESTIONS, CHALLENGE_CONFIGS, CUSTOM_QUESTION_SLOTS, MAX_CONSECUTIVE_FAILURES } = require("../src/security/security-questions");
const { TimeLockEngine, CONTRACT_STATES, MIN_LOCK_IN_HOURS, TRUST_TIERS, CONTRACT_FEE_FLAT, CONTRACT_FEE_BPS } = require("../src/contracts/timelock");
const { EncryptionEngine } = require("../src/crypto/encryption");
const { FXService } = require("../src/core/fx-service");

const PASS = "test-passphrase-32chars-minimum!!";
const mk = EncryptionEngine.generateMasterKey();

// Standard test answers for all 9 questions
const STANDARD_SETUP = {
  presetAnswers: {
    "SQ-001": "Maple Street",
    "SQ-002": "Mrs. Johnson",
    "SQ-003": "Michael Davis",
    "SQ-004": "Portland",
    "SQ-005": "Blue Honda Civic",
    "SQ-006": "Burger King",
    "SQ-007": "Italian"
  },
  customQuestions: [
    { question: "What was the name of your first pet fish?", answer: "Goldie" },
    { question: "What was the first concert you attended?", answer: "Green Day" }
  ]
};

// ════════════════════════════════════════════════════════════
// SECURITY QUESTIONS MODULE
// ════════════════════════════════════════════════════════════

describe("SECURITY QUESTIONS: Account Setup", () => {
  let sq;
  
  beforeEach(() => {
    sq = new SecurityQuestions();
  });
  
  test("SQ-001: Setup requires all 7 preset answers", async () => {
    const result = await sq.setupQuestions("cust-1", STANDARD_SETUP);
    expect(result.success).toBe(true);
    expect(result.questionsConfigured).toBe(9);
    expect(result.questionIds).toHaveLength(9);
  });
  
  test("SQ-002: Missing preset answer rejected", async () => {
    const partial = {
      presetAnswers: { "SQ-001": "Street", "SQ-002": "Teacher" },
      customQuestions: STANDARD_SETUP.customQuestions
    };
    await expect(sq.setupQuestions("cust-2", partial)).rejects.toThrow("Missing answers");
  });
  
  test("SQ-003: Exactly 2 custom questions required", async () => {
    const oneCustom = {
      presetAnswers: STANDARD_SETUP.presetAnswers,
      customQuestions: [{ question: "Only one question here?", answer: "Yes" }]
    };
    await expect(sq.setupQuestions("cust-3", oneCustom)).rejects.toThrow("Exactly 2");
  });
  
  test("SQ-004: Custom question must be at least 10 characters", async () => {
    const shortQ = {
      presetAnswers: STANDARD_SETUP.presetAnswers,
      customQuestions: [
        { question: "Short?", answer: "Answer" },
        { question: "Also short?", answer: "Answer" }
      ]
    };
    await expect(sq.setupQuestions("cust-4", shortQ)).rejects.toThrow("at least 10 characters");
  });
  
  test("SQ-005: Answer must be at least 2 characters", async () => {
    const shortA = {
      ...STANDARD_SETUP,
      presetAnswers: { ...STANDARD_SETUP.presetAnswers, "SQ-001": "X" }
    };
    await expect(sq.setupQuestions("cust-5", shortA)).rejects.toThrow("at least 2 characters");
  });
  
  test("SQ-006: Customer ID required", async () => {
    await expect(sq.setupQuestions("", STANDARD_SETUP)).rejects.toThrow("Customer ID");
  });
  
  test("SQ-007: hasQuestionsConfigured returns correct status", async () => {
    expect(sq.hasQuestionsConfigured("cust-7")).toBe(false);
    await sq.setupQuestions("cust-7", STANDARD_SETUP);
    expect(sq.hasQuestionsConfigured("cust-7")).toBe(true);
  });
  
  test("SQ-008: getQuestionCount returns 9 after setup", async () => {
    await sq.setupQuestions("cust-8", STANDARD_SETUP);
    expect(sq.getQuestionCount("cust-8")).toBe(9);
  });
  
  test("SQ-009: Setup with encryption engine encrypts at rest", async () => {
    const enc = new EncryptionEngine({ masterKey: mk });
    const sqEnc = new SecurityQuestions({ encryptionEngine: enc });
    
    const result = await sqEnc.setupQuestions("cust-9", STANDARD_SETUP);
    expect(result.success).toBe(true);
    
    // Verify stored data is encrypted
    const stored = sqEnc.customerQuestions.get("cust-9");
    expect(stored.encrypted).toBe(true);
    expect(typeof stored.data).toBe("string"); // Encrypted string, not plain object
  });
  
  test("SQ-010: Null/undefined params rejected", async () => {
    await expect(sq.setupQuestions("cust-10", null)).rejects.toThrow();
    await expect(sq.setupQuestions("cust-10", {})).rejects.toThrow();
  });
});

describe("SECURITY QUESTIONS: Challenge Generation", () => {
  let sq;
  
  beforeAll(async () => {
    sq = new SecurityQuestions();
    await sq.setupQuestions("cust-chal", STANDARD_SETUP);
  });
  
  test("CH-001: Generate PASSWORD_CHANGE challenge (3 questions)", () => {
    const challenge = sq.generateChallenge("cust-chal", "PASSWORD_CHANGE");
    expect(challenge.questions).toHaveLength(3);
    expect(challenge.challengeToken).toBeDefined();
    expect(challenge.challengeToken.length).toBe(64); // 32 bytes hex
    expect(challenge.expiresAt).toBeDefined();
  });
  
  test("CH-002: Generate TIMELOCK_CREATE challenge (3 questions)", () => {
    const challenge = sq.generateChallenge("cust-chal", "TIMELOCK_CREATE");
    expect(challenge.questions).toHaveLength(3);
    expect(challenge.challengeType).toBe("TIMELOCK_CREATE");
  });
  
  test("CH-003: Generate ACCOUNT_RECOVERY challenge (5 questions)", () => {
    const challenge = sq.generateChallenge("cust-chal", "ACCOUNT_RECOVERY");
    expect(challenge.questions).toHaveLength(5);
  });
  
  test("CH-004: Invalid challenge type rejected", () => {
    expect(() => sq.generateChallenge("cust-chal", "INVALID")).toThrow("Invalid challenge type");
  });
  
  test("CH-005: Unconfigured customer rejected", () => {
    expect(() => sq.generateChallenge("nonexistent", "PASSWORD_CHANGE")).toThrow("not configured");
  });
  
  test("CH-006: Questions are randomized (statistical test)", () => {
    const seen = new Set();
    for (let i = 0; i < 20; i++) {
      const challenge = sq.generateChallenge("cust-chal", "PASSWORD_CHANGE");
      const key = challenge.questions.map(q => q.id).sort().join(",");
      seen.add(key);
    }
    // With 9 choose 3 = 84 combinations, 20 draws should produce multiple unique sets
    expect(seen.size).toBeGreaterThan(1);
  });
  
  test("CH-007: Challenge questions never include answers", () => {
    const challenge = sq.generateChallenge("cust-chal", "PASSWORD_CHANGE");
    for (const q of challenge.questions) {
      expect(q.id).toBeDefined();
      expect(q.text).toBeDefined();
      expect(q.answer).toBeUndefined();
      expect(q.answerHash).toBeUndefined();
      expect(q.answerSalt).toBeUndefined();
    }
  });
  
  test("CH-008: Challenge includes attempts remaining", () => {
    const challenge = sq.generateChallenge("cust-chal", "PASSWORD_CHANGE");
    expect(challenge.attemptsRemaining).toBeDefined();
    expect(challenge.attemptsRemaining).toBe(MAX_CONSECUTIVE_FAILURES);
  });
});

describe("SECURITY QUESTIONS: Verification", () => {
  let sq;
  
  beforeAll(async () => {
    sq = new SecurityQuestions();
    await sq.setupQuestions("cust-ver", STANDARD_SETUP);
  });
  
  test("VER-001: Correct answers pass verification", async () => {
    const challenge = sq.generateChallenge("cust-ver", "TIMELOCK_CREATE");
    
    // Build answers from our standard setup
    const answers = {};
    for (const q of challenge.questions) {
      if (q.id === "SQ-001") answers[q.id] = "Maple Street";
      else if (q.id === "SQ-002") answers[q.id] = "Mrs. Johnson";
      else if (q.id === "SQ-003") answers[q.id] = "Michael Davis";
      else if (q.id === "SQ-004") answers[q.id] = "Portland";
      else if (q.id === "SQ-005") answers[q.id] = "Blue Honda Civic";
      else if (q.id === "SQ-006") answers[q.id] = "Burger King";
      else if (q.id === "SQ-007") answers[q.id] = "Italian";
      else if (q.id === "SQ-C01") answers[q.id] = "Goldie";
      else if (q.id === "SQ-C02") answers[q.id] = "Green Day";
    }
    
    const result = await sq.verifyChallenge(challenge.challengeToken, answers);
    expect(result.verified).toBe(true);
    expect(result.correctCount).toBe(3);
  });
  
  test("VER-002: Wrong answers fail verification", async () => {
    const challenge = sq.generateChallenge("cust-ver", "TIMELOCK_CREATE");
    
    const answers = {};
    for (const q of challenge.questions) {
      answers[q.id] = "WRONG ANSWER";
    }
    
    const result = await sq.verifyChallenge(challenge.challengeToken, answers);
    expect(result.verified).toBe(false);
    expect(result.correctCount).toBe(0);
  });
  
  test("VER-003: Missing answers fail verification", async () => {
    const challenge = sq.generateChallenge("cust-ver", "TIMELOCK_CREATE");
    const result = await sq.verifyChallenge(challenge.challengeToken, {});
    expect(result.verified).toBe(false);
  });
  
  test("VER-004: Challenge token is one-time use", async () => {
    const challenge = sq.generateChallenge("cust-ver", "TIMELOCK_CREATE");
    const answers = {};
    for (const q of challenge.questions) {
      answers[q.id] = "anything";
    }
    
    await sq.verifyChallenge(challenge.challengeToken, answers);
    // Second use of same token must fail
    await expect(sq.verifyChallenge(challenge.challengeToken, answers)).rejects.toThrow("Invalid or expired");
  });
  
  test("VER-005: Invalid challenge token rejected", async () => {
    await expect(sq.verifyChallenge("invalid-token", {})).rejects.toThrow("Invalid or expired");
  });
  
  test("VER-006: Answer normalization — case insensitive", async () => {
    const challenge = sq.generateChallenge("cust-ver", "TIMELOCK_CREATE");
    
    const answers = {};
    for (const q of challenge.questions) {
      if (q.id === "SQ-001") answers[q.id] = "MAPLE STREET"; // Uppercase
      else if (q.id === "SQ-002") answers[q.id] = "mrs. johnson"; // Lowercase
      else if (q.id === "SQ-003") answers[q.id] = "  Michael  Davis  "; // Extra spaces
      else if (q.id === "SQ-004") answers[q.id] = "  portland  "; // Spaces + case
      else if (q.id === "SQ-005") answers[q.id] = "BLUE HONDA CIVIC";
      else if (q.id === "SQ-006") answers[q.id] = "burger king";
      else if (q.id === "SQ-007") answers[q.id] = "  ITALIAN  ";
      else if (q.id === "SQ-C01") answers[q.id] = "GOLDIE";
      else if (q.id === "SQ-C02") answers[q.id] = "GREEN DAY";
    }
    
    const result = await sq.verifyChallenge(challenge.challengeToken, answers);
    expect(result.verified).toBe(true);
  });
  
  test("VER-007: Results don't reveal which questions were wrong", async () => {
    const challenge = sq.generateChallenge("cust-ver", "TIMELOCK_CREATE");
    const answers = {};
    for (const q of challenge.questions) {
      answers[q.id] = "WRONG";
    }
    
    const result = await sq.verifyChallenge(challenge.challengeToken, answers);
    // Should NOT contain per-question correct/incorrect details
    expect(result.questionDetails).toBeUndefined();
    expect(result.results).toBeUndefined();
  });
});

describe("SECURITY QUESTIONS: Rate Limiting & Lockout", () => {
  let sq;
  
  beforeAll(async () => {
    sq = new SecurityQuestions();
    await sq.setupQuestions("cust-lock", STANDARD_SETUP);
  });
  
  test("LOCK-001: Lockout after 5 consecutive failures", async () => {
    for (let i = 0; i < MAX_CONSECUTIVE_FAILURES; i++) {
      const challenge = sq.generateChallenge("cust-lock", "PASSWORD_CHANGE");
      const answers = {};
      for (const q of challenge.questions) answers[q.id] = "WRONG";
      await sq.verifyChallenge(challenge.challengeToken, answers);
    }
    
    // Next challenge should be blocked
    expect(() => sq.generateChallenge("cust-lock", "PASSWORD_CHANGE")).toThrow("locked");
  });
  
  test("LOCK-002: Successful answer resets consecutive counter", async () => {
    const sq2 = new SecurityQuestions();
    await sq2.setupQuestions("cust-reset", STANDARD_SETUP);
    
    // Fail twice
    for (let i = 0; i < 2; i++) {
      const ch = sq2.generateChallenge("cust-reset", "PASSWORD_CHANGE");
      const a = {};
      for (const q of ch.questions) a[q.id] = "WRONG";
      await sq2.verifyChallenge(ch.challengeToken, a);
    }
    
    // Succeed once
    const ch = sq2.generateChallenge("cust-reset", "PASSWORD_CHANGE");
    const answers = {};
    for (const q of ch.questions) {
      if (q.id === "SQ-001") answers[q.id] = "Maple Street";
      else if (q.id === "SQ-002") answers[q.id] = "Mrs. Johnson";
      else if (q.id === "SQ-003") answers[q.id] = "Michael Davis";
      else if (q.id === "SQ-004") answers[q.id] = "Portland";
      else if (q.id === "SQ-005") answers[q.id] = "Blue Honda Civic";
      else if (q.id === "SQ-006") answers[q.id] = "Burger King";
      else if (q.id === "SQ-007") answers[q.id] = "Italian";
      else if (q.id === "SQ-C01") answers[q.id] = "Goldie";
      else if (q.id === "SQ-C02") answers[q.id] = "Green Day";
    }
    const result = await sq2.verifyChallenge(ch.challengeToken, answers);
    expect(result.verified).toBe(true);
    expect(result.attemptsRemaining).toBe(MAX_CONSECUTIVE_FAILURES);
  });
  
  test("LOCK-003: Attempts remaining decrements correctly", async () => {
    const sq3 = new SecurityQuestions();
    await sq3.setupQuestions("cust-dec", STANDARD_SETUP);
    
    const ch = sq3.generateChallenge("cust-dec", "PASSWORD_CHANGE");
    const a = {};
    for (const q of ch.questions) a[q.id] = "WRONG";
    const result = await sq3.verifyChallenge(ch.challengeToken, a);
    
    expect(result.attemptsRemaining).toBe(MAX_CONSECUTIVE_FAILURES - 1);
  });
});

// ════════════════════════════════════════════════════════════
// TIMELOCK ANTI-EXPLOITATION — The Three Fixes
// ════════════════════════════════════════════════════════════

describe("TIMELOCK FIX 1: 48-Hour Lock-In Period", () => {
  let tl;
  
  beforeAll(() => {
    const fx = new FXService({ markupBps: 0 });
    tl = new TimeLockEngine({ fxService: fx, paymentEngine: null, config: { feeBps: 120 } });
  });
  
  afterAll(() => tl.stopMonitor());
  
  test("LOCK-IN-001: Default lock-in is 48 hours", async () => {
    const c = await tl.createContract({
      paymentId: "p1", customerId: "c-li-1",
      amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    expect(c.lockInHours).toBe(48);
    
    const lockIn = new Date(c.lockInExpiresAt);
    const created = new Date(c.createdAt);
    const diffHours = (lockIn - created) / 3600000;
    expect(diffHours).toBeCloseTo(48, 0);
  });
  
  test("LOCK-IN-002: Cancel blocked during lock-in", async () => {
    const c = await tl.createContract({
      paymentId: "p2", customerId: "c-li-2",
      amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    await expect(tl.cancelContract(c, "DEDUCTED")).rejects.toThrow("lock-in period");
  });
  
  test("LOCK-IN-003: Cancel succeeds after lock-in expires", async () => {
    const fx = new FXService({ markupBps: 0 });
    const tlShort = new TimeLockEngine({ 
      fxService: fx, paymentEngine: null, 
      config: { feeBps: 120, minLockInHours: 0 } 
    });
    
    const c = await tlShort.createContract({
      paymentId: "p3", customerId: "c-li-3",
      amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    const result = await tlShort.cancelContract(c, "DEDUCTED");
    expect(result.action).toBe("CANCELLED");
    tlShort.stopMonitor();
  });
  
  test("LOCK-IN-004: Lock-in period configurable", async () => {
    const fx = new FXService({ markupBps: 0 });
    const tl24 = new TimeLockEngine({
      fxService: fx, paymentEngine: null,
      config: { feeBps: 120, minLockInHours: 24 }
    });
    
    const c = await tl24.createContract({
      paymentId: "p4", customerId: "c-li-4",
      amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    expect(c.lockInHours).toBe(24);
    tl24.stopMonitor();
  });
  
  test("LOCK-IN-005: Error message includes remaining hours", async () => {
    const c = await tl.createContract({
      paymentId: "p5", customerId: "c-li-5",
      amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    try {
      await tl.cancelContract(c, "DEDUCTED");
      fail("Should have thrown");
    } catch (e) {
      expect(e.message).toContain("hour");
      expect(e.message).toContain("lock-in period");
    }
  });
});

describe("TIMELOCK FIX 2: Daily Contract Cap + Trust Tiers", () => {
  let tl;
  
  beforeEach(() => {
    const fx = new FXService({ markupBps: 0 });
    tl = new TimeLockEngine({ fxService: fx, paymentEngine: null, config: { feeBps: 120 } });
  });
  
  afterEach(() => tl.stopMonitor());
  
  test("CAP-001: NEW customer limited to 1 contract/day", async () => {
    await tl.createContract({
      paymentId: "p1", customerId: "c-cap-1",
      amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    await expect(tl.createContract({
      paymentId: "p2", customerId: "c-cap-1",
      amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    })).rejects.toThrow("Daily TimeLock contract limit reached");
  });
  
  test("CAP-002: ESTABLISHED customer gets 3/day", async () => {
    tl.setCustomerTrustTier("c-cap-2", "ESTABLISHED");
    
    for (let i = 0; i < 3; i++) {
      await tl.createContract({
        paymentId: `p-${i}`, customerId: "c-cap-2",
        amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
        fallbackTier: "DEDUCTED"
      });
    }
    
    await expect(tl.createContract({
      paymentId: "p-4", customerId: "c-cap-2",
      amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    })).rejects.toThrow("Daily TimeLock contract limit reached");
  });
  
  test("CAP-003: TRUSTED customer gets 5/day", async () => {
    tl.setCustomerTrustTier("c-cap-3", "TRUSTED");
    
    for (let i = 0; i < 5; i++) {
      await tl.createContract({
        paymentId: `p-${i}`, customerId: "c-cap-3",
        amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
        fallbackTier: "DEDUCTED"
      });
    }
    
    await expect(tl.createContract({
      paymentId: "p-6", customerId: "c-cap-3",
      amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    })).rejects.toThrow("Daily TimeLock contract limit reached");
  });
  
  test("CAP-004: Different customers have independent limits", async () => {
    await tl.createContract({
      paymentId: "p-a", customerId: "c-cap-4a",
      amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    // Different customer should succeed
    const c = await tl.createContract({
      paymentId: "p-b", customerId: "c-cap-4b",
      amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    expect(c.id).toMatch(/^TLC-/);
  });
  
  test("CAP-005: Invalid trust tier rejected", () => {
    expect(() => tl.setCustomerTrustTier("c-x", "INVALID")).toThrow("Invalid trust tier");
  });
  
  test("CAP-006: Error message includes tier and usage info", async () => {
    await tl.createContract({
      paymentId: "p-1", customerId: "c-cap-6",
      amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    try {
      await tl.createContract({
        paymentId: "p-2", customerId: "c-cap-6",
        amount: 100, sendCurrency: "USD", receiveCurrency: "SGD",
        fallbackTier: "DEDUCTED"
      });
      fail("Should have thrown");
    } catch (e) {
      expect(e.message).toContain("NEW");
      expect(e.message).toContain("1 contract");
      expect(e.message).toContain("used 1");
    }
  });
  
  test("CAP-007: Trust tiers have correct max values", () => {
    expect(TRUST_TIERS.NEW.maxDailyContracts).toBe(1);
    expect(TRUST_TIERS.ESTABLISHED.maxDailyContracts).toBe(3);
    expect(TRUST_TIERS.TRUSTED.maxDailyContracts).toBe(5);
  });
});

describe("TIMELOCK FIX 3: Non-Refundable Contract Fee", () => {
  let tl;
  
  beforeAll(() => {
    const fx = new FXService({ markupBps: 0 });
    tl = new TimeLockEngine({ 
      fxService: fx, paymentEngine: null, 
      config: { feeBps: 120, minLockInHours: 0 }
    });
  });
  
  afterAll(() => tl.stopMonitor());
  
  test("FEE-001: Contract fee is 1.2% + $1", async () => {
    const c = await tl.createContract({
      paymentId: "p-fee1", customerId: "c-fee-1",
      amount: 1000, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    expect(c.contractFee).toBeDefined();
    expect(c.contractFee.flatComponent).toBe(1.00);
    expect(c.contractFee.percentComponent).toBe(12.00); // 1.2% of 1000
    expect(c.contractFee.total).toBe(13.00); // 12 + 1
  });
  
  test("FEE-002: Contract fee marked non-refundable", async () => {
    const c = await tl.createContract({
      paymentId: "p-fee2", customerId: "c-fee-2",
      amount: 500, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    expect(c.contractFee.refundable).toBe(false);
    expect(c.contractFee.creditedOnExecution).toBe(true);
  });
  
  test("FEE-003: Cancellation forfeits contract fee", async () => {
    const c = await tl.createContract({
      paymentId: "p-fee3", customerId: "c-fee-3",
      amount: 1000, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    const result = await tl.cancelContract(c, "DEDUCTED");
    expect(result.contractFeeForfeited).toBeDefined();
    expect(result.contractFeeForfeited.refunded).toBe(false);
    expect(result.contractFeeForfeited.amount).toBe(13.00);
  });
  
  test("FEE-004: Small amount still incurs $1 flat fee", async () => {
    const c = await tl.createContract({
      paymentId: "p-fee4", customerId: "c-fee-4",
      amount: 10, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    expect(c.contractFee.flatComponent).toBe(1.00);
    expect(c.contractFee.percentComponent).toBe(0.12); // 1.2% of 10
    expect(c.contractFee.total).toBe(1.12);
  });
  
  test("FEE-005: Fee currency matches send currency", async () => {
    const c = await tl.createContract({
      paymentId: "p-fee5", customerId: "c-fee-5",
      amount: 100, sendCurrency: "EUR", receiveCurrency: "USD",
      fallbackTier: "DEDUCTED"
    });
    
    expect(c.contractFee.currency).toBe("EUR");
  });
  
  test("FEE-006: Contract fee defaults are correct", () => {
    expect(CONTRACT_FEE_FLAT).toBe(1.00);
    expect(CONTRACT_FEE_BPS).toBe(120);
  });
});

describe("TIMELOCK SEAL: Derivative Profile Hidden", () => {
  let tl;
  
  beforeAll(() => {
    const fx = new FXService({ markupBps: 0 });
    tl = new TimeLockEngine({ 
      fxService: fx, paymentEngine: null, 
      config: { feeBps: 120, minLockInHours: 0 } 
    });
  });
  
  afterAll(() => tl.stopMonitor());
  
  test("SEAL-001: Contract object has no derivativeProfile field", async () => {
    const c = await tl.createContract({
      paymentId: "p-s1", customerId: "c-seal-1",
      amount: 5000, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    expect(c.derivativeProfile).toBeUndefined();
  });
  
  test("SEAL-002: Client view strips sealed data completely", async () => {
    const c = await tl.createContract({
      paymentId: "p-s2", customerId: "c-seal-2",
      amount: 5000, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    const view = tl.getClientView(c);
    expect(view._derivativeProfileSealed).toBeUndefined();
    expect(view.derivativeProfile).toBeUndefined();
    
    // JSON.stringify should contain no probability data
    const json = JSON.stringify(view);
    expect(json).not.toContain("estimatedProbability");
    expect(json).not.toContain("theoreticalValue");
    expect(json).not.toContain("optionType");
  });
  
  test("SEAL-003: Internal getDerivativeProfile works", async () => {
    const c = await tl.createContract({
      paymentId: "p-s3", customerId: "c-seal-3",
      amount: 5000, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    const profile = tl.getDerivativeProfile(c);
    expect(profile).toBeDefined();
    expect(profile.notional).toBe(5000);
    expect(profile.optionType).toBe("EUROPEAN_DIGITAL");
    expect(profile.theoreticalValue.estimatedProbability).toBeGreaterThan(0);
    expect(profile.theoreticalValue.estimatedProbability).toBeLessThan(1);
  });
  
  test("SEAL-004: Encrypted derivative profile with EncryptionEngine", async () => {
    const fx = new FXService({ markupBps: 0 });
    const enc = new EncryptionEngine({ masterKey: mk });
    const tlEnc = new TimeLockEngine({
      fxService: fx, paymentEngine: null,
      config: { feeBps: 120, minLockInHours: 0, encryptionEngine: enc }
    });
    
    const c = await tlEnc.createContract({
      paymentId: "p-enc", customerId: "c-seal-enc",
      amount: 5000, sendCurrency: "USD", receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });
    
    // Sealed data should be an encrypted string, not readable
    expect(typeof c._derivativeProfileSealed).toBe("string");
    expect(c._derivativeProfileSealed).not.toContain("estimatedProbability");
    
    // But internal method can decrypt it
    const profile = tlEnc.getDerivativeProfile(c);
    expect(profile.notional).toBe(5000);
    expect(profile.theoreticalValue.estimatedProbability).toBeGreaterThan(0);
    
    tlEnc.stopMonitor();
  });
  
  test("SEAL-005: getDerivativeProfile returns null for contract without profile", () => {
    const fakeContract = { id: "fake", _derivativeProfileSealed: null };
    expect(tl.getDerivativeProfile(fakeContract)).toBeNull();
  });
});

describe("TIMELOCK CONSTANTS: Exported values", () => {
  test("CONST-001: MIN_LOCK_IN_HOURS is 48", () => {
    expect(MIN_LOCK_IN_HOURS).toBe(48);
  });
  
  test("CONST-002: All trust tiers defined", () => {
    expect(TRUST_TIERS.NEW).toBeDefined();
    expect(TRUST_TIERS.ESTABLISHED).toBeDefined();
    expect(TRUST_TIERS.TRUSTED).toBeDefined();
  });
  
  test("CONST-003: CONTRACT_FEE values", () => {
    expect(CONTRACT_FEE_FLAT).toBe(1.00);
    expect(CONTRACT_FEE_BPS).toBe(120);
  });
  
  test("CONST-004: Preset questions count is 7", () => {
    expect(PRESET_QUESTIONS).toHaveLength(7);
  });
  
  test("CONST-005: Custom question slots is 2", () => {
    expect(CUSTOM_QUESTION_SLOTS).toBe(2);
  });
  
  test("CONST-006: All preset questions have id and text", () => {
    for (const q of PRESET_QUESTIONS) {
      expect(q.id).toMatch(/^SQ-\d{3}$/);
      expect(q.text.length).toBeGreaterThan(20);
    }
  });
});
