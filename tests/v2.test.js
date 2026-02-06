const { EncryptionEngine } = require("../src/crypto/encryption");
const { EnhancedSanctionsScreener } = require("../src/core/enhanced-sanctions");
const { KYCFramework, TIER_LIMITS } = require("../src/kyc/framework");
const { AMLFramework, REPORTING_THRESHOLDS } = require("../src/aml/framework");
const { TimeLockEngine, CONTRACT_STATES } = require("../src/contracts/timelock");
const { FXService } = require("../src/core/fx-service");

// ============================================================
// ENCRYPTION ENGINE
// ============================================================

describe("Encryption Engine", () => {
  const masterKey = EncryptionEngine.generateMasterKey();
  let engine;

  beforeAll(() => {
    engine = new EncryptionEngine({ masterKey, keyVersion: 1 });
  });

  test("encrypts and decrypts plaintext", () => {
    const plaintext = "DE89370400440532013000";
    const encrypted = engine.encrypt(plaintext, "pii");
    const decrypted = engine.decrypt(encrypted, "pii");
    expect(decrypted).toBe(plaintext);
  });

  test("encrypted output is not plaintext", () => {
    const plaintext = "sensitive-iban-number";
    const encrypted = engine.encrypt(plaintext, "pii");
    expect(encrypted).not.toContain(plaintext);
    expect(encrypted.startsWith("v1:")).toBe(true);
  });

  test("same plaintext produces different ciphertext (unique IV)", () => {
    const plaintext = "same-value";
    const enc1 = engine.encrypt(plaintext, "pii");
    const enc2 = engine.encrypt(plaintext, "pii");
    expect(enc1).not.toBe(enc2);
  });

  test("context binding prevents cross-record swaps", () => {
    const plaintext = "secret-data";
    const encrypted = engine.encrypt(plaintext, "pii", "payment-123");
    
    // Decrypt with correct context works
    expect(engine.decrypt(encrypted, "pii", "payment-123")).toBe(plaintext);
    
    // Decrypt with wrong context fails (tamper detection)
    expect(() => engine.decrypt(encrypted, "pii", "payment-456"))
      .toThrow("tampered");
  });

  test("wrong purpose key fails decryption", () => {
    const encrypted = engine.encrypt("data", "pii");
    expect(() => engine.decrypt(encrypted, "financial")).toThrow();
  });

  test("field-level encryption on object", () => {
    const obj = { name: "John Smith", iban: "DE89370400440532013000", country: "DE" };
    const encrypted = engine.encryptFields(obj, ["name", "iban"], "pii", "cust-1");
    
    expect(encrypted.name).not.toBe("John Smith");
    expect(encrypted.iban).not.toBe("DE89370400440532013000");
    expect(encrypted.country).toBe("DE"); // Not encrypted
    
    const decrypted = engine.decryptFields(encrypted, ["name", "iban"], "pii", "cust-1");
    expect(decrypted.name).toBe("John Smith");
    expect(decrypted.iban).toBe("DE89370400440532013000");
  });

  test("HMAC hash is deterministic", () => {
    const hash1 = engine.hash("test@email.com", "email");
    const hash2 = engine.hash("test@email.com", "email");
    expect(hash1).toBe(hash2);
    expect(hash1.length).toBe(64); // SHA-256 hex
  });

  test("different salts produce different hashes", () => {
    const hash1 = engine.hash("same-value", "salt1");
    const hash2 = engine.hash("same-value", "salt2");
    expect(hash1).not.toBe(hash2);
  });

  test("rejects invalid master key length", () => {
    expect(() => new EncryptionEngine({ masterKey: "short" })).toThrow("32 bytes");
  });

  test("handles empty string encryption", () => {
    expect(() => engine.encrypt("", "pii")).toThrow("non-empty");
  });

  test("handles unicode in plaintext", () => {
    const plaintext = "名前: 田中太郎 🇯🇵";
    const encrypted = engine.encrypt(plaintext, "pii");
    expect(engine.decrypt(encrypted, "pii")).toBe(plaintext);
  });
});

// ============================================================
// ENHANCED SANCTIONS SCREENING
// ============================================================

describe("Enhanced Sanctions Screening", () => {
  let screener;

  beforeAll(async () => {
    screener = new EnhancedSanctionsScreener();
    await screener.loadLists();
  });

  // Exact matches
  test("exact match on primary name", () => {
    const result = screener.screen("IVAN VLADIMIROVICH PETROV");
    expect(result.clear).toBe(false);
    expect(result.matches[0].matchType).toBe("EXACT");
    expect(result.matches[0].confidence).toBe(1.0);
  });

  test("exact match on alias", () => {
    const result = screener.screen("DS FINANCIAL LTD");
    expect(result.clear).toBe(false);
  });

  // Title stripping
  test("matches name with title prefix stripped", () => {
    const result = screener.screen("MR. IVAN VLADIMIROVICH PETROV");
    expect(result.clear).toBe(false);
  });

  test("matches name with military title", () => {
    const result = screener.screen("GENERAL IVAN VLADIMIROVICH PETROV");
    expect(result.clear).toBe(false);
  });

  // Phonetic matching
  test("KNOWN GAP: YVAN → IVAN phonetic match", () => {
    // YVAN produces different phonetic code than IVAN
    // Levenshtein catches it only if threshold is low enough
    const result = screener.screen("YVAN PETROV");
    if (result.clear) {
      console.log("VULN: YVAN/IVAN transliteration bypasses screening");
      console.log("  Fix: Add Soundex as secondary phonetic algorithm");
    }
    // Document the gap - don't pretend it works
    expect(result.clear).toBe(true);
  });

  test("catches French transliteration: PIETROV → PETROV", () => {
    const result = screener.screen("IVAN PIETROV");
    expect(result.clear).toBe(false);
  });

  // Cyrillic transliteration
  test("matches Cyrillic name via transliteration", () => {
    const result = screener.screen("ИВАН ПЕТРОВ");
    expect(result.clear).toBe(false);
  });

  // Arabic transliteration
  test("matches Arabic name via transliteration", () => {
    const result = screener.screen("MOHAMMED AL-RASHID");
    expect(result.clear).toBe(false);
  });

  test("catches Arabic transliteration variant", () => {
    const result = screener.screen("MUHAMMAD AL RASHID");
    expect(result.clear).toBe(false);
  });

  // Legal suffix normalization
  test("matches entity with different legal suffix", () => {
    const result = screener.screen("DARKSIDE FINANCIAL LIMITED");
    expect(result.clear).toBe(false);
  });

  // Name reversal
  test("catches reversed name order", () => {
    const result = screener.screen("PETROV IVAN VLADIMIROVICH");
    expect(result.clear).toBe(false);
  });

  // Clear names
  test("clears clean name", () => {
    const result = screener.screen("JOHN SMITH");
    expect(result.clear).toBe(true);
  });

  test("clears clean entity", () => {
    const result = screener.screen("ACME WIDGET CORPORATION");
    expect(result.clear).toBe(true);
  });

  // Zero-width character stripping
  test("strips zero-width characters before matching", () => {
    const result = screener.screen("IVAN\u200B PETROV");
    expect(result.clear).toBe(false);
  });

  // Jurisdiction risk
  test("flags high-risk jurisdiction", () => {
    const result = screener.screen("CLEAN NAME", { country: "KP" });
    expect(result.jurisdictionRisk).toBe("HIGH_RISK");
  });

  test("flags monitored jurisdiction", () => {
    const result = screener.screen("CLEAN NAME", { country: "NG" });
    expect(result.jurisdictionRisk).toBe("MONITORED");
  });

  // Payment screening
  test("screens full payment with corridor risk", () => {
    const result = screener.screenPayment({
      sender: { name: "CLEAN CORP", country: "US" },
      beneficiary: { name: "DARKSIDE FINANCIAL LTD", country: "RU" }
    });
    expect(result.clear).toBe(false);
    expect(result.sender.clear).toBe(true);
    expect(result.beneficiary.clear).toBe(false);
  });

  // Performance
  test("screens 1000 names in under 2 seconds", async () => {
    const names = Array.from({ length: 1000 }, (_, i) => `TEST ENTITY ${i}`);
    const start = performance.now();
    for (const name of names) {
      screener.screen(name);
    }
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(2000);
  });
});

// ============================================================
// KYC FRAMEWORK
// ============================================================

describe("KYC Framework", () => {
  let kyc;
  const masterKey = EncryptionEngine.generateMasterKey();

  beforeAll(async () => {
    const encryption = new EncryptionEngine({ masterKey });
    const screener = new EnhancedSanctionsScreener();
    await screener.loadLists();

    kyc = new KYCFramework({
      encryption,
      db: null,
      sanctionsScreener: screener
    });
  });

  test("onboards customer with basic verification", async () => {
    const result = await kyc.onboardCustomer({
      firstName: "John",
      lastName: "Smith",
      email: "john@example.com",
      phone: "+1234567890",
      country: "US"
    });

    expect(result.success).toBe(true);
    expect(result.customerId).toBeDefined();
    expect(result.tier).toBe("TIER_1");
    expect(result.limits.perTransaction).toBe(1000);
  });

  test("blocks customer matching sanctions", async () => {
    const result = await kyc.onboardCustomer({
      firstName: "IVAN",
      lastName: "PETROV",
      email: "ivan@example.com",
      phone: "+74951234567",
      country: "RU"
    });

    expect(result.success).toBe(false);
    expect(result.status).toBe("BLOCKED_SANCTIONS");
  });

  test("rejects missing required fields", async () => {
    const result = await kyc.onboardCustomer({
      firstName: "",
      lastName: "Smith",
      email: "invalid",
      phone: "",
      country: "X"
    });

    expect(result.success).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  test("encrypts PII in customer profile", async () => {
    const result = await kyc.onboardCustomer({
      firstName: "Jane",
      lastName: "Doe",
      email: "jane@example.com",
      phone: "+1555123456",
      country: "DE"
    });

    // Encrypted fields should start with version prefix
    expect(result.profile.firstName.startsWith("v1:")).toBe(true);
    expect(result.profile.email.startsWith("v1:")).toBe(true);
    expect(result.profile.country).toBe("DE"); // Not encrypted
  });

  test("validates document submission", async () => {
    const result = await kyc.submitDocument("cust-123", {
      type: "GOVERNMENT_ID",
      idType: "PASSPORT",
      number: "AB1234567",
      issuingCountry: "US",
      expiryDate: "2030-12-31"
    });

    expect(result.success).toBe(true);
    expect(result.status).toBe("PENDING_REVIEW");
  });

  test("rejects expired document", async () => {
    const result = await kyc.submitDocument("cust-123", {
      type: "GOVERNMENT_ID",
      idType: "PASSPORT",
      number: "AB1234567",
      issuingCountry: "US",
      expiryDate: "2020-01-01"
    });

    expect(result.success).toBe(false);
    expect(result.errors).toContain("Document has expired");
  });

  test("checks transaction limits for tier", () => {
    const customer = { kycTier: "TIER_1", monthlyTransactionVolume: 0 };
    
    const allowed = kyc.checkTransactionLimits(customer, 500);
    expect(allowed.allowed).toBe(true);
    
    const blocked = kyc.checkTransactionLimits(customer, 5000);
    expect(blocked.allowed).toBe(false);
    expect(blocked.violations[0].requiredTier).toBe("TIER_2");
  });

  test("risk score elevates for monitored jurisdiction", async () => {
    const result = await kyc.onboardCustomer({
      firstName: "Clean",
      lastName: "Person",
      email: "clean@example.com",
      phone: "+234123456789",
      country: "NG" // Nigeria - monitored (+15 points)
    });

    expect(result.success).toBe(true);
    // 15 points from monitored jurisdiction = LOW (0-25 range)
    // Would need additional risk factors to reach MEDIUM
    expect(result.riskLevel).toBe("LOW");
    expect(result.profile.riskScore).toBe(15);
  });
});

// ============================================================
// AML FRAMEWORK
// ============================================================

describe("AML Framework", () => {
  let aml;

  beforeAll(() => {
    aml = new AMLFramework();
  });

  test("detects structuring (smurfing)", async () => {
    const transaction = {
      id: "tx-current",
      sendAmount: 9500,
      sendCurrency: "EUR",
      sender: { name: "Test", country: "DE" },
      beneficiary: { name: "Receiver", country: "SG" },
      createdAt: new Date().toISOString()
    };

    // History: multiple transactions just below 10k threshold
    const history = Array.from({ length: 4 }, (_, i) => ({
      id: `tx-${i}`,
      sendAmount: 9000 + i * 100,
      sendCurrency: "EUR",
      sender: { name: "Test", country: "DE" },
      beneficiary: { name: "Receiver", country: "SG" },
      createdAt: new Date(Date.now() - i * 3600000).toISOString()
    }));

    const customer = { id: "cust-1", riskScore: 20, riskLevel: "LOW", kycTier: "TIER_2" };
    const result = await aml.analyzeTransaction(transaction, customer, history);

    const structuring = result.indicators.find(i => i.pattern === "STRUCTURING");
    expect(structuring).toBeDefined();
    expect(structuring.action).toBe("SAR");
  });

  test("detects high-risk corridor", async () => {
    const transaction = {
      id: "tx-1",
      sendAmount: 5000,
      sender: { name: "Sender", country: "US" },
      beneficiary: { name: "Receiver", country: "KP" }, // North Korea
      createdAt: new Date().toISOString()
    };

    const customer = { id: "cust-1", riskScore: 10, riskLevel: "LOW" };
    const result = await aml.analyzeTransaction(transaction, customer, []);

    expect(result.action).toBe("BLOCK");
    const corridor = result.indicators.find(i => i.pattern === "HIGH_RISK_CORRIDOR");
    expect(corridor.severity).toBe("CRITICAL");
  });

  test("detects currency layering", async () => {
    const transaction = {
      id: "tx-current",
      sendAmount: 5000,
      sendCurrency: "EUR",
      receiveCurrency: "JPY",
      sender: { name: "Test", country: "DE" },
      beneficiary: { name: "Recv", country: "JP" },
      createdAt: new Date().toISOString()
    };

    const history = [
      { sendCurrency: "EUR", receiveCurrency: "USD", createdAt: new Date(Date.now() - 3600000).toISOString() },
      { sendCurrency: "USD", receiveCurrency: "SGD", createdAt: new Date(Date.now() - 7200000).toISOString() }
    ];

    const customer = { id: "cust-1", riskScore: 10 };
    const result = await aml.analyzeTransaction(transaction, customer, history);

    const layering = result.indicators.find(i => i.pattern === "CURRENCY_LAYERING");
    expect(layering).toBeDefined();
  });

  test("flags threshold reporting", async () => {
    const transaction = {
      id: "tx-1",
      sendAmount: 15000,
      sender: { name: "Sender", country: "DE" },
      beneficiary: { name: "Receiver", country: "US" },
      createdAt: new Date().toISOString()
    };

    const customer = { id: "cust-1", riskScore: 5, riskLevel: "LOW" };
    const result = await aml.analyzeTransaction(transaction, customer, []);

    const threshold = result.indicators.find(i => i.pattern === "THRESHOLD_REPORT");
    expect(threshold).toBeDefined();
    expect(threshold.mandatory).toBe(true);
  });

  test("passes clean transaction", async () => {
    const transaction = {
      id: "tx-clean",
      sendAmount: 500,
      sendCurrency: "EUR",
      receiveCurrency: "USD",
      sender: { name: "Clean Sender", country: "DE" },
      beneficiary: { name: "Clean Receiver", country: "US" },
      createdAt: new Date().toISOString()
    };

    const customer = { id: "cust-1", riskScore: 5, riskLevel: "LOW" };
    const result = await aml.analyzeTransaction(transaction, customer, []);

    expect(result.action).toBe("PASS");
    expect(result.indicatorCount).toBe(0);
  });

  test("generates SAR draft when required", async () => {
    const transaction = {
      id: "tx-sar",
      sendAmount: 5000,
      sendCurrency: "USD",
      receiveCurrency: "SGD",
      sender: { name: "Sender", country: "US" },
      beneficiary: { name: "Receiver", country: "IR" }, // Iran
      createdAt: new Date().toISOString()
    };

    const customer = { id: "cust-1", riskScore: 30, riskLevel: "MEDIUM", kycTier: "TIER_2" };
    const result = await aml.analyzeTransaction(transaction, customer, []);

    expect(result.sarRequired).toBe(true);
    expect(result.sarDraft).toBeDefined();
    expect(result.sarDraft.reportType).toBe("SUSPICIOUS_ACTIVITY_REPORT");
  });
});

// ============================================================
// TIMELOCK CONTRACT ENGINE
// ============================================================

describe("TimeLock Contract Engine", () => {
  let timeLock;
  let fxService;

  beforeAll(() => {
    fxService = new FXService({ markupBps: 0 }); // No markup for testing
    timeLock = new TimeLockEngine({
      fxService,
      paymentEngine: null,
      config: { feeBps: 120, maxDurationHours: 72, minLockInHours: 0, contractFeeFlat: 1.00 }
    });
  });

  afterAll(() => {
    timeLock.stopMonitor();
  });

  test("calculates three fee tier options", async () => {
    const options = await timeLock.calculateOptions(20, "USD", "SGD");

    expect(options.options.instant).toBeDefined();
    expect(options.options.deducted).toBeDefined();
    expect(options.options.timeLock).toBeDefined();

    // Instant: user pays $20.24
    expect(options.options.instant.feeAmount).toBeCloseTo(0.24, 1);
    expect(options.options.instant.totalUserPays).toBeCloseTo(20.24, 1);

    // Deducted: receiver gets less
    expect(options.options.deducted.netTransferAmount).toBeCloseTo(19.76, 1);
    expect(options.options.deducted.totalUserPays).toBe(20);

    // TimeLock: potential zero fee
    expect(options.options.timeLock.feeAmount).toBe(0);
    expect(options.options.timeLock.breakEvenRate).toBeGreaterThan(options.options.timeLock.currentRate);
    expect(options.options.timeLock.maxDurationHours).toBe(72);
  });

  test("creates TimeLock contract with correct terms", async () => {
    const contract = await timeLock.createContract({
      paymentId: "pay-123",
      customerId: "cust-456",
      amount: 20,
      sendCurrency: "USD",
      receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED",
      maxDurationHours: 48
    });

    expect(contract.id).toMatch(/^TLC-/);
    expect(contract.state).toBe(CONTRACT_STATES.CREATED);
    expect(contract.principal).toBe(20);
    expect(contract.breakEvenRate).toBeGreaterThan(contract.entryRate);
    expect(contract.maxDurationHours).toBe(48);
    expect(contract.fallbackTier).toBe("DEDUCTED");
    expect(contract.derivativeProfile).toBeUndefined(); // SEALED — never in client view
    expect(contract._derivativeProfileSealed).toBeDefined(); // Sealed internally
    expect(contract.contractFee).toBeDefined();
    expect(contract.contractFee.refundable).toBe(false);
    expect(contract.contractFee.flatComponent).toBe(1.00);
    expect(contract.lockInExpiresAt).toBeDefined();
  });

  test("activates contract and starts monitoring", async () => {
    const contract = await timeLock.createContract({
      paymentId: "pay-789",
      customerId: "cust-789",
      amount: 100,
      sendCurrency: "USD",
      receiveCurrency: "EUR",
      fallbackTier: "INSTANT"
    });

    const activated = await timeLock.activateContract(contract);
    expect(activated.state).toBe(CONTRACT_STATES.ACTIVE);
    expect(timeLock.activeContracts.has(contract.id)).toBe(true);
  });

  test("executes contract when break-even reached", async () => {
    const contract = await timeLock.createContract({
      paymentId: "pay-exec",
      customerId: "cust-exec",
      amount: 1000,
      sendCurrency: "USD",
      receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });

    contract.state = CONTRACT_STATES.ACTIVE;

    // Simulate rate reaching break-even
    const favorableRate = contract.breakEvenRate + 0.001;
    const result = timeLock._isBreakEvenReached(contract, favorableRate);
    expect(result).toBe(true);

    const execution = timeLock._executeContract(contract, favorableRate);
    expect(execution.action).toBe("EXECUTED");
    expect(execution.contract.state).toBe(CONTRACT_STATES.EXECUTED);
    expect(execution.savings.fxGain).toBeGreaterThan(0);
  });

  test("expires contract and triggers fallback", () => {
    const contract = {
      id: "TLC-expired",
      state: CONTRACT_STATES.ACTIVE,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      fallbackTier: "DEDUCTED",
      feeAmountIfCharged: 1.20,
      maxDurationHours: 72,
      entryRate: 1.27,
      breakEvenRate: 1.2854,
      rateSnapshots: [{ rate: 1.27, timestamp: new Date().toISOString() }],
      stateHistory: []
    };

    const result = timeLock._expireContract(contract);
    expect(result.action).toBe("EXPIRED");
    expect(result.revertToTier).toBe("DEDUCTED");
    expect(result.feeCharged.deductedFrom).toBe("TRANSFER_AMOUNT");
  });

  test("cancels contract and reverts to chosen tier", async () => {
    const contract = await timeLock.createContract({
      paymentId: "pay-cancel",
      customerId: "cust-cancel",
      amount: 50,
      sendCurrency: "USD",
      receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED"
    });

    const result = await timeLock.cancelContract(contract, "INSTANT");
    expect(result.action).toBe("CANCELLED");
    expect(result.revertToTier).toBe("INSTANT");
    expect(result.feeCharged.deductedFrom).toBe("USER_ADDITIONAL");
    // FIX 3 verification: contract fee is forfeited, not refunded
    expect(result.contractFeeForfeited).toBeDefined();
    expect(result.contractFeeForfeited.refunded).toBe(false);
    expect(result.contractFeeForfeited.amount).toBeGreaterThan(0);
  });

  test("derivative profile is sealed but accessible via internal method", async () => {
    const contract = await timeLock.createContract({
      paymentId: "pay-deriv",
      customerId: "cust-deriv",
      amount: 10000,
      sendCurrency: "USD",
      receiveCurrency: "SGD",
      fallbackTier: "DEDUCTED",
      maxDurationHours: 72
    });

    // Client-facing: derivative profile must NOT be exposed
    expect(contract.derivativeProfile).toBeUndefined();
    
    // Client view strips it entirely
    const clientView = timeLock.getClientView(contract);
    expect(clientView._derivativeProfileSealed).toBeUndefined();
    expect(clientView.derivativeProfile).toBeUndefined();
    
    // Internal analytics: accessible via getDerivativeProfile()
    const profile = timeLock.getDerivativeProfile(contract);
    expect(profile).toBeDefined();
    expect(profile.notional).toBe(10000);
    expect(profile.strike).toBe(contract.breakEvenRate);
    expect(profile.theoreticalValue).toBeDefined();
    expect(profile.theoreticalValue.estimatedProbability).toBeGreaterThan(0);
    expect(profile.theoreticalValue.estimatedProbability).toBeLessThan(1);
    expect(profile.theoreticalValue.theoreticalValue).toBeGreaterThanOrEqual(0);
  });

  test("rejects invalid fallback tier", async () => {
    await expect(timeLock.createContract({
      paymentId: "pay-bad",
      customerId: "cust-bad",
      amount: 20,
      sendCurrency: "USD",
      receiveCurrency: "SGD",
      fallbackTier: "INVALID"
    })).rejects.toThrow("INSTANT or DEDUCTED");
  });

  test("break-even rate is higher than entry rate", async () => {
    const options = await timeLock.calculateOptions(20, "USD", "SGD");
    const tl = options.options.timeLock;

    expect(tl.breakEvenRate).toBeGreaterThan(tl.currentRate);
    expect(tl.rateMovementNeeded).toBeGreaterThan(0);
  });
});
