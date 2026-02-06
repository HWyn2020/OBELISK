const { IBANValidator, SWIFTValidator } = require("../src/core/validator");
const { toMinorUnits, toMajorUnits, formatAmount, isValidCurrency, applyMarkup } = require("../src/utils/currency");
const { SanctionsScreener } = require("../src/core/sanctions");
const { PaymentEngine, STATE_MACHINE } = require("../src/core/payment-engine");

// ============================================================
// IBAN VALIDATION
// ============================================================

describe("IBAN Validator", () => {
  test("validates correct German IBAN", () => {
    const result = IBANValidator.validate("DE89 3704 0044 0532 0130 00");
    expect(result.valid).toBe(true);
    expect(result.countryCode).toBe("DE");
    expect(result.errors).toHaveLength(0);
  });

  test("validates correct British IBAN", () => {
    const result = IBANValidator.validate("GB29 NWBK 6016 1331 9268 19");
    expect(result.valid).toBe(true);
    expect(result.countryCode).toBe("GB");
  });

  test("validates correct French IBAN", () => {
    const result = IBANValidator.validate("FR76 3000 6000 0112 3456 7890 189");
    expect(result.valid).toBe(true);
    expect(result.countryCode).toBe("FR");
  });

  test("validates correct Dutch IBAN", () => {
    const result = IBANValidator.validate("NL91 ABNA 0417 1643 00");
    expect(result.valid).toBe(true);
  });

  test("validates correct Spanish IBAN", () => {
    const result = IBANValidator.validate("ES91 2100 0418 4502 0005 1332");
    expect(result.valid).toBe(true);
  });

  test("rejects IBAN with bad checksum", () => {
    const result = IBANValidator.validate("DE00 3704 0044 0532 0130 00");
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("checksum");
  });

  test("rejects IBAN with wrong length", () => {
    const result = IBANValidator.validate("DE89 3704 0044 0532 0130");
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("length");
  });

  test("rejects IBAN with invalid country", () => {
    const result = IBANValidator.validate("XX89 3704 0044 0532 0130 00");
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("Unsupported country");
  });

  test("rejects empty input", () => {
    expect(IBANValidator.validate("").valid).toBe(false);
    expect(IBANValidator.validate(null).valid).toBe(false);
  });

  test("handles IBAN without spaces", () => {
    const result = IBANValidator.validate("DE89370400440532013000");
    expect(result.valid).toBe(true);
  });

  test("extracts bank identifier", () => {
    const result = IBANValidator.validate("DE89370400440532013000");
    expect(result.bankIdentifier).toBe("37040044");
  });
});

// ============================================================
// SWIFT VALIDATION
// ============================================================

describe("SWIFT/BIC Validator", () => {
  test("validates 8-char SWIFT code", () => {
    const result = SWIFTValidator.validate("DEUTDEFF");
    expect(result.valid).toBe(true);
    expect(result.bankCode).toBe("DEUT");
    expect(result.countryCode).toBe("DE");
    expect(result.isHeadOffice).toBe(true);
  });

  test("validates 11-char SWIFT code", () => {
    const result = SWIFTValidator.validate("DEUTDEFF500");
    expect(result.valid).toBe(true);
    expect(result.branchCode).toBe("500");
    expect(result.isHeadOffice).toBe(false);
  });

  test("rejects invalid length", () => {
    expect(SWIFTValidator.validate("DEUT").valid).toBe(false);
    expect(SWIFTValidator.validate("DEUTDEFF50").valid).toBe(false);
  });

  test("rejects numeric bank code", () => {
    expect(SWIFTValidator.validate("1234DEFF").valid).toBe(false);
  });

  test("identifies test BIC", () => {
    const result = SWIFTValidator.validate("DEUTDEF0");
    expect(result.valid).toBe(true);
    expect(result.isTest).toBe(true);
  });
});

// ============================================================
// CURRENCY UTILITIES
// ============================================================

describe("Currency Utils", () => {
  test("converts to minor units (EUR)", () => {
    expect(toMinorUnits(100.50, "EUR")).toBe(10050);
    expect(toMinorUnits(0.01, "EUR")).toBe(1);
    expect(toMinorUnits(999999.99, "EUR")).toBe(99999999);
  });

  test("handles zero-decimal currencies (JPY)", () => {
    expect(toMinorUnits(1000, "JPY")).toBe(1000);
    expect(toMajorUnits(1000, "JPY")).toBe(1000);
  });

  test("handles 3-decimal currencies (BHD)", () => {
    expect(toMinorUnits(100.123, "BHD")).toBe(100123);
    expect(toMajorUnits(100123, "BHD")).toBe(100.123);
  });

  test("round-trips without precision loss", () => {
    const original = 1234.56;
    const minor = toMinorUnits(original, "EUR");
    const back = toMajorUnits(minor, "EUR");
    expect(back).toBe(original);
  });

  test("validates currency codes", () => {
    expect(isValidCurrency("USD")).toBe(true);
    expect(isValidCurrency("EUR")).toBe(true);
    expect(isValidCurrency("XYZ")).toBe(false);
    expect(isValidCurrency("")).toBe(false);
  });

  test("formats amounts correctly", () => {
    const formatted = formatAmount(1234.56, "USD");
    expect(formatted).toContain("1,234.56");
  });

  test("applies markup in basis points", () => {
    const rate = 1.0800;
    const marked = applyMarkup(rate, 50); // 50 bps = 0.5%
    expect(marked).toBeLessThan(rate);
    expect(marked).toBeCloseTo(1.0746, 4);
  });

  test("throws on unknown currency", () => {
    expect(() => toMinorUnits(100, "FAKE")).toThrow("Unknown currency");
  });
});

// ============================================================
// SANCTIONS SCREENING
// ============================================================

describe("Sanctions Screener", () => {
  let screener;

  beforeAll(async () => {
    screener = new SanctionsScreener();
    await screener.loadLists();
  });

  test("exact match returns high confidence", () => {
    const result = screener.screen("IVAN PETROV");
    expect(result.clear).toBe(false);
    expect(result.matches[0].matchType).toBe("EXACT");
    expect(result.matches[0].confidence).toBe(1.0);
  });

  test("fuzzy match catches transliterations", () => {
    const result = screener.screen("IVAN PETROFF");
    expect(result.clear).toBe(false);
    expect(result.matches[0].confidence).toBeGreaterThanOrEqual(0.80);
  });

  test("clears non-sanctioned names", () => {
    const result = screener.screen("MARIA GARCIA");
    expect(result.clear).toBe(true);
    expect(result.matches).toHaveLength(0);
  });

  test("screens both payment parties", () => {
    const payment = {
      sender: { name: "CLEAN SENDER CO", country: "DE" },
      beneficiary: { name: "DARKSIDE FINANCIAL LTD", country: "RU" }
    };
    const result = screener.screenPayment(payment);
    expect(result.clear).toBe(false);
    expect(result.sender.clear).toBe(true);
    expect(result.beneficiary.clear).toBe(false);
  });

  test("handles unicode normalization", () => {
    // Accented characters should be normalized
    const result = screener.screen("IVÁN PÉTROV");
    expect(result.clear).toBe(false);
  });

  test("handles empty name gracefully", () => {
    const result = screener.screen("");
    expect(result.clear).toBe(true);
  });

  test("case insensitive matching", () => {
    const result = screener.screen("ivan petrov");
    expect(result.clear).toBe(false);
  });

  test("returns screening duration", () => {
    const result = screener.screen("TEST NAME");
    expect(result.durationMs).toBeDefined();
    expect(typeof result.durationMs).toBe("number");
  });
});

// ============================================================
// PAYMENT STATE MACHINE
// ============================================================

describe("Payment State Machine", () => {
  test("all states have defined transitions", () => {
    const states = Object.keys(STATE_MACHINE);
    expect(states).toContain("INITIATED");
    expect(states).toContain("COMPLETED");
    expect(states).toContain("FAILED");
    expect(states).toContain("REJECTED");
  });

  test("terminal states have no outgoing transitions", () => {
    expect(STATE_MACHINE.COMPLETED).toHaveLength(0);
    expect(STATE_MACHINE.CANCELLED).toHaveLength(0);
    expect(STATE_MACHINE.EXPIRED).toHaveLength(0);
  });

  test("FAILED can retry to INITIATED", () => {
    expect(STATE_MACHINE.FAILED).toContain("INITIATED");
  });

  test("HELD can clear to SCREENED or reject", () => {
    expect(STATE_MACHINE.HELD).toContain("SCREENED");
    expect(STATE_MACHINE.HELD).toContain("REJECTED");
  });

  test("happy path is valid", () => {
    const happyPath = ["INITIATED", "VALIDATED", "SCREENED", "QUOTED", "CONFIRMED", "PROCESSING", "SETTLED", "COMPLETED"];
    for (let i = 0; i < happyPath.length - 1; i++) {
      expect(STATE_MACHINE[happyPath[i]]).toContain(happyPath[i + 1]);
    }
  });

  test("no state can transition to INITIATED except FAILED", () => {
    for (const [state, transitions] of Object.entries(STATE_MACHINE)) {
      if (state === "FAILED") continue;
      expect(transitions).not.toContain("INITIATED");
    }
  });
});
