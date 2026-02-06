/**
 * IBAN / SWIFT Validator
 * 
 * Full IBAN validation with ISO 7064 Mod 97-10 checksum.
 * SWIFT/BIC format validation per ISO 9362.
 * Country-specific IBAN length enforcement.
 */

// IBAN lengths per country (ISO 13616)
const IBAN_LENGTHS = {
  AL: 28, AD: 24, AT: 20, AZ: 28, BH: 22, BY: 28, BE: 16, BA: 20,
  BR: 29, BG: 22, CR: 22, HR: 21, CY: 28, CZ: 24, DK: 18, DO: 28,
  EG: 29, SV: 28, EE: 20, FO: 18, FI: 18, FR: 27, GE: 22, DE: 22,
  GI: 23, GR: 27, GL: 18, GT: 28, HU: 28, IS: 26, IQ: 23, IE: 22,
  IL: 23, IT: 27, JO: 30, KZ: 20, XK: 20, KW: 30, LV: 21, LB: 28,
  LY: 25, LI: 21, LT: 20, LU: 20, MT: 31, MR: 27, MU: 30, MD: 24,
  MC: 27, ME: 22, NL: 18, MK: 19, NO: 15, PK: 24, PS: 29, PL: 28,
  PT: 25, QA: 29, RO: 24, LC: 32, SM: 27, SA: 24, RS: 22, SC: 31,
  SK: 24, SI: 19, ES: 24, SD: 18, SE: 24, CH: 21, TL: 23, TN: 24,
  TR: 26, UA: 29, AE: 23, GB: 22, VA: 22, VG: 24
};

class IBANValidator {
  /**
   * Validate IBAN with full checksum verification
   * @param {string} iban - IBAN string (spaces allowed)
   * @returns {Object} { valid, errors, formatted, countryCode, bankCode, accountNumber }
   */
  static validate(iban) {
    const errors = [];
    
    if (!iban || typeof iban !== "string") {
      return { valid: false, errors: ["IBAN is required"] };
    }
    
    // Normalize: strip spaces and uppercase
    const clean = iban.replace(/\s+/g, "").toUpperCase();
    
    // Basic format check
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(clean)) {
      errors.push("Invalid IBAN format: must start with 2-letter country code + 2 check digits");
      return { valid: false, errors };
    }
    
    const countryCode = clean.slice(0, 2);
    const checkDigits = clean.slice(2, 4);
    const bban = clean.slice(4);
    
    // Country code check
    if (!IBAN_LENGTHS[countryCode]) {
      errors.push(`Unsupported country code: ${countryCode}`);
      return { valid: false, errors, countryCode };
    }
    
    // Length check
    const expectedLength = IBAN_LENGTHS[countryCode];
    if (clean.length !== expectedLength) {
      errors.push(`Invalid length for ${countryCode}: expected ${expectedLength}, got ${clean.length}`);
      return { valid: false, errors, countryCode };
    }
    
    // ISO 7064 Mod 97-10 checksum
    // Move first 4 chars to end, convert letters to numbers (A=10, B=11, ..., Z=35)
    const rearranged = bban + countryCode + checkDigits;
    const numericString = rearranged.replace(/[A-Z]/g, (ch) => {
      return (ch.charCodeAt(0) - 55).toString();
    });
    
    // Modular arithmetic on the large number (process in chunks to avoid BigInt issues)
    let remainder = 0;
    for (const char of numericString) {
      remainder = (remainder * 10 + parseInt(char)) % 97;
    }
    
    if (remainder !== 1) {
      errors.push("IBAN checksum verification failed");
      return { valid: false, errors, countryCode };
    }
    
    // Format with spaces every 4 characters
    const formatted = clean.replace(/(.{4})/g, "$1 ").trim();
    
    return {
      valid: true,
      errors: [],
      raw: clean,
      formatted,
      countryCode,
      checkDigits,
      bban,
      bankIdentifier: this._extractBankId(countryCode, bban)
    };
  }
  
  /**
   * Extract bank identifier from BBAN (country-specific)
   */
  static _extractBankId(country, bban) {
    const bankIdLengths = {
      DE: 8, GB: 4, FR: 5, ES: 4, IT: 5, NL: 4, BE: 3,
      AT: 5, CH: 5, SE: 3, NO: 4, DK: 4, FI: 3, PL: 3
    };
    
    const len = bankIdLengths[country];
    return len ? bban.slice(0, len) : bban.slice(0, 4);
  }
}

class SWIFTValidator {
  /**
   * Validate SWIFT/BIC code per ISO 9362
   * Format: AAAA BB CC DDD
   *   AAAA = Bank code (letters)
   *   BB   = Country code (letters)
   *   CC   = Location code (alphanumeric)
   *   DDD  = Branch code (optional, alphanumeric, 'XXX' = head office)
   *   
   * @param {string} bic - SWIFT/BIC code
   * @returns {Object} { valid, errors, bankCode, countryCode, locationCode, branchCode }
   */
  static validate(bic) {
    const errors = [];
    
    if (!bic || typeof bic !== "string") {
      return { valid: false, errors: ["SWIFT/BIC code is required"] };
    }
    
    const clean = bic.replace(/\s+/g, "").toUpperCase();
    
    // Must be 8 or 11 characters
    if (clean.length !== 8 && clean.length !== 11) {
      errors.push("SWIFT/BIC must be 8 or 11 characters");
      return { valid: false, errors };
    }
    
    // Full pattern validation
    if (!/^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(clean)) {
      errors.push("Invalid SWIFT/BIC format");
      return { valid: false, errors };
    }
    
    const bankCode = clean.slice(0, 4);
    const countryCode = clean.slice(4, 6);
    const locationCode = clean.slice(6, 8);
    const branchCode = clean.length === 11 ? clean.slice(8, 11) : "XXX";
    
    // Validate country code exists
    if (!IBAN_LENGTHS[countryCode] && !["US", "CN", "JP", "IN", "RU", "AU", "NZ", "TH", "MY", "ID", "PH", "VN", "KR", "TW", "HK", "SG", "ZA", "NG", "KE", "GH"].includes(countryCode)) {
      errors.push(`Unrecognized country code: ${countryCode}`);
    }
    
    // Location code: second char '0' means test, '1' means passive
    const isTest = locationCode[1] === "0";
    const isPassive = locationCode[1] === "1";
    
    return {
      valid: errors.length === 0,
      errors,
      raw: clean,
      bankCode,
      countryCode,
      locationCode,
      branchCode,
      isHeadOffice: branchCode === "XXX",
      isTest,
      isPassive
    };
  }
}

module.exports = { IBANValidator, SWIFTValidator, IBAN_LENGTHS };
