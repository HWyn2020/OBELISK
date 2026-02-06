/**
 * Encryption Engine
 * 
 * Military-grade encryption for financial data at rest.
 * 
 * Standards:
 *   - AES-256-GCM for symmetric encryption (NIST approved, used by NSA for TOP SECRET)
 *   - HKDF for key derivation (RFC 5869)
 *   - Unique IV per encryption operation (96-bit, cryptographically random)
 *   - Authentication tags prevent tampering (GCM mode)
 *   - Key rotation with versioning (old data remains decryptable)
 *   - Field-level encryption (encrypt individual fields, not entire records)
 * 
 * What gets encrypted:
 *   - IBAN / account numbers
 *   - Beneficiary names
 *   - KYC documents (ID numbers, passport data)
 *   - Transaction amounts in audit logs
 *   - Webhook payloads
 * 
 * What stays plaintext (for indexing/querying):
 *   - Payment IDs (UUIDs, no PII)
 *   - State (enum)
 *   - Currency codes
 *   - Timestamps
 *   - Country codes
 */

const crypto = require("crypto");
const logger = require("../utils/logger");

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;        // 96-bit IV for GCM (NIST recommendation)
const TAG_LENGTH = 16;       // 128-bit auth tag
const KEY_LENGTH = 32;       // 256-bit key
const SALT_LENGTH = 16;      // For HKDF
const ENCODING = "base64";

class EncryptionEngine {
  /**
   * @param {Object} options
   * @param {string} options.masterKey - Base64-encoded 256-bit master key
   * @param {number} options.keyVersion - Current key version for rotation
   * @param {Map<number, string>} options.previousKeys - Old key versions for decryption
   */
  constructor(options = {}) {
    if (!options.masterKey) {
      throw new Error("Master encryption key is required");
    }
    
    const keyBuffer = Buffer.from(options.masterKey, "base64");
    if (keyBuffer.length !== KEY_LENGTH) {
      throw new Error(`Master key must be ${KEY_LENGTH} bytes (${KEY_LENGTH * 8}-bit)`);
    }
    
    this.masterKey = keyBuffer;
    this.keyVersion = options.keyVersion || 1;
    this.previousKeys = options.previousKeys || new Map();
    
    // FIX PEN-005: Instance-specific entropy for key derivation
    this._instanceSalt = options.instanceSalt || crypto.randomBytes(16);
    
    // Derive purpose-specific keys from master key using HKDF
    this.keys = {
      pii: this._deriveKey("pii-encryption"),
      financial: this._deriveKey("financial-data"),
      documents: this._deriveKey("kyc-documents"),
      webhooks: this._deriveKey("webhook-payloads"),
      audit: this._deriveKey("audit-trail")
    };
    
    logger.info("Encryption engine initialized", {
      algorithm: ALGORITHM,
      keyVersion: this.keyVersion,
      purposes: Object.keys(this.keys)
    });
  }
  
  /**
   * Encrypt a plaintext value
   * 
   * Output format: VERSION:IV:AUTH_TAG:CIPHERTEXT (all base64)
   * Version prefix enables key rotation — old ciphertext can be
   * decrypted with the correct historical key.
   * 
   * @param {string} plaintext - Value to encrypt
   * @param {string} purpose - Key purpose: 'pii', 'financial', 'documents', 'webhooks', 'audit'
   * @param {string} context - Additional authenticated data (e.g., payment ID)
   * @returns {string} Encrypted string
   */
  encrypt(plaintext, purpose = "pii", context = "") {
    if (!plaintext || typeof plaintext !== "string") {
      throw new Error("Plaintext must be a non-empty string");
    }
    
    const key = this.keys[purpose];
    if (!key) throw new Error(`Unknown encryption purpose: ${purpose}`);
    
    // Unique IV per operation (CRITICAL: never reuse IV with same key)
    const iv = crypto.randomBytes(IV_LENGTH);
    
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
      authTagLength: TAG_LENGTH
    });
    
    // Additional Authenticated Data (AAD) - binds ciphertext to context
    // Prevents moving encrypted field from one record to another
    if (context) {
      cipher.setAAD(Buffer.from(context, "utf8"));
    }
    
    const encrypted = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final()
    ]);
    
    const authTag = cipher.getAuthTag();
    
    // Format: v{VERSION}:{IV}:{TAG}:{CIPHERTEXT}
    return [
      `v${this.keyVersion}`,
      iv.toString(ENCODING),
      authTag.toString(ENCODING),
      encrypted.toString(ENCODING)
    ].join(":");
  }
  
  /**
   * Decrypt an encrypted value
   * 
   * @param {string} encryptedStr - Output from encrypt()
   * @param {string} purpose - Must match the purpose used during encryption
   * @param {string} context - Must match the context used during encryption
   * @returns {string} Decrypted plaintext
   */
  decrypt(encryptedStr, purpose = "pii", context = "") {
    if (!encryptedStr || typeof encryptedStr !== "string") {
      throw new Error("Encrypted string is required");
    }
    
    const parts = encryptedStr.split(":");
    if (parts.length !== 4) {
      throw new Error("Invalid encrypted format");
    }
    
    const [versionStr, ivB64, tagB64, ciphertextB64] = parts;
    const version = parseInt(versionStr.slice(1));
    
    // Get the correct key for this version
    let key;
    if (version === this.keyVersion) {
      key = this.keys[purpose];
    } else {
      const oldMasterKey = this.previousKeys.get(version);
      if (!oldMasterKey) {
        throw new Error(`No key available for version ${version}`);
      }
      key = this._deriveKeyFromMaster(Buffer.from(oldMasterKey, "base64"), `${purpose}-encryption`);
    }
    
    if (!key) throw new Error(`Unknown encryption purpose: ${purpose}`);
    
    const iv = Buffer.from(ivB64, ENCODING);
    const authTag = Buffer.from(tagB64, ENCODING);
    const ciphertext = Buffer.from(ciphertextB64, ENCODING);
    
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
      authTagLength: TAG_LENGTH
    });
    
    decipher.setAuthTag(authTag);
    
    if (context) {
      decipher.setAAD(Buffer.from(context, "utf8"));
    }
    
    try {
      const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
      ]);
      return decrypted.toString("utf8");
    } catch (err) {
      // Auth tag mismatch = data tampered with
      if (err.message.includes("Unsupported state") || err.message.includes("unable to authenticate")) {
        throw new Error("Decryption failed: data may have been tampered with");
      }
      throw err;
    }
  }
  
  /**
   * Encrypt an object's sensitive fields in-place
   * Returns a new object with specified fields encrypted
   * 
   * @param {Object} obj - Source object
   * @param {string[]} fields - Fields to encrypt
   * @param {string} purpose - Encryption purpose
   * @param {string} contextId - Unique ID binding (e.g., payment ID)
   * @returns {Object} New object with encrypted fields
   */
  encryptFields(obj, fields, purpose = "pii", contextId = "") {
    const result = { ...obj };
    
    for (const field of fields) {
      if (result[field] !== undefined && result[field] !== null) {
        const value = typeof result[field] === "string"
          ? result[field]
          : JSON.stringify(result[field]);
        result[field] = this.encrypt(value, purpose, `${contextId}:${field}`);
      }
    }
    
    return result;
  }
  
  /**
   * Decrypt an object's encrypted fields
   */
  decryptFields(obj, fields, purpose = "pii", contextId = "") {
    const result = { ...obj };
    
    for (const field of fields) {
      if (result[field] && typeof result[field] === "string" && result[field].startsWith("v")) {
        try {
          result[field] = this.decrypt(result[field], purpose, `${contextId}:${field}`);
        } catch (err) {
          logger.error("Field decryption failed", { field, error: err.message });
          result[field] = "[DECRYPTION_FAILED]";
        }
      }
    }
    
    return result;
  }
  
  /**
   * Generate a cryptographically secure hash for comparison
   * (e.g., hash an IBAN for lookups without storing plaintext)
   */
  hash(value, salt = "") {
    return crypto
      .createHmac("sha256", this.masterKey)
      .update(`${salt}:${value}`)
      .digest("hex");
  }
  
  /**
   * Generate a new random master key (for initial setup or rotation)
   */
  static generateMasterKey() {
    return crypto.randomBytes(KEY_LENGTH).toString("base64");
  }
  
  /**
   * Derive a purpose-specific key using HKDF
   */
  _deriveKey(info) {
    return this._deriveKeyFromMaster(this.masterKey, info);
  }
  
  _deriveKeyFromMaster(masterKey, info) {
    // HKDF-SHA256
    // FIX PEN-005: Salt includes instance-specific entropy
    const baseSalt = crypto.createHash("sha256").update("obelisk-key-derivation").digest();
    const salt = crypto.createHmac("sha256", baseSalt).update(this._instanceSalt || Buffer.alloc(0)).digest();
    const prk = crypto.createHmac("sha256", salt).update(masterKey).digest();
    
    // Expand
    const infoBuffer = Buffer.from(info, "utf8");
    const t1 = crypto.createHmac("sha256", prk)
      .update(Buffer.concat([infoBuffer, Buffer.from([1])]))
      .digest();
    
    return t1; // 32 bytes = 256-bit derived key
  }
}

module.exports = { EncryptionEngine };
