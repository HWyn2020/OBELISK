/**
 * Sanctions Screening Engine
 * 
 * Screens payment parties against OFAC SDN, EU consolidated sanctions,
 * and UN Security Council lists. Uses fuzzy matching to catch transliteration
 * variants and common evasion patterns.
 * 
 * Match types:
 *   EXACT    - Direct name match (confidence >= 0.95)
 *   FUZZY    - Levenshtein distance <= 2 (confidence >= 0.80)
 *   PARTIAL  - Substring or word-level match (confidence >= 0.60)
 *   ALIAS    - Match against known aliases
 * 
 * Screening is BLOCKING: payments halt on any match above threshold.
 * False positives require manual review via the review queue.
 */

const logger = require("../utils/logger");

// In production, these would be loaded from OFAC SDN list downloads
// and refreshed every SANCTIONS_LIST_REFRESH_HOURS
// This is a demonstration set showing the matching logic
const DEMO_SDN_ENTRIES = [
  {
    id: "OFAC-001",
    name: "IVAN PETROV",
    aliases: ["IVAN PETROFF", "I. PETROV"],
    type: "individual",
    programs: ["UKRAINE-EO13662"],
    country: "RU",
    remarks: "Designated pursuant to E.O. 13662"
  },
  {
    id: "OFAC-002",
    name: "DARKSIDE FINANCIAL LTD",
    aliases: ["DARKSIDE FINANCE", "DS FINANCIAL"],
    type: "entity",
    programs: ["CYBER2"],
    country: "RU",
    remarks: "Ransomware-related designation"
  },
  {
    id: "EU-001",
    name: "ACME PETROLEUM GMBH",
    aliases: [],
    type: "entity",
    programs: ["EU-SANCTIONS-RU"],
    country: "RU",
    remarks: "EU Council Regulation 2022/XXX"
  }
];

class SanctionsScreener {
  constructor(options = {}) {
    this.threshold = options.threshold || 0.80;
    this.entries = [];
    this.lastRefresh = null;
    this.indexedNames = new Map(); // name -> entry mapping for fast lookup
  }
  
  /**
   * Load sanctions lists into memory and build search index
   * In production: downloads from OFAC/EU/UN endpoints
   */
  async loadLists() {
    // Production: fetch from official sources
    // OFAC: https://www.treasury.gov/ofac/downloads/sdn.csv
    // EU: https://data.europa.eu/data/datasets/consolidated-list-of-persons-groups-and-entities-subject-to-eu-financial-sanctions
    
    this.entries = DEMO_SDN_ENTRIES;
    this.indexedNames.clear();
    
    for (const entry of this.entries) {
      // Index primary name
      const normalized = this._normalize(entry.name);
      this.indexedNames.set(normalized, entry);
      
      // Index all aliases
      for (const alias of entry.aliases) {
        this.indexedNames.set(this._normalize(alias), entry);
      }
    }
    
    this.lastRefresh = new Date();
    
    logger.info("Sanctions lists loaded", {
      entryCount: this.entries.length,
      indexedNames: this.indexedNames.size,
      refreshedAt: this.lastRefresh.toISOString()
    });
  }
  
  /**
   * Screen a name against all sanctions lists
   * @param {string} name - Name to screen (individual or entity)
   * @param {string} country - ISO country code (optional, narrows search)
   * @returns {Object} { clear, matches, screenedAt, duration }
   */
  screen(name, country = null) {
    const startTime = Date.now();
    
    if (!name || typeof name !== "string") {
      return { clear: true, matches: [], screenedAt: new Date().toISOString(), duration: 0 };
    }
    
    const normalized = this._normalize(name);
    const matches = [];
    
    for (const [indexedName, entry] of this.indexedNames) {
      // Country pre-filter (if provided)
      if (country && entry.country && entry.country !== country) continue;
      
      // Exact match
      if (normalized === indexedName) {
        matches.push({
          entryId: entry.id,
          matchedName: entry.name,
          matchType: "EXACT",
          confidence: 1.0,
          programs: entry.programs,
          entityType: entry.type
        });
        continue;
      }
      
      // Fuzzy match (Levenshtein)
      const distance = this._levenshtein(normalized, indexedName);
      const maxLen = Math.max(normalized.length, indexedName.length);
      const similarity = 1 - (distance / maxLen);
      
      if (similarity >= this.threshold) {
        matches.push({
          entryId: entry.id,
          matchedName: entry.name,
          matchType: "FUZZY",
          confidence: Math.round(similarity * 100) / 100,
          programs: entry.programs,
          entityType: entry.type,
          editDistance: distance
        });
        continue;
      }
      
      // Partial match (all words from query appear in entry or vice versa)
      if (this._partialMatch(normalized, indexedName)) {
        matches.push({
          entryId: entry.id,
          matchedName: entry.name,
          matchType: "PARTIAL",
          confidence: 0.65,
          programs: entry.programs,
          entityType: entry.type
        });
      }
    }
    
    // Deduplicate by entry ID, keep highest confidence
    const deduped = this._dedup(matches);
    const duration = Date.now() - startTime;
    
    const result = {
      clear: deduped.length === 0,
      matches: deduped,
      screenedAt: new Date().toISOString(),
      durationMs: duration
    };
    
    if (!result.clear) {
      logger.warn("Sanctions match found", {
        screenedName: name.slice(0, 3) + "***",
        matchCount: deduped.length,
        highestConfidence: Math.max(...deduped.map(m => m.confidence))
      });
    }
    
    return result;
  }
  
  /**
   * Screen all parties in a payment
   * @param {Object} payment - Payment with sender and beneficiary
   * @returns {Object} { clear, senderResult, beneficiaryResult }
   */
  screenPayment(payment) {
    const senderResult = this.screen(
      payment.sender?.name,
      payment.sender?.country
    );
    
    const beneficiaryResult = this.screen(
      payment.beneficiary?.name,
      payment.beneficiary?.country
    );
    
    return {
      clear: senderResult.clear && beneficiaryResult.clear,
      sender: senderResult,
      beneficiary: beneficiaryResult,
      screenedAt: new Date().toISOString()
    };
  }
  
  /**
   * Normalize name for comparison
   * Strip accents, punctuation, extra spaces, lowercase
   */
  _normalize(name) {
    return name
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "") // strip accents
      .replace(/[^a-zA-Z0-9\s]/g, "") // strip punctuation
      .replace(/\s+/g, " ")           // normalize spaces
      .trim()
      .toUpperCase();
  }
  
  /**
   * Levenshtein edit distance
   */
  _levenshtein(a, b) {
    const matrix = Array.from({ length: a.length + 1 }, (_, i) =>
      Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
    );
    
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,      // deletion
          matrix[i][j - 1] + 1,      // insertion
          matrix[i - 1][j - 1] + cost // substitution
        );
      }
    }
    
    return matrix[a.length][b.length];
  }
  
  /**
   * Partial word match: all words from shorter string appear in longer
   */
  _partialMatch(a, b) {
    const wordsA = a.split(" ").filter(w => w.length > 2);
    const wordsB = b.split(" ").filter(w => w.length > 2);
    
    if (wordsA.length === 0 || wordsB.length === 0) return false;
    
    const shorter = wordsA.length <= wordsB.length ? wordsA : wordsB;
    const longer = wordsA.length <= wordsB.length ? wordsB : wordsA;
    
    const matchCount = shorter.filter(w => longer.includes(w)).length;
    return matchCount === shorter.length && shorter.length >= 2;
  }
  
  /**
   * Deduplicate matches by entry ID
   */
  _dedup(matches) {
    const best = new Map();
    
    for (const match of matches) {
      const existing = best.get(match.entryId);
      if (!existing || match.confidence > existing.confidence) {
        best.set(match.entryId, match);
      }
    }
    
    return [...best.values()].sort((a, b) => b.confidence - a.confidence);
  }
}

module.exports = { SanctionsScreener };
