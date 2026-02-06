/**
 * Currency Utilities
 * 
 * ISO 4217 currency handling. Decimal precision per currency,
 * formatting, and validation. All monetary math uses integer
 * minor units (cents/pence) to avoid floating point errors.
 */

// ISO 4217 currency definitions with decimal places
const CURRENCIES = {
  USD: { code: "USD", name: "US Dollar", decimals: 2, symbol: "$" },
  EUR: { code: "EUR", name: "Euro", decimals: 2, symbol: "€" },
  GBP: { code: "GBP", name: "British Pound", decimals: 2, symbol: "£" },
  JPY: { code: "JPY", name: "Japanese Yen", decimals: 0, symbol: "¥" },
  CHF: { code: "CHF", name: "Swiss Franc", decimals: 2, symbol: "CHF" },
  CAD: { code: "CAD", name: "Canadian Dollar", decimals: 2, symbol: "CA$" },
  AUD: { code: "AUD", name: "Australian Dollar", decimals: 2, symbol: "A$" },
  CNY: { code: "CNY", name: "Chinese Yuan", decimals: 2, symbol: "¥" },
  HKD: { code: "HKD", name: "Hong Kong Dollar", decimals: 2, symbol: "HK$" },
  SGD: { code: "SGD", name: "Singapore Dollar", decimals: 2, symbol: "S$" },
  SEK: { code: "SEK", name: "Swedish Krona", decimals: 2, symbol: "kr" },
  NOK: { code: "NOK", name: "Norwegian Krone", decimals: 2, symbol: "kr" },
  DKK: { code: "DKK", name: "Danish Krone", decimals: 2, symbol: "kr" },
  PLN: { code: "PLN", name: "Polish Zloty", decimals: 2, symbol: "zł" },
  CZK: { code: "CZK", name: "Czech Koruna", decimals: 2, symbol: "Kč" },
  INR: { code: "INR", name: "Indian Rupee", decimals: 2, symbol: "₹" },
  BRL: { code: "BRL", name: "Brazilian Real", decimals: 2, symbol: "R$" },
  MXN: { code: "MXN", name: "Mexican Peso", decimals: 2, symbol: "MX$" },
  KRW: { code: "KRW", name: "South Korean Won", decimals: 0, symbol: "₩" },
  ZAR: { code: "ZAR", name: "South African Rand", decimals: 2, symbol: "R" },
  AED: { code: "AED", name: "UAE Dirham", decimals: 2, symbol: "د.إ" },
  SAR: { code: "SAR", name: "Saudi Riyal", decimals: 2, symbol: "﷼" },
  TRY: { code: "TRY", name: "Turkish Lira", decimals: 2, symbol: "₺" },
  THB: { code: "THB", name: "Thai Baht", decimals: 2, symbol: "฿" },
  NZD: { code: "NZD", name: "New Zealand Dollar", decimals: 2, symbol: "NZ$" },
  ILS: { code: "ILS", name: "Israeli Shekel", decimals: 2, symbol: "₪" },
  BHD: { code: "BHD", name: "Bahraini Dinar", decimals: 3, symbol: "BD" },
  KWD: { code: "KWD", name: "Kuwaiti Dinar", decimals: 3, symbol: "KD" },
  OMR: { code: "OMR", name: "Omani Rial", decimals: 3, symbol: "OMR" },
};

/**
 * Convert major units (e.g., 100.50 EUR) to minor units (10050 cents)
 * All internal math uses minor units to avoid floating point errors
 */
function toMinorUnits(amount, currencyCode) {
  const currency = CURRENCIES[currencyCode];
  if (!currency) throw new Error(`Unknown currency: ${currencyCode}`);
  
  const multiplier = Math.pow(10, currency.decimals);
  return Math.round(amount * multiplier);
}

/**
 * Convert minor units back to major units for display
 */
function toMajorUnits(minorAmount, currencyCode) {
  const currency = CURRENCIES[currencyCode];
  if (!currency) throw new Error(`Unknown currency: ${currencyCode}`);
  
  const divisor = Math.pow(10, currency.decimals);
  return minorAmount / divisor;
}

/**
 * Format amount for display: "€1,234.56" or "¥1,234"
 */
function formatAmount(amount, currencyCode) {
  const currency = CURRENCIES[currencyCode];
  if (!currency) throw new Error(`Unknown currency: ${currencyCode}`);
  
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currencyCode,
    minimumFractionDigits: currency.decimals,
    maximumFractionDigits: currency.decimals
  }).format(amount);
}

/**
 * Apply FX markup in basis points
 * 50 bps = 0.50% spread
 */
function applyMarkup(rate, markupBps) {
  return rate * (1 - markupBps / 10000);
}

function isValidCurrency(code) {
  return code in CURRENCIES;
}

function getCurrencyDecimals(code) {
  const currency = CURRENCIES[code];
  return currency ? currency.decimals : null;
}

module.exports = {
  CURRENCIES,
  toMinorUnits,
  toMajorUnits,
  formatAmount,
  applyMarkup,
  isValidCurrency,
  getCurrencyDecimals
};
