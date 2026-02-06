/**
 * Logger
 * 
 * Structured JSON logging via Pino. Redacts sensitive fields
 * (account numbers, API keys) from all log output.
 */

const pino = require("pino");

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  
  redact: {
    paths: [
      "req.headers.authorization",
      "*.accountNumber",
      "*.iban",
      "*.apiKey",
      "*.password",
      "*.beneficiary.name",
      "*.sender.name"
    ],
    censor: "[REDACTED]"
  },
  
  serializers: {
    err: pino.stdSerializers.err,
    req: (req) => ({
      method: req.method,
      url: req.url,
      requestId: req.id,
      remoteAddress: req.ip
    }),
    res: (res) => ({
      statusCode: res.statusCode
    })
  },
  
  transport: process.env.NODE_ENV !== "production"
    ? { target: "pino-pretty", options: { colorize: true } }
    : undefined,
    
  timestamp: pino.stdTimeFunctions.isoTime
});

module.exports = logger;
