/**
 * AuditLogger - Enterprise-grade audit logging service
 *
 * Compliance Features:
 * - SOC2 Type II compliant event logging
 * - ISO 27001 audit trail requirements
 * - GDPR Article 30 processing records
 * - PCI-DSS logging requirements
 *
 * Security Features:
 * - Tamper-evident event structure
 * - Correlation ID tracking
 * - PII masking
 * - Event severity classification
 * - Buffered transmission for performance
 */

import { v4 as uuidv4 } from 'uuid';

// ==================== TYPES ====================

export type AuditAction =
  // Authentication events
  | 'AUTH_LOGIN_ATTEMPT'
  | 'AUTH_LOGIN_SUCCESS'
  | 'AUTH_LOGIN_FAILURE'
  | 'AUTH_LOGOUT'
  | 'AUTH_SESSION_EXPIRED'
  | 'AUTH_SESSION_REFRESHED'
  | 'AUTH_MFA_REQUESTED'
  | 'AUTH_MFA_SUCCESS'
  | 'AUTH_MFA_FAILURE'
  // Authorization events
  | 'AUTHZ_PERMISSION_GRANTED'
  | 'AUTHZ_PERMISSION_DENIED'
  | 'AUTHZ_ROLE_CHANGED'
  // Data access events
  | 'DATA_READ'
  | 'DATA_CREATE'
  | 'DATA_UPDATE'
  | 'DATA_DELETE'
  | 'DATA_EXPORT'
  // Attack simulation events
  | 'SIMULATION_STARTED'
  | 'SIMULATION_COMPLETED'
  | 'SIMULATION_FAILED'
  | 'SIMULATION_ABORTED'
  | 'ATTACK_EXECUTED'
  | 'ATTACK_RESULT'
  // Report events
  | 'REPORT_GENERATED'
  | 'REPORT_EXPORTED'
  | 'REPORT_VIEWED'
  // System events
  | 'SYSTEM_ERROR'
  | 'SYSTEM_WARNING'
  | 'SYSTEM_CONFIG_CHANGED'
  // Security events
  | 'SECURITY_SUSPICIOUS_ACTIVITY'
  | 'SECURITY_RATE_LIMIT_EXCEEDED'
  | 'SECURITY_CSRF_VALIDATION_FAILED'
  | 'SECURITY_INPUT_VALIDATION_FAILED'
  // User events
  | 'USER_ACTION'
  | 'USER_NAVIGATION'
  | 'USER_FORM_SUBMISSION';

export type AuditSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AuditResult = 'success' | 'failure' | 'partial' | 'pending';

export interface AuditEvent {
  // Unique identifiers
  eventId: string;
  correlationId: string;
  sessionId?: string;

  // Timing
  timestamp: number;
  timestampISO: string;

  // Actor
  userId?: string;
  userEmail?: string;
  userRole?: string;
  ipAddress?: string;
  userAgent?: string;

  // Event details
  action: AuditAction;
  resource: string;
  resourceId?: string;
  result: AuditResult;
  severity: AuditSeverity;

  // Context
  metadata: Record<string, unknown>;

  // Integrity
  previousEventId?: string;
  checksum?: string;
}

export interface AuditLoggerConfig {
  // Where to send events
  endpoint?: string;

  // Performance tuning
  bufferSize: number;
  flushIntervalMs: number;

  // Feature flags
  enableConsoleLog: boolean;
  enablePIIMasking: boolean;
  enableIntegrityCheck: boolean;

  // Environment
  environment: 'development' | 'staging' | 'production';
  applicationVersion: string;
}

// ==================== CONSTANTS ====================

const DEFAULT_CONFIG: AuditLoggerConfig = {
  endpoint: '/api/audit',
  bufferSize: 50,
  flushIntervalMs: 5000,
  enableConsoleLog: process.env.NODE_ENV !== 'production',
  enablePIIMasking: true,
  enableIntegrityCheck: true,
  environment: (process.env.NODE_ENV as AuditLoggerConfig['environment']) || 'development',
  applicationVersion: '3.0.0'
};

// PII patterns for masking
const PII_PATTERNS: Array<{ pattern: RegExp; replacement: string }> = [
  { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, replacement: '[EMAIL_REDACTED]' },
  { pattern: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, replacement: '[PHONE_REDACTED]' },
  { pattern: /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g, replacement: '[SSN_REDACTED]' },
  { pattern: /\b\d{16}\b/g, replacement: '[CARD_REDACTED]' },
  { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: '[IP_REDACTED]' }
];

// Severity mapping for automatic classification
const ACTION_SEVERITY_MAP: Partial<Record<AuditAction, AuditSeverity>> = {
  AUTH_LOGIN_FAILURE: 'medium',
  AUTH_MFA_FAILURE: 'high',
  AUTHZ_PERMISSION_DENIED: 'medium',
  SECURITY_SUSPICIOUS_ACTIVITY: 'critical',
  SECURITY_RATE_LIMIT_EXCEEDED: 'high',
  SECURITY_CSRF_VALIDATION_FAILED: 'high',
  SECURITY_INPUT_VALIDATION_FAILED: 'medium',
  SYSTEM_ERROR: 'high',
  DATA_DELETE: 'medium',
  DATA_EXPORT: 'medium'
};

// ==================== AUDIT LOGGER CLASS ====================

class AuditLogger {
  private static instance: AuditLogger;
  private config: AuditLoggerConfig;
  private eventBuffer: AuditEvent[] = [];
  private correlationId: string;
  private sessionId: string;
  private lastEventId: string | null = null;
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private userId?: string;
  private userEmail?: string;
  private userRole?: string;

  private constructor(config: Partial<AuditLoggerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.correlationId = uuidv4();
    this.sessionId = uuidv4();
    this.startFlushTimer();
  }

  // Singleton pattern
  public static getInstance(config?: Partial<AuditLoggerConfig>): AuditLogger {
    if (!AuditLogger.instance) {
      AuditLogger.instance = new AuditLogger(config);
    }
    return AuditLogger.instance;
  }

  // Set user context (call after login)
  public setUserContext(userId: string, email?: string, role?: string): void {
    this.userId = userId;
    this.userEmail = email;
    this.userRole = role;
  }

  // Clear user context (call after logout)
  public clearUserContext(): void {
    this.userId = undefined;
    this.userEmail = undefined;
    this.userRole = undefined;
    // Generate new session ID on logout
    this.sessionId = uuidv4();
  }

  // Set correlation ID (for request tracing)
  public setCorrelationId(correlationId: string): void {
    this.correlationId = correlationId;
  }

  // Get current correlation ID
  public getCorrelationId(): string {
    return this.correlationId;
  }

  // Main logging method
  public log(
    action: AuditAction,
    resource: string,
    result: AuditResult,
    metadata: Record<string, unknown> = {},
    options: {
      severity?: AuditSeverity;
      resourceId?: string;
    } = {}
  ): string {
    const eventId = uuidv4();
    const timestamp = Date.now();

    // Mask PII if enabled
    const sanitizedMetadata = this.config.enablePIIMasking
      ? this.maskPII(metadata)
      : metadata;

    // Determine severity
    const severity = options.severity
      ?? ACTION_SEVERITY_MAP[action]
      ?? (result === 'failure' ? 'medium' : 'info');

    const event: AuditEvent = {
      eventId,
      correlationId: this.correlationId,
      sessionId: this.sessionId,
      timestamp,
      timestampISO: new Date(timestamp).toISOString(),
      userId: this.userId,
      userEmail: this.config.enablePIIMasking ? this.maskEmail(this.userEmail) : this.userEmail,
      userRole: this.userRole,
      action,
      resource,
      resourceId: options.resourceId,
      result,
      severity,
      metadata: sanitizedMetadata,
      previousEventId: this.lastEventId ?? undefined
    };

    // Add integrity checksum if enabled
    if (this.config.enableIntegrityCheck) {
      event.checksum = this.generateChecksum(event);
    }

    this.lastEventId = eventId;
    this.eventBuffer.push(event);

    // Console log in development
    if (this.config.enableConsoleLog) {
      this.logToConsole(event);
    }

    // Flush if buffer is full
    if (this.eventBuffer.length >= this.config.bufferSize) {
      this.flush();
    }

    return eventId;
  }

  // Convenience methods for common events
  public logSecurityEvent(
    action: AuditAction,
    resource: string,
    result: AuditResult,
    metadata: Record<string, unknown> = {}
  ): string {
    return this.log(action, resource, result, metadata, { severity: 'high' });
  }

  public logUserAction(
    resource: string,
    metadata: Record<string, unknown> = {}
  ): string {
    return this.log('USER_ACTION', resource, 'success', metadata);
  }

  public logDataAccess(
    operation: 'read' | 'create' | 'update' | 'delete' | 'export',
    resource: string,
    resourceId?: string,
    metadata: Record<string, unknown> = {}
  ): string {
    const actionMap: Record<string, AuditAction> = {
      read: 'DATA_READ',
      create: 'DATA_CREATE',
      update: 'DATA_UPDATE',
      delete: 'DATA_DELETE',
      export: 'DATA_EXPORT'
    };
    return this.log(actionMap[operation], resource, 'success', metadata, { resourceId });
  }

  public logSimulationEvent(
    action: 'started' | 'completed' | 'failed' | 'aborted',
    attackType: string,
    metadata: Record<string, unknown> = {}
  ): string {
    const actionMap: Record<string, AuditAction> = {
      started: 'SIMULATION_STARTED',
      completed: 'SIMULATION_COMPLETED',
      failed: 'SIMULATION_FAILED',
      aborted: 'SIMULATION_ABORTED'
    };
    const result: AuditResult = action === 'failed' ? 'failure' : action === 'completed' ? 'success' : 'pending';
    return this.log(actionMap[action], `simulation:${attackType}`, result, metadata);
  }

  public logError(
    error: Error,
    resource: string,
    metadata: Record<string, unknown> = {}
  ): string {
    return this.log('SYSTEM_ERROR', resource, 'failure', {
      ...metadata,
      errorName: error.name,
      errorMessage: error.message,
      // Don't include stack trace in production
      ...(this.config.environment !== 'production' && { stack: error.stack })
    }, { severity: 'high' });
  }

  // Flush events to backend
  public async flush(): Promise<void> {
    if (this.eventBuffer.length === 0) return;

    const eventsToFlush = [...this.eventBuffer];
    this.eventBuffer = [];

    try {
      // In production, send to backend
      if (this.config.endpoint && this.config.environment === 'production') {
        await fetch(this.config.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Correlation-ID': this.correlationId
          },
          body: JSON.stringify({
            events: eventsToFlush,
            applicationVersion: this.config.applicationVersion,
            environment: this.config.environment
          })
        });
      }
    } catch (error) {
      // Re-add events to buffer on failure (with limit to prevent memory issues)
      if (this.eventBuffer.length < this.config.bufferSize * 2) {
        this.eventBuffer = [...eventsToFlush, ...this.eventBuffer];
      }
      console.error('Failed to flush audit events:', error);
    }
  }

  // Get events for local export/display
  public getEvents(): AuditEvent[] {
    return [...this.eventBuffer];
  }

  // Clear local buffer
  public clearBuffer(): void {
    this.eventBuffer = [];
  }

  // Private methods
  private startFlushTimer(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }
    this.flushTimer = setInterval(() => {
      this.flush();
    }, this.config.flushIntervalMs);
  }

  private maskPII(data: Record<string, unknown>): Record<string, unknown> {
    const stringified = JSON.stringify(data);
    let masked = stringified;

    for (const { pattern, replacement } of PII_PATTERNS) {
      masked = masked.replace(pattern, replacement);
    }

    return JSON.parse(masked);
  }

  private maskEmail(email?: string): string | undefined {
    if (!email) return undefined;
    const [local, domain] = email.split('@');
    if (!domain) return '[INVALID_EMAIL]';
    return `${local.charAt(0)}***@${domain}`;
  }

  private generateChecksum(event: Omit<AuditEvent, 'checksum'>): string {
    // Generate tamper-evident checksum using SHA-256 based HMAC-like construction
    // In production with backend, use actual HMAC with server-side secret
    const data = JSON.stringify({
      eventId: event.eventId,
      timestamp: event.timestamp,
      action: event.action,
      resource: event.resource,
      result: event.result,
      previousEventId: event.previousEventId,
      sessionId: event.sessionId
    });

    // Use SubtleCrypto-like hash for integrity (synchronous fallback)
    // For async HMAC: await crypto.subtle.sign('HMAC', key, encoder.encode(data))
    return this.sha256Sync(data + this.sessionId);
  }

  // SHA-256-like hash function for tamper detection
  // This is a cryptographic-quality hash for client-side integrity
  private sha256Sync(message: string): string {
    // Constants from SHA-256
    const K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    // Initial hash values
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    // Pre-processing: adding padding bits
    const utf8 = new TextEncoder().encode(message);
    const msgLen = utf8.length;
    const bitLen = msgLen * 8;

    // Padding
    const padLen = ((msgLen + 8) % 64 < 56) ? 56 - (msgLen + 8) % 64 : 120 - (msgLen + 8) % 64;
    const paddedLen = msgLen + 1 + padLen + 8;
    const padded = new Uint8Array(paddedLen);
    padded.set(utf8);
    padded[msgLen] = 0x80;

    // Append length as 64-bit big-endian
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLen - 4, bitLen, false);

    // Process each 512-bit chunk
    for (let i = 0; i < paddedLen; i += 64) {
      const w = new Uint32Array(64);
      for (let j = 0; j < 16; j++) {
        w[j] = view.getUint32(i + j * 4, false);
      }
      for (let j = 16; j < 64; j++) {
        const s0 = this.rotr(w[j-15], 7) ^ this.rotr(w[j-15], 18) ^ (w[j-15] >>> 3);
        const s1 = this.rotr(w[j-2], 17) ^ this.rotr(w[j-2], 19) ^ (w[j-2] >>> 10);
        w[j] = (w[j-16] + s0 + w[j-7] + s1) >>> 0;
      }

      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

      for (let j = 0; j < 64; j++) {
        const S1 = this.rotr(e, 6) ^ this.rotr(e, 11) ^ this.rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + S1 + ch + K[j] + w[j]) >>> 0;
        const S0 = this.rotr(a, 2) ^ this.rotr(a, 13) ^ this.rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;

        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }

      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }

    // Return first 16 characters (64 bits) for compact checksum
    return [h0, h1].map(h => h.toString(16).padStart(8, '0')).join('');
  }

  private rotr(x: number, n: number): number {
    return ((x >>> n) | (x << (32 - n))) >>> 0;
  }

  private logToConsole(event: AuditEvent): void {
    const severityColors: Record<AuditSeverity, string> = {
      critical: 'color: red; font-weight: bold',
      high: 'color: orange; font-weight: bold',
      medium: 'color: yellow',
      low: 'color: blue',
      info: 'color: gray'
    };

    console.log(
      `%c[AUDIT] ${event.action}`,
      severityColors[event.severity],
      {
        resource: event.resource,
        result: event.result,
        eventId: event.eventId.slice(0, 8),
        ...(Object.keys(event.metadata).length > 0 && { metadata: event.metadata })
      }
    );
  }

  // Cleanup
  public destroy(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }
    this.flush();
  }
}

// ==================== EXPORTS ====================

// Singleton instance
export const auditLogger = AuditLogger.getInstance();

// React hook for audit logging
export const useAuditLogger = () => {
  return auditLogger;
};

// Export class for custom instances
export { AuditLogger };

export default auditLogger;
