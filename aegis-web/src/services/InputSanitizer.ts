/**
 * InputSanitizer - Production-grade input sanitization service
 *
 * Security Features:
 * - XSS prevention using DOMPurify
 * - Input validation using validator.js
 * - Protocol whitelisting
 * - Rate limiting helpers
 * - CSRF token management
 *
 * OWASP Compliance:
 * - Input Validation (OWASP ASVS 5.1)
 * - Output Encoding (OWASP ASVS 5.3)
 * - General Security (OWASP Top 10 2021)
 */

import DOMPurify from 'dompurify';
import validator from 'validator';

// ==================== TYPES ====================

export interface SanitizeOptions {
  maxLength?: number;
  allowedTags?: string[];
  allowedProtocols?: string[];
  stripAllHtml?: boolean;
}

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  sanitizedValue: string;
}

// ==================== CONSTANTS ====================

const DEFAULT_MAX_LENGTH = 10000;
const EMAIL_MAX_LENGTH = 254;
const NAME_MAX_LENGTH = 100;
const URL_MAX_LENGTH = 2048;

// Allowed URL protocols (whitelist approach)
const SAFE_PROTOCOLS = ['http:', 'https:', 'mailto:'];

// DOMPurify configuration for strict sanitization
const DOMPURIFY_CONFIG = {
  ALLOWED_TAGS: [], // No HTML tags by default
  ALLOWED_ATTR: [],
  ALLOW_DATA_ATTR: false,
  ALLOW_UNKNOWN_PROTOCOLS: false,
  SAFE_FOR_TEMPLATES: true,
  WHOLE_DOCUMENT: false,
  RETURN_DOM: false,
  RETURN_DOM_FRAGMENT: false,
  RETURN_TRUSTED_TYPE: false
};

// ==================== SANITIZATION FUNCTIONS ====================

/**
 * Sanitize any text input - removes all HTML and dangerous content
 */
export const sanitizeText = (input: string, options: SanitizeOptions = {}): string => {
  if (!input || typeof input !== 'string') return '';

  const maxLength = options.maxLength ?? DEFAULT_MAX_LENGTH;

  // First pass: DOMPurify with strict config
  let sanitized = DOMPurify.sanitize(input, {
    ...DOMPURIFY_CONFIG,
    ALLOWED_TAGS: options.allowedTags ?? []
  });

  // Remove any remaining potential XSS vectors
  sanitized = sanitized
    .replace(/javascript:/gi, '')
    .replace(/vbscript:/gi, '')
    .replace(/data:/gi, '')
    .replace(/on\w+\s*=/gi, '')
    .trim();

  // Truncate to max length
  return sanitized.slice(0, maxLength);
};

/**
 * Sanitize HTML content - allows specific safe tags
 */
export const sanitizeHtml = (
  input: string,
  allowedTags: string[] = ['b', 'i', 'em', 'strong', 'p', 'br']
): string => {
  if (!input || typeof input !== 'string') return '';

  return DOMPurify.sanitize(input, {
    ALLOWED_TAGS: allowedTags,
    ALLOWED_ATTR: ['href', 'title', 'class'],
    ALLOW_DATA_ATTR: false
  });
};

/**
 * Validate and sanitize email
 */
export const sanitizeEmail = (email: string): ValidationResult => {
  const errors: string[] = [];
  let sanitized = sanitizeText(email, { maxLength: EMAIL_MAX_LENGTH }).toLowerCase();

  if (!sanitized) {
    errors.push('Email is required');
    return { isValid: false, errors, sanitizedValue: '' };
  }

  if (!validator.isEmail(sanitized)) {
    errors.push('Invalid email format');
  }

  if (sanitized.length > EMAIL_MAX_LENGTH) {
    errors.push(`Email must be less than ${EMAIL_MAX_LENGTH} characters`);
    sanitized = sanitized.slice(0, EMAIL_MAX_LENGTH);
  }

  return {
    isValid: errors.length === 0,
    errors,
    sanitizedValue: sanitized
  };
};

/**
 * Validate and sanitize name
 */
export const sanitizeName = (name: string): ValidationResult => {
  const errors: string[] = [];
  let sanitized = sanitizeText(name, { maxLength: NAME_MAX_LENGTH });

  if (!sanitized) {
    errors.push('Name is required');
    return { isValid: false, errors, sanitizedValue: '' };
  }

  // Allow letters, spaces, hyphens, apostrophes (international names)
  const nameRegex = /^[\p{L}\s\-']+$/u;
  if (!nameRegex.test(sanitized)) {
    errors.push('Name contains invalid characters');
    // Remove invalid characters
    sanitized = sanitized.replace(/[^\p{L}\s\-']/gu, '');
  }

  if (sanitized.length < 2) {
    errors.push('Name must be at least 2 characters');
  }

  if (sanitized.length > NAME_MAX_LENGTH) {
    errors.push(`Name must be less than ${NAME_MAX_LENGTH} characters`);
    sanitized = sanitized.slice(0, NAME_MAX_LENGTH);
  }

  // No consecutive special characters
  if (/[-']{2,}/.test(sanitized)) {
    errors.push('Name cannot contain consecutive special characters');
    sanitized = sanitized.replace(/[-']{2,}/g, '-');
  }

  return {
    isValid: errors.length === 0,
    errors,
    sanitizedValue: sanitized.trim()
  };
};

/**
 * Validate and sanitize URL
 */
export const sanitizeUrl = (url: string): ValidationResult => {
  const errors: string[] = [];
  let sanitized = sanitizeText(url, { maxLength: URL_MAX_LENGTH });

  if (!sanitized) {
    return { isValid: true, errors: [], sanitizedValue: '' };
  }

  try {
    const parsed = new URL(sanitized);

    // Check protocol whitelist
    if (!SAFE_PROTOCOLS.includes(parsed.protocol)) {
      errors.push(`Invalid URL protocol. Allowed: ${SAFE_PROTOCOLS.join(', ')}`);
      return { isValid: false, errors, sanitizedValue: '' };
    }

    // Validate URL format
    if (!validator.isURL(sanitized, { protocols: ['http', 'https'], require_protocol: true })) {
      errors.push('Invalid URL format');
    }

    sanitized = parsed.toString();
  } catch {
    errors.push('Invalid URL format');
    return { isValid: false, errors, sanitizedValue: '' };
  }

  return {
    isValid: errors.length === 0,
    errors,
    sanitizedValue: sanitized
  };
};

/**
 * Validate and sanitize phone number
 */
export const sanitizePhone = (phone: string): ValidationResult => {
  const errors: string[] = [];
  let sanitized = sanitizeText(phone, { maxLength: 20 });

  if (!sanitized) {
    return { isValid: true, errors: [], sanitizedValue: '' };
  }

  // Remove all non-digit characters except + at start
  sanitized = sanitized.replace(/[^\d+]/g, '');
  if (sanitized.indexOf('+') > 0) {
    sanitized = sanitized.replace(/\+/g, '');
  }

  if (!validator.isMobilePhone(sanitized, 'any', { strictMode: false })) {
    // Allow basic phone formats even if not recognized as mobile
    if (!/^[+]?\d{7,15}$/.test(sanitized)) {
      errors.push('Invalid phone number format');
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
    sanitizedValue: sanitized
  };
};

/**
 * Validate and sanitize message/text area content
 */
export const sanitizeMessage = (
  message: string,
  options: { minLength?: number; maxLength?: number } = {}
): ValidationResult => {
  const { minLength = 10, maxLength = 5000 } = options;
  const errors: string[] = [];
  let sanitized = sanitizeText(message, { maxLength });

  if (!sanitized) {
    errors.push('Message is required');
    return { isValid: false, errors, sanitizedValue: '' };
  }

  if (sanitized.length < minLength) {
    errors.push(`Message must be at least ${minLength} characters`);
  }

  if (sanitized.length > maxLength) {
    errors.push(`Message must be less than ${maxLength} characters`);
    sanitized = sanitized.slice(0, maxLength);
  }

  return {
    isValid: errors.length === 0,
    errors,
    sanitizedValue: sanitized
  };
};

// ==================== ENCODING FUNCTIONS ====================

/**
 * HTML encode for safe output in HTML context
 */
export const encodeHtml = (str: string): string => {
  if (!str || typeof str !== 'string') return '';

  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

/**
 * URL encode for safe output in URL parameters
 */
export const encodeUrl = (str: string): string => {
  if (!str || typeof str !== 'string') return '';
  return encodeURIComponent(str);
};

/**
 * JavaScript encode for safe output in JavaScript context
 */
export const encodeJs = (str: string): string => {
  if (!str || typeof str !== 'string') return '';
  return JSON.stringify(str).slice(1, -1);
};

// ==================== RATE LIMITING ====================

interface RateLimitState {
  count: number;
  resetTime: number;
}

const rateLimitStore = new Map<string, RateLimitState>();

/**
 * Check if action is rate limited
 */
export const isRateLimited = (
  key: string,
  limit: number,
  windowMs: number
): { limited: boolean; remaining: number; resetIn: number } => {
  const now = Date.now();
  const state = rateLimitStore.get(key);

  if (!state || now >= state.resetTime) {
    rateLimitStore.set(key, { count: 1, resetTime: now + windowMs });
    return { limited: false, remaining: limit - 1, resetIn: windowMs };
  }

  if (state.count >= limit) {
    return { limited: true, remaining: 0, resetIn: state.resetTime - now };
  }

  state.count++;
  return { limited: false, remaining: limit - state.count, resetIn: state.resetTime - now };
};

/**
 * Reset rate limit for a key
 */
export const resetRateLimit = (key: string): void => {
  rateLimitStore.delete(key);
};

// ==================== CSRF ====================

let csrfToken: string | null = null;

/**
 * Initialize CSRF token
 */
export const initCsrfToken = (token: string): void => {
  csrfToken = token;
};

/**
 * Get CSRF token
 */
export const getCsrfToken = (): string | null => {
  return csrfToken;
};

/**
 * Validate CSRF token
 */
export const validateCsrfToken = (token: string): boolean => {
  if (!csrfToken || !token) return false;
  // Constant-time comparison to prevent timing attacks
  if (csrfToken.length !== token.length) return false;
  let result = 0;
  for (let i = 0; i < csrfToken.length; i++) {
    result |= csrfToken.charCodeAt(i) ^ token.charCodeAt(i);
  }
  return result === 0;
};

// ==================== HONEYPOT ====================

/**
 * Check honeypot field (should be empty if real user)
 */
export const checkHoneypot = (value: string): boolean => {
  return !value || value.trim() === '';
};

// ==================== EXPORTS ====================

export const InputSanitizer = {
  sanitizeText,
  sanitizeHtml,
  sanitizeEmail,
  sanitizeName,
  sanitizeUrl,
  sanitizePhone,
  sanitizeMessage,
  encodeHtml,
  encodeUrl,
  encodeJs,
  isRateLimited,
  resetRateLimit,
  initCsrfToken,
  getCsrfToken,
  validateCsrfToken,
  checkHoneypot
};

export default InputSanitizer;
