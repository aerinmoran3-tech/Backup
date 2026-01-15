/**
 * Client-side encryption utility for sensitive PII (SSN, DOB, etc.)
 * Uses base64 encoding as a minimal obfuscation layer during transmission.
 * Full encryption happens server-side before database storage.
 * 
 * IMPORTANT: This provides transport-layer obfuscation only.
 * For true security, use HTTPS (which you must already have).
 * The server will perform actual encryption before storage.
 */

/**
 * Simple base64 encoding for client-side obfuscation
 * Transforms "123-45-6789" -> "MTIzLTQ1LTY3ODk="
 * @param data - Raw SSN or sensitive data
 * @returns Base64 encoded version
 */
export function encodeForTransmission(data: string): string {
  if (!data) return '';
  try {
    return btoa(encodeURIComponent(data));
  } catch (e) {
    console.error('[CLIENT_ENCRYPTION] Failed to encode data for transmission', e);
    return data; // Fallback to original if encoding fails
  }
}

/**
 * Decode base64 on client (used internally)
 * @param encoded - Base64 encoded data
 * @returns Decoded original data
 */
export function decodeFromTransmission(encoded: string): string {
  if (!encoded) return '';
  try {
    return decodeURIComponent(atob(encoded));
  } catch (e) {
    console.error('[CLIENT_ENCRYPTION] Failed to decode data', e);
    return encoded; // Fallback if decoding fails
  }
}

/**
 * Clean SSN by removing non-numeric characters for transmission
 * @param ssn - Raw SSN (123-45-6789 or 12345678 9 format)
 * @returns Cleaned SSN with only digits
 */
export function cleanSSN(ssn: string): string {
  if (!ssn) return '';
  return ssn.replace(/\D/g, '');
}

/**
 * Prepare SSN for secure transmission
 * 1. Remove formatting
 * 2. Validate length
 * 3. Encode for transport
 * @param ssn - Raw SSN input from user
 * @returns Encoded SSN ready for transmission or error message
 */
export function encodeSSNForTransmission(ssn: string): { encoded: string; error?: string } {
  if (!ssn) {
    return { encoded: '', error: 'SSN is required' };
  }

  const cleaned = cleanSSN(ssn);
  
  if (cleaned.length !== 9) {
    return { encoded: '', error: 'SSN must be 9 digits' };
  }

  if (/^(\d)\1{8}$/.test(cleaned)) {
    return { encoded: '', error: 'Invalid SSN format' };
  }

  return { encoded: encodeForTransmission(cleaned) };
}

/**
 * Mark field as containing sensitive data that should be encrypted
 * Used for form field tracking
 */
export const SENSITIVE_FIELDS = ['ssn', 'socialSecurityNumber', 'dateOfBirth'];

/**
 * Check if a field contains sensitive data
 * @param fieldName - Name of the form field
 * @returns true if field is sensitive
 */
export function isSensitiveField(fieldName: string): boolean {
  return SENSITIVE_FIELDS.some(name => 
    fieldName.toLowerCase().includes(name.toLowerCase())
  );
}
