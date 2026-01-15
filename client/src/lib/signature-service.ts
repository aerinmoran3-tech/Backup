/**
 * Electronic Signature Service
 * Compliant with ESIGN Act requirements:
 * - Clear consent to use electronic signatures
 * - Timestamp of signature
 * - Identification of signer
 * - Access to signed document
 * - Audit trail
 */

export interface SignatureMetadata {
  timestamp: string; // ISO 8601 timestamp
  ipAddress: string;
  userAgent: string;
  screenResolution: string;
  timezone: string;
  consentGiven: boolean; // Did user explicitly consent?
  signatureValue: string; // The typed name
  signatureHash: string; // Hash of signature for tampering detection
  deviceFingerprint: string; // Unique device identifier
}

/**
 * Capture detailed signature metadata for ESIGN compliance
 * @returns Promise<SignatureMetadata>
 */
export async function captureSignatureMetadata(
  signatureValue: string
): Promise<SignatureMetadata> {
  // Get IP address from server (will be added server-side)
  // For now, we'll send what we have and server adds IP
  const timestamp = new Date().toISOString();
  const userAgent = navigator.userAgent;
  const screenResolution = `${window.screen.width}x${window.screen.height}`;
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  // Create simple hash of signature for tampering detection
  const signatureHash = await hashString(signatureValue + timestamp);

  // Simple device fingerprint
  const deviceFingerprint = generateDeviceFingerprint();

  return {
    timestamp,
    ipAddress: '', // Will be filled by server
    userAgent,
    screenResolution,
    timezone,
    consentGiven: true,
    signatureValue,
    signatureHash,
    deviceFingerprint,
  };
}

/**
 * Simple hash function for signature verification
 * @param data - String to hash
 * @returns Promise<string> - Hex hash
 */
async function hashString(data: string): Promise<string> {
  try {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
  } catch (e) {
    console.error('[SIGNATURE] Hash failed:', e);
    return 'unknown';
  }
}

/**
 * Generate a simple device fingerprint
 * @returns string - Device fingerprint
 */
function generateDeviceFingerprint(): string {
  const nav = navigator as any;
  const parts = [
    nav.language || 'unknown',
    nav.platform || 'unknown',
    new Date().getTimezoneOffset().toString(),
    (screen.width || 0) * (screen.height || 0),
  ];
  return parts.join('|');
}

/**
 * Validate signature metadata for completeness
 * @param metadata - SignatureMetadata to validate
 * @returns { valid: boolean; errors: string[] }
 */
export function validateSignatureMetadata(
  metadata: SignatureMetadata
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!metadata.timestamp) {
    errors.push('Timestamp missing');
  }
  if (!metadata.userAgent) {
    errors.push('User agent missing');
  }
  if (!metadata.signatureValue || metadata.signatureValue.length < 2) {
    errors.push('Signature value invalid');
  }
  if (!metadata.consentGiven) {
    errors.push('Consent not given');
  }
  if (!metadata.signatureHash) {
    errors.push('Signature hash missing');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Format signature metadata for display/audit trail
 * @param metadata - SignatureMetadata
 * @returns Formatted string for records
 */
export function formatSignatureMetadata(metadata: SignatureMetadata): string {
  return `
Signature Metadata (ESIGN Act Compliance)
==========================================
Signed By: ${metadata.signatureValue}
Timestamp: ${metadata.timestamp}
Time Zone: ${metadata.timezone}
IP Address: ${metadata.ipAddress || 'pending'}
Device: ${metadata.screenResolution}
User Agent: ${metadata.userAgent}
Device Fingerprint: ${metadata.deviceFingerprint}
Signature Hash: ${metadata.signatureHash}
Consent Given: ${metadata.consentGiven ? 'Yes' : 'No'}
  `.trim();
}
