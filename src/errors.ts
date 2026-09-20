const messages = {
  AUTHENTICATION_FAILED: 'Noise authentication failed',
  PROTOCOL_ERROR: 'Invalid encrypted WebSocket protocol message',
  HANDSHAKE_TIMEOUT: 'Noise handshake timed out',
  MESSAGE_TIMEOUT: 'Encrypted message assembly timed out',
  MESSAGE_TOO_LARGE: 'Message exceeds the configured size limit',
  BACKPRESSURE: 'Encrypted WebSocket buffer limit exceeded',
  RECORD_LIMIT: 'Noise record limit reached; reconnect with fresh keys',
  TRANSPORT_ERROR: 'WebSocket transport failed',
  TRANSPORT_CLOSED: 'WebSocket closed without an authenticated close record',
  HANDLER_ERROR: 'Encrypted WebSocket handler failed',
  NOT_OPEN: 'Encrypted WebSocket is not open',
  CLOSED: 'Encrypted WebSocket is closed',
} as const;

export type NoiseErrorCode = keyof typeof messages;

export class NoiseError extends Error {
  override readonly name = 'NoiseError';
  constructor(readonly code: NoiseErrorCode) { super(messages[code]); }
}
