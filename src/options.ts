import type { NoiseWebSocket } from './connection.ts';
import type { NoiseError } from './errors.ts';

export const NOISE_PROTOCOL = 'Noise_NNpsk0_25519_AESGCM_SHA256';
export const MAX_FRAME_BYTES = 65_535;
export const MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
// Reconnect well before Noise's nonce/data-volume limits: at most 1 TiB per AES-GCM key.
export const MAX_RECORDS_PER_DIRECTION = 2 ** 24;

export interface NoiseCloseInfo {
  /** True only when the peer's encrypted close record was received. Not a delivery receipt. */
  readonly authenticated: boolean;
  readonly error: NoiseError | null;
}

export interface NoiseLimits {
  readonly handshakeTimeoutMs?: number;
  readonly messageTimeoutMs?: number;
  readonly maxMessageBytes?: number;
  readonly maxBufferedBytes?: number;
  readonly maxRecordsPerDirection?: number;
}

export interface NoiseOptions {
  /** Exactly 32 cryptographically random bytes, provisioned out of band. Not a password. */
  readonly psk: Uint8Array;
  /** Must match on both peers. Bind this connection to its application/protocol. */
  readonly context: string;
  readonly limits?: NoiseLimits;
  readonly onMessage: (socket: NoiseWebSocket, message: string | Uint8Array) => void;
  readonly onOpen?: (socket: NoiseWebSocket) => void;
  readonly onError?: (socket: NoiseWebSocket, error: NoiseError) => void;
  readonly onClose?: (socket: NoiseWebSocket, info: NoiseCloseInfo) => void;
}

export function resolveLimits(limits: NoiseLimits = {}): Required<NoiseLimits> {
  const resolved = {
    handshakeTimeoutMs: limits.handshakeTimeoutMs ?? 5_000,
    messageTimeoutMs: limits.messageTimeoutMs ?? 30_000,
    maxMessageBytes: limits.maxMessageBytes ?? MAX_MESSAGE_BYTES,
    maxBufferedBytes: limits.maxBufferedBytes ?? 32 * 1024 * 1024,
    maxRecordsPerDirection: limits.maxRecordsPerDirection ?? MAX_RECORDS_PER_DIRECTION,
  };
  for (const [key, value] of Object.entries(resolved)) {
    if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`Invalid Noise limit: ${key}`);
  }
  if (resolved.maxMessageBytes > MAX_MESSAGE_BYTES
    || resolved.maxBufferedBytes < MAX_FRAME_BYTES || resolved.maxBufferedBytes > 128 * 1024 * 1024
    || resolved.maxRecordsPerDirection < 2 || resolved.maxRecordsPerDirection > MAX_RECORDS_PER_DIRECTION
    || resolved.handshakeTimeoutMs > 2 ** 31 - 1 || resolved.messageTimeoutMs > 2 ** 31 - 1) {
    throw new TypeError('Noise limits exceed supported bounds');
  }
  return resolved;
}

export function connectionPrologue(context: string): Buffer {
  if (typeof context !== 'string' || !context.isWellFormed() || context.length === 0 || Buffer.byteLength(context) > 1024) {
    throw new TypeError('Noise context must contain 1 to 1024 UTF-8 bytes');
  }
  const bytes = Buffer.from(context);
  const header = Buffer.alloc(3);
  header[0] = 1;
  header.writeUInt16BE(bytes.length, 1);
  return Buffer.concat([Buffer.from('cfal/noise-ws\0'), header, bytes]);
}
