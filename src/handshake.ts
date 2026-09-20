import { createHash, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, type KeyObject } from 'node:crypto';
import { NoiseCipher } from './cipher.ts';
import { NoiseError } from './errors.ts';
import { MAX_FRAME_BYTES, NOISE_PROTOCOL } from './options.ts';

const EMPTY = Buffer.alloc(0);
// RFC 8410 SubjectPublicKeyInfo for a raw X25519 public key.
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');
type Phase = 'write-first' | 'read-first' | 'write-second' | 'read-second' | 'complete' | 'closed';

function hash(...parts: Buffer[]): Buffer {
  const state = createHash('sha256');
  for (const part of parts) state.update(part);
  return state.digest();
}

function derive(chainingKey: Buffer, input: Buffer, outputs: 2 | 3): Buffer[] {
  // Noise HKDF uses the chaining key as salt and empty info (Noise section 4.3).
  const material = Buffer.from(hkdfSync('sha256', input, chainingKey, EMPTY, outputs * 32));
  try { return Array.from({ length: outputs }, (_, index) => Buffer.from(material.subarray(index * 32, (index + 1) * 32))); }
  finally { material.fill(0); }
}

/** Fixed NNpsk0 only: -> psk,e; <- e,ee. No pattern interpreter or negotiation. */
export class NoiseHandshake {
  #phase: Phase;
  #chainingKey: Buffer;
  #hash: Buffer;
  #cipher: NoiseCipher | null = null;
  #ephemeral: KeyObject | null;
  #remote: Buffer | null = null;

  // Deterministic ephemeral input is internal to vector tests, never a socket option.
  constructor(private readonly initiator: boolean, psk: Uint8Array, prologue: Buffer, ephemeral?: KeyObject) {
    if (!(psk instanceof Uint8Array) || psk.byteLength !== 32) throw new TypeError('Noise PSK must be exactly 32 bytes');
    this.#phase = initiator ? 'write-first' : 'read-first';
    // This fixed protocol name is exactly HASHLEN bytes; Noise does not hash it.
    this.#hash = Buffer.from(NOISE_PROTOCOL);
    this.#chainingKey = Buffer.from(this.#hash);
    this.#ephemeral = ephemeral ?? generateKeyPairSync('x25519').privateKey;
    const key = Buffer.from(psk);
    try {
      if (this.#ephemeral.type !== 'private' || this.#ephemeral.asymmetricKeyType !== 'x25519') throw new NoiseError('PROTOCOL_ERROR');
      this.#mixHash(prologue);
      const [chainingKey, tempHash, cipherKey] = derive(this.#chainingKey, key, 3);
      this.#chainingKey.fill(0);
      this.#chainingKey = chainingKey!;
      this.#mixHash(tempHash!);
      tempHash!.fill(0);
      this.#replaceCipher(cipherKey!);
    } catch (error) { this.#fail(error); }
    finally { key.fill(0); }
  }

  get complete(): boolean { return this.#phase === 'complete'; }

  write(payload: Buffer = EMPTY): Buffer {
    try {
      if (this.#phase !== 'write-first' && this.#phase !== 'write-second') throw new NoiseError('PROTOCOL_ERROR');
      if (payload.length > MAX_FRAME_BYTES - 48) throw new NoiseError('MESSAGE_TOO_LARGE');
      const first = this.#phase === 'write-first';
      const encoded = createPublicKey(this.#ephemeral!).export({ format: 'der', type: 'spki' });
      if (encoded.length !== 44 || !encoded.subarray(0, 12).equals(X25519_SPKI)) throw new NoiseError('PROTOCOL_ERROR');
      const ephemeral = encoded.subarray(12);
      this.#mixHash(ephemeral);
      this.#mixKey(ephemeral); // The e token also mixes a key in every PSK pattern.
      if (!first) this.#mixDH();
      const encrypted = this.#cipher!.encrypt(payload, this.#hash);
      this.#mixHash(encrypted);
      this.#phase = first ? 'read-second' : 'complete';
      return Buffer.concat([ephemeral, encrypted]);
    } catch (error) { return this.#fail(error); }
  }

  read(message: Buffer): Buffer {
    try {
      if (this.#phase !== 'read-first' && this.#phase !== 'read-second') throw new NoiseError('PROTOCOL_ERROR');
      if (message.length < 48 || message.length > MAX_FRAME_BYTES) throw new NoiseError('PROTOCOL_ERROR');
      const first = this.#phase === 'read-first';
      this.#remote = Buffer.from(message.subarray(0, 32));
      this.#mixHash(this.#remote);
      this.#mixKey(this.#remote);
      if (!first) this.#mixDH();
      const ciphertext = message.subarray(32);
      const payload = this.#cipher!.decrypt(ciphertext, this.#hash);
      this.#mixHash(ciphertext);
      this.#phase = first ? 'write-second' : 'complete';
      return payload;
    } catch (error) { return this.#fail(error); }
  }

  finish(): { tx: Buffer; rx: Buffer; hash: Buffer } {
    try {
      if (!this.complete) throw new NoiseError('PROTOCOL_ERROR');
      const [first, second] = derive(this.#chainingKey, EMPTY, 2);
      const result = { tx: (this.initiator ? first : second)!, rx: (this.initiator ? second : first)!, hash: Buffer.from(this.#hash) };
      this.destroy();
      return result;
    } catch (error) { return this.#fail(error); }
  }

  destroy(): void {
    this.#phase = 'closed';
    this.#chainingKey.fill(0);
    this.#hash.fill(0);
    this.#cipher?.destroy();
    this.#cipher = null;
    this.#ephemeral = null;
    this.#remote = null;
  }

  #mixHash(data: Buffer): void {
    const next = hash(this.#hash, data);
    this.#hash.fill(0);
    this.#hash = next;
  }

  #mixKey(input: Buffer): void {
    const [chainingKey, cipherKey] = derive(this.#chainingKey, input, 2);
    this.#chainingKey.fill(0);
    this.#chainingKey = chainingKey!;
    this.#replaceCipher(cipherKey!);
  }

  #replaceCipher(key: Buffer): void {
    this.#cipher?.destroy();
    try { this.#cipher = new NoiseCipher(key); }
    finally { key.fill(0); }
  }

  #mixDH(): void {
    const publicKey = createPublicKey({ key: Buffer.concat([X25519_SPKI, this.#remote!]), format: 'der', type: 'spki' });
    const shared = diffieHellman({ privateKey: this.#ephemeral!, publicKey });
    try {
      if (shared.equals(Buffer.alloc(32))) throw new NoiseError('AUTHENTICATION_FAILED');
      this.#mixKey(shared);
    } finally { shared.fill(0); }
  }

  #fail(error: unknown): never {
    this.destroy();
    throw error instanceof NoiseError ? error : new NoiseError('AUTHENTICATION_FAILED');
  }
}
