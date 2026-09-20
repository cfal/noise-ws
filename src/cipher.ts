import { createCipheriv, createDecipheriv } from 'node:crypto';
import { NoiseError } from './errors.ts';
import { MAX_FRAME_BYTES, MAX_RECORDS_PER_DIRECTION } from './options.ts';

const EMPTY = Buffer.alloc(0);

/** Noise AESGCM: 32 zero bits followed by a big-endian 64-bit counter. */
export class NoiseCipher {
  #key: Buffer | null;
  #counter = 0;

  constructor(key: Uint8Array, private readonly limit = MAX_RECORDS_PER_DIRECTION) {
    if (key.byteLength !== 32 || !Number.isSafeInteger(limit) || limit < 1 || limit > MAX_RECORDS_PER_DIRECTION) {
      throw new TypeError('Invalid Noise cipher configuration');
    }
    this.#key = Buffer.from(key);
  }

  get remaining(): number { return this.#key ? this.limit - this.#counter : 0; }

  encrypt(plaintext: Buffer, additionalData: Buffer = EMPTY): Buffer {
    try {
      const nonce = this.#nonce();
      if (plaintext.length > MAX_FRAME_BYTES - 16) throw new NoiseError('MESSAGE_TOO_LARGE');
      const cipher = createCipheriv('aes-256-gcm', this.#key!, nonce, { authTagLength: 16 });
      cipher.setAAD(additionalData);
      const result = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
      this.#counter++;
      return result;
    } catch (error) {
      this.destroy();
      throw error instanceof NoiseError ? error : new NoiseError('AUTHENTICATION_FAILED');
    }
  }

  decrypt(ciphertext: Buffer, additionalData: Buffer = EMPTY): Buffer {
    let plaintext: Buffer | undefined;
    try {
      const nonce = this.#nonce();
      if (ciphertext.length < 16 || ciphertext.length > MAX_FRAME_BYTES) throw new NoiseError('PROTOCOL_ERROR');
      const cipher = createDecipheriv('aes-256-gcm', this.#key!, nonce, { authTagLength: 16 });
      cipher.setAAD(additionalData);
      cipher.setAuthTag(ciphertext.subarray(-16));
      plaintext = cipher.update(ciphertext.subarray(0, -16));
      cipher.final();
      this.#counter++;
      return plaintext;
    } catch (error) {
      // update() can produce bytes before final() authenticates them.
      plaintext?.fill(0);
      this.destroy();
      throw error instanceof NoiseError ? error : new NoiseError('AUTHENTICATION_FAILED');
    }
  }

  destroy(): void {
    this.#key?.fill(0);
    this.#key = null;
  }

  #nonce(): Buffer {
    if (!this.#key) throw new NoiseError('CLOSED');
    if (this.#counter >= this.limit) throw new NoiseError('RECORD_LIMIT');
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64BE(BigInt(this.#counter), 4);
    return nonce;
  }
}
