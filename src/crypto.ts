import { NoiseHandshake } from './handshake.ts';
import { NoiseCipher } from './cipher.ts';
import { NoiseError } from './errors.ts';

export class NoiseCrypto {
  #handshake: NoiseHandshake | null;
  #sendCipher: NoiseCipher | null = null;
  #receiveCipher: NoiseCipher | null = null;

  constructor(initiator: boolean, psk: Uint8Array, prologue: Buffer, private readonly recordLimit: number) {
    this.#handshake = new NoiseHandshake(initiator, psk, prologue);
  }

  get sendRemaining(): number { return this.#sendCipher?.remaining ?? 0; }

  sendHandshake(): Buffer {
    try {
      if (!this.#handshake) throw new NoiseError('PROTOCOL_ERROR');
      const result = this.#handshake.write();
      this.#split();
      return result;
    } catch (error) {
      this.destroy();
      throw error;
    }
  }

  receiveHandshake(frame: Buffer): void {
    try {
      if (!this.#handshake) throw new NoiseError('PROTOCOL_ERROR');
      const payload = this.#handshake.read(frame);
      if (payload.byteLength !== 0) throw new NoiseError('PROTOCOL_ERROR');
      this.#split();
    } catch (error) {
      this.destroy();
      throw error;
    }
  }

  encrypt(plaintext: Buffer): Buffer {
    try {
      if (!this.#sendCipher) throw new NoiseError('NOT_OPEN');
      return this.#sendCipher.encrypt(plaintext);
    } catch (error) {
      this.destroy();
      throw error;
    }
  }

  decrypt(ciphertext: Buffer): Buffer {
    try {
      if (!this.#receiveCipher) throw new NoiseError('NOT_OPEN');
      return this.#receiveCipher.decrypt(ciphertext);
    } catch (error) {
      this.destroy();
      throw error;
    }
  }

  destroy(): void {
    this.#sendCipher?.destroy();
    this.#receiveCipher?.destroy();
    this.#receiveCipher = null;
    this.#sendCipher = null;
    this.#handshake?.destroy();
    this.#handshake = null;
  }

  #split(): void {
    if (!this.#handshake?.complete) return;
    const keys = this.#handshake.finish();
    this.#handshake = null;
    try {
      this.#sendCipher = new NoiseCipher(keys.tx, this.recordLimit);
      this.#receiveCipher = new NoiseCipher(keys.rx, this.recordLimit);
    } finally {
      keys.tx.fill(0);
      keys.rx.fill(0);
      keys.hash.fill(0);
    }
  }
}
