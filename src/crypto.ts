import { NoiseHandshake } from './handshake.ts';
import { NoiseCipher } from './cipher.ts';
import { NoiseError } from './errors.ts';

export class NoiseCrypto {
  #handshake: NoiseHandshake | null;
  #send: NoiseCipher | null = null;
  #receive: NoiseCipher | null = null;

  constructor(initiator: boolean, psk: Uint8Array, prologue: Buffer, private readonly recordLimit: number) {
    this.#handshake = new NoiseHandshake(initiator, psk, prologue);
  }

  get sendRemaining(): number { return this.#send?.remaining ?? 0; }

  sendHandshake(): Buffer {
    try {
      if (!this.#handshake) throw new NoiseError('PROTOCOL_ERROR');
      const result = this.#handshake.write();
      this.#split();
      return result;
    } catch (error) { this.destroy(); throw error; }
  }

  receiveHandshake(frame: Buffer): void {
    try {
      if (!this.#handshake) throw new NoiseError('PROTOCOL_ERROR');
      const payload = this.#handshake.read(frame);
      if (payload.byteLength !== 0) throw new NoiseError('PROTOCOL_ERROR');
      this.#split();
    } catch (error) { this.destroy(); throw error; }
  }

  encrypt(plaintext: Buffer): Buffer {
    try {
      if (!this.#send) throw new NoiseError('NOT_OPEN');
      return this.#send.encrypt(plaintext);
    } catch (error) { this.destroy(); throw error; }
  }

  decrypt(ciphertext: Buffer): Buffer {
    try {
      if (!this.#receive) throw new NoiseError('NOT_OPEN');
      return this.#receive.decrypt(ciphertext);
    } catch (error) { this.destroy(); throw error; }
  }

  destroy(): void {
    this.#send?.destroy();
    this.#receive?.destroy();
    this.#send = this.#receive = null;
    this.#handshake?.destroy();
    this.#handshake = null;
  }

  #split(): void {
    if (!this.#handshake?.complete) return;
    const keys = this.#handshake.finish();
    this.#handshake = null;
    try {
      this.#send = new NoiseCipher(keys.tx, this.recordLimit);
      this.#receive = new NoiseCipher(keys.rx, this.recordLimit);
    } finally { keys.tx.fill(0); keys.rx.fill(0); keys.hash.fill(0); }
  }
}
