import { NoiseError } from './errors.ts';
import { MAX_FRAME_BYTES } from './options.ts';

export const CLIENT_READY = 1;
export const SERVER_READY = 2;
export const CLOSE = 3;
const TEXT = 16;
const BINARY = 17;
const CONTINUE = 18;
const FIRST_PAYLOAD_BYTES = MAX_FRAME_BYTES - 16 - 5;
const NEXT_PAYLOAD_BYTES = MAX_FRAME_BYTES - 16 - 1;

export function recordCount(length: number): number {
  return 1 + Math.ceil(Math.max(0, length - FIRST_PAYLOAD_BYTES) / NEXT_PAYLOAD_BYTES);
}

export function encodedBytes(length: number): number {
  const count = recordCount(length);
  // Reserves room for WebSocket framing/masking as well as encrypted headers/tags.
  return length + 4 + count * (1 + 16 + 14);
}

export function* messageRecords(payload: Buffer, text: boolean): Generator<Buffer> {
  let offset = 0;
  const first = Buffer.allocUnsafe(5 + Math.min(payload.length, FIRST_PAYLOAD_BYTES));
  first[0] = text ? TEXT : BINARY;
  first.writeUInt32BE(payload.length, 1);
  offset += payload.copy(first, 5, 0, FIRST_PAYLOAD_BYTES);
  yield first;
  while (offset < payload.length) {
    const next = Buffer.allocUnsafe(1 + Math.min(payload.length - offset, NEXT_PAYLOAD_BYTES));
    next[0] = CONTINUE;
    offset += payload.copy(next, 1, offset, offset + NEXT_PAYLOAD_BYTES);
    yield next;
  }
}

export class MessageAssembler {
  #chunks: Buffer[] = [];
  #received = 0;
  #total = 0;
  #text = false;
  #active = false;

  get active(): boolean { return this.#active; }

  receive(record: Buffer, maxBytes: number): string | Uint8Array | null {
    const isFirstRecord = record[0] === TEXT || record[0] === BINARY;
    if (isFirstRecord) {
      if (this.#active || record.length < 5) throw new NoiseError('PROTOCOL_ERROR');
      this.#total = record.readUInt32BE(1);
      if (this.#total > maxBytes) throw new NoiseError('MESSAGE_TOO_LARGE');
      this.#text = record[0] === TEXT;
      this.#active = true;
    } else if (record[0] !== CONTINUE || !this.#active) {
      throw new NoiseError('PROTOCOL_ERROR');
    }

    const chunk = record.subarray(isFirstRecord ? 5 : 1);
    const payloadCapacity = isFirstRecord ? FIRST_PAYLOAD_BYTES : NEXT_PAYLOAD_BYTES;
    const expectedBytes = Math.min(this.#total - this.#received, payloadCapacity);
    if (chunk.length !== expectedBytes) throw new NoiseError('PROTOCOL_ERROR');
    this.#chunks.push(chunk);
    this.#received += chunk.length;
    if (this.#received !== this.#total) return null;

    const payload = Buffer.concat(this.#chunks, this.#total);
    const text = this.#text;
    this.clear();
    if (!text) return payload;
    try {
      return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(payload);
    } catch {
      throw new NoiseError('PROTOCOL_ERROR');
    }
  }

  clear(): void {
    this.#chunks = [];
    this.#total = 0;
    this.#received = 0;
    this.#active = false;
  }
}
