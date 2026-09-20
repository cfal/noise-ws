import { NoiseConnection as NoiseWebSocket, type NoiseTransport } from '../src/connection.ts';
import type { NoiseOptions } from '../src/options.ts';

export const psk = Buffer.alloc(32, 42);
export const context = 'noise-ws-tests/v1';

export async function deadline<T>(promise: Promise<T>, ms = 2_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  try {
    return await Promise.race([promise, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('Test deadline exceeded')), ms);
    })]);
  } finally { clearTimeout(timer!); }
}

export function pair(leftOptions: Partial<NoiseOptions> = {}, rightOptions: Partial<NoiseOptions> = {}) {
  const leftMessages: (string | Uint8Array)[] = [];
  const rightMessages: (string | Uint8Array)[] = [];
  const leftFrames: Buffer[] = [];
  const rightFrames: Buffer[] = [];
  const left = new NoiseWebSocket(true, { psk, context, onMessage: (_, message) => { leftMessages.push(message); }, ...leftOptions });
  const right = new NoiseWebSocket(false, { psk, context, onMessage: (_, message) => { rightMessages.push(message); }, ...rightOptions });
  let bufferedAmount = 0;
  let writeError = false;
  let filter: ((frame: Buffer, from: 'left' | 'right') => Buffer | null) | null = null;
  const transport = (peer: NoiseWebSocket, frames: Buffer[], from: 'left' | 'right'): NoiseTransport => ({
    get bufferedAmount() { return bufferedAmount; },
    write(frame) {
      if (writeError) throw new Error('Synthetic write rejection');
      frames.push(Buffer.from(frame));
      const changed = filter ? filter(Buffer.from(frame), from) : frame;
      if (changed) queueMicrotask(() => peer.receive(changed));
    },
    close() { queueMicrotask(() => peer.fail('TRANSPORT_CLOSED')); },
    abort() { queueMicrotask(() => peer.fail('TRANSPORT_CLOSED')); },
  });
  return {
    left, right, leftMessages, rightMessages, leftFrames, rightFrames,
    start() {
      right.attach(transport(left, rightFrames, 'right'));
      left.attach(transport(right, leftFrames, 'left'));
    },
    async ready() { await deadline(Promise.all([left.ready, right.ready])); },
    set filter(value: typeof filter) { filter = value; },
    set bufferedAmount(value: number) { bufferedAmount = value; },
    set writeError(value: boolean) { writeError = value; },
    close() { left.close(); right.close(); },
  };
}
