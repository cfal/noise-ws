import { describe, expect, test } from 'bun:test';
import { NoiseConnection as NoiseWebSocket } from '../src/connection.ts';
import { NoiseCrypto } from '../src/crypto.ts';
import { NoiseError } from '../src/errors.ts';
import { connectionPrologue, MAX_RECORDS_PER_DIRECTION, resolveLimits } from '../src/options.ts';
import { messageRecords } from '../src/records.ts';
import { context, deadline, pair, psk } from './helpers.ts';

test('does not admit either peer before directional key confirmation', async () => {
  const fixture = pair();
  let confirm: Buffer | null = null;
  fixture.filter = (frame, from) => {
    if (from === 'left' && frame.length === 17) { confirm = frame; return null; }
    return frame;
  };
  fixture.start();
  await Bun.sleep(1);
  expect(confirm).not.toBeNull();
  expect(fixture.left.readyState).toBe('confirming');
  expect(fixture.right.readyState).toBe('confirming');
  expect(() => fixture.left.send('not yet')).toThrow(NoiseError);
  fixture.right.receive(confirm!);
  await fixture.ready();
  fixture.close();
});

test('preserves text, binary, empties, BOM and large messages in both directions', async () => {
  const fixture = pair();
  try {
    fixture.start();
    await fixture.ready();
    const messages = ['', '\ufeffhello\n\u{1f642}', Buffer.alloc(0), Buffer.from([0, 255, 13]), 'large '.repeat(30_000)];
    for (const message of messages) { fixture.left.send(message); fixture.right.send(message); }
    await Bun.sleep(1);
    expect(fixture.leftMessages).toEqual(messages);
    expect(fixture.rightMessages).toEqual(messages);
    expect(fixture.leftFrames.every((frame) => frame.length <= 65_535)).toBe(true);
    expect(fixture.leftFrames.some((frame) => frame.includes(Buffer.from('large ')))).toBe(false);
  } finally { fixture.close(); }
});

test.each(['wrong-key', 'wrong-context'])('rejects %s without open callbacks or application delivery', async (failure) => {
  let opens = 0;
  const fixture = pair({ onOpen: () => { opens++; } }, {
    ...(failure === 'wrong-key' ? { psk: Buffer.alloc(32, 99) } : { context: 'another-protocol' }),
    onOpen: () => { opens++; },
  });
  fixture.start();
  const closed = await deadline(fixture.right.closed);
  expect(closed.error?.code).toBe('AUTHENTICATION_FAILED');
  await expect(fixture.right.ready).rejects.toBeInstanceOf(NoiseError);
  expect(opens).toBe(0);
  expect(fixture.rightMessages).toEqual([]);
  fixture.close();
});

test.each(['corrupt', 'duplicate', 'reorder', 'reflect'])('rejects %s transport records', async (attack) => {
  const fixture = pair();
  fixture.start();
  await fixture.ready();
  const held: Buffer[] = [];
  fixture.filter = (frame, from) => { if (from === 'left') { held.push(frame); return null; } return frame; };
  fixture.left.send('first');
  fixture.left.send('second');
  if (attack === 'corrupt') {
    const corrupt = Buffer.from(held[0]!);
    corrupt[corrupt.length - 1]! ^= 1;
    fixture.right.receive(corrupt);
  } else if (attack === 'duplicate') {
    fixture.right.receive(held[0]!);
    fixture.right.receive(held[0]!);
  } else if (attack === 'reorder') fixture.right.receive(held[1]!);
  else fixture.left.receive(held[0]!);
  const attacked = attack === 'reflect' ? fixture.left : fixture.right;
  expect((await deadline(attacked.closed)).error?.code).toBe('AUTHENTICATION_FAILED');
  expect(fixture.rightMessages).toEqual(attack === 'duplicate' ? ['first'] : []);
  fixture.close();
});

test('fresh connections reject old ciphertext and replayed first handshakes cannot reach open', async () => {
  const previous = pair();
  previous.start();
  await previous.ready();
  previous.left.send('old payload');
  const ciphertext = Buffer.from(previous.leftFrames.at(-1)!);
  const firstHello = Buffer.from(previous.leftFrames[0]!);
  previous.close();
  const replacement = pair();
  replacement.start();
  await replacement.ready();
  replacement.right.receive(ciphertext);
  expect((await replacement.right.closed).error?.code).toBe('AUTHENTICATION_FAILED');
  replacement.close();
  const replayed = new NoiseWebSocket(false, { psk, context, limits: { handshakeTimeoutMs: 20 }, onMessage() {} });
  replayed.attach({ bufferedAmount: 0, write() {}, close() {}, abort() {} });
  replayed.receive(firstHello);
  expect(replayed.readyState).toBe('confirming');
  expect((await deadline(replayed.closed)).error?.code).toBe('HANDSHAKE_TIMEOUT');
});

test('caps messages before encryption without damaging a healthy connection', async () => {
  const fixture = pair({ limits: { maxMessageBytes: 5 } });
  fixture.start();
  await fixture.ready();
  const before = fixture.leftFrames.length;
  expect(() => fixture.left.send('too large')).toThrow('size limit');
  expect(fixture.leftFrames).toHaveLength(before);
  fixture.left.send('valid');
  await Bun.sleep(1);
  expect(fixture.rightMessages).toEqual(['valid']);
  fixture.close();
});

test('rejects plaintext, malformed and oversized wire messages', async () => {
  for (const invalid of ['plaintext secret', Buffer.alloc(0), Buffer.alloc(65_536), Buffer.alloc(18)]) {
    const fixture = pair();
    fixture.start();
    await fixture.ready();
    fixture.right.receive(invalid);
    expect((await fixture.right.closed).authenticated).toBe(false);
    expect(fixture.rightMessages).toEqual([]);
    fixture.close();
  }
});

test('refuses backpressure before encryption but treats a write failure as terminal', async () => {
  const fixture = pair();
  fixture.start();
  await fixture.ready();
  fixture.bufferedAmount = 32 * 1024 * 1024;
  const frames = fixture.leftFrames.length;
  expect(() => fixture.left.send('test')).toThrow('buffer limit');
  expect(fixture.left.readyState).toBe('open');
  expect(fixture.leftFrames).toHaveLength(frames);
  fixture.bufferedAmount = 0;
  fixture.left.send('retry before any encryption');
  await Bun.sleep(1);
  expect(fixture.rightMessages).toEqual(['retry before any encryption']);
  fixture.writeError = true;
  expect(() => fixture.left.send('test')).toThrow(NoiseError);
  expect((await fixture.left.closed).error?.code).toBe('TRANSPORT_ERROR');
  expect(() => fixture.left.send('retry')).toThrow('not open');
  fixture.close();
});

test('enforces the record budget including key confirmation', async () => {
  const fixture = pair({ limits: { maxRecordsPerDirection: 2 } });
  fixture.start();
  await fixture.ready();
  fixture.left.send('only allowed message');
  expect(() => fixture.left.send('would exceed limit')).toThrow('record limit');
  expect((await fixture.left.closed).error?.code).toBe('RECORD_LIMIT');
  expect(fixture.leftFrames).toHaveLength(3);
  fixture.close();
  expect(() => resolveLimits({ maxRecordsPerDirection: MAX_RECORDS_PER_DIRECTION + 1 })).toThrow();
});

test('unexpected or detached native frame types fail closed without throwing out of the handler', async () => {
  const detached = new ArrayBuffer(48);
  structuredClone(detached, { transfer: [detached] });
  for (const frame of [new Blob([Buffer.alloc(48)]), {}, null, 42, detached]) {
    const socket = new NoiseWebSocket(false, { psk, context, onMessage() { throw new Error('unreachable'); } });
    socket.attach({ bufferedAmount: 0, write() {}, close() {}, abort() {} });
    expect(() => socket.receive(frame)).not.toThrow();
    expect((await socket.closed).error).not.toBeNull();
  }
});

test('separates an authenticated close from an untrusted transport drop', async () => {
  const graceful = pair();
  graceful.start();
  await graceful.ready();
  graceful.left.close();
  expect(await deadline(graceful.right.closed)).toEqual({ authenticated: true, error: null });
  const dropped = pair();
  dropped.start();
  await dropped.ready();
  dropped.right.fail('TRANSPORT_CLOSED');
  expect((await dropped.right.closed).authenticated).toBe(false);
  expect((await dropped.right.closed).error?.code).toBe('TRANSPORT_CLOSED');
  dropped.close();
});

test('a fragmented message has a total deadline rather than a sliding deadline', async () => {
  const fixture = pair({}, { limits: { messageTimeoutMs: 20 } });
  fixture.start();
  await fixture.ready();
  let kept = false;
  fixture.filter = (frame, from) => {
    if (from !== 'left') return frame;
    if (kept) return null;
    kept = true;
    return frame;
  };
  fixture.left.send(Buffer.alloc(200_000));
  expect((await deadline(fixture.right.closed)).error?.code).toBe('MESSAGE_TIMEOUT');
  expect(fixture.rightMessages).toEqual([]);
  fixture.close();
});

test('callbacks settle once, failures are sanitized, and caller PSKs are not erased', async () => {
  let closes = 0;
  const fixture = pair({}, { onMessage() { throw new Error('sensitive details'); }, onClose() { closes++; throw new Error('ignored'); } });
  fixture.start();
  await fixture.ready();
  fixture.left.send('trigger');
  const result = await deadline(fixture.right.closed);
  expect(result.error?.message).not.toContain('sensitive');
  expect(result.error?.code).toBe('HANDLER_ERROR');
  fixture.right.fail();
  fixture.close();
  expect(closes).toBe(1);
  expect(psk).toEqual(Buffer.alloc(32, 42));
});

test('replaying either side of a complete transcript cannot open a new connection', async () => {
  const previous = pair();
  previous.start();
  await previous.ready();
  previous.left.send('previous initiator');
  previous.right.send('previous responder');
  for (const initiator of [true, false]) {
    let opens = 0;
    let messages = 0;
    const replay = new NoiseWebSocket(initiator, { psk, context, onOpen() { opens++; }, onMessage() { messages++; } });
    replay.attach({ bufferedAmount: 0, write() {}, close() {}, abort() {} });
    for (const frame of initiator ? previous.rightFrames : previous.leftFrames) replay.receive(frame);
    expect((await deadline(replay.closed)).error?.code).toBe('AUTHENTICATION_FAILED');
    expect(opens).toBe(0);
    expect(messages).toBe(0);
  }
  previous.close();
});

test('the wire version is authenticated as part of the prologue', async () => {
  const prologue = connectionPrologue(context);
  prologue[Buffer.byteLength('cfal/noise-ws\0')] = 2;
  const otherVersion = new NoiseCrypto(true, psk, prologue, MAX_RECORDS_PER_DIRECTION);
  let opened = false;
  const socket = new NoiseWebSocket(false, { psk, context, onMessage() {}, onOpen() { opened = true; } });
  socket.attach({ bufferedAmount: 0, write() {}, close() {}, abort() {} });
  socket.receive(otherVersion.sendHandshake());
  expect((await deadline(socket.closed)).error?.code).toBe('AUTHENTICATION_FAILED');
  expect(opened).toBe(false);
  otherVersion.destroy();
});

test('async callback rejection closes once without leaking the rejection reason', async () => {
  let errors = 0;
  let closes = 0;
  const fixture = pair({}, {
    async onMessage() { await Promise.resolve(); throw new Error('secret asynchronous failure'); },
    onError() { errors++; }, onClose() { closes++; },
  });
  fixture.start();
  await fixture.ready();
  fixture.left.send('trigger');
  const info = await deadline(fixture.right.closed);
  expect(info.error?.code).toBe('HANDLER_ERROR');
  expect(info.error?.message).not.toContain('secret');
  fixture.close();
  fixture.close();
  expect(errors).toBe(1);
  expect(closes).toBe(1);
});

describe('authenticated but malicious peer', () => {
  async function malicious(limits = {}) {
    const engine = new NoiseCrypto(true, psk, connectionPrologue(context), MAX_RECORDS_PER_DIRECTION);
    const received: (string | Uint8Array)[] = [];
    const socket = new NoiseWebSocket(false, { psk, context, limits, onMessage(_, message) { received.push(message); } });
    let handshake = true;
    socket.attach({ bufferedAmount: 0, write(frame) {
      if (handshake) { handshake = false; engine.receiveHandshake(frame); }
      else engine.decrypt(frame);
    }, close() {}, abort() {} });
    socket.receive(engine.sendHandshake());
    socket.receive(engine.encrypt(Buffer.from([1])));
    await socket.ready;
    return { engine, socket, received, close() { socket.close(); engine.destroy(); } };
  }

  test.each([
    Buffer.from([18, 1]),
    Buffer.from([255]),
    Buffer.from([16, 0, 0, 0, 2, 0]),
    Buffer.from([16, 0, 0, 0, 1, 255]),
    Buffer.from([1]),
    Buffer.from([3, 1]),
  ])('rejects invalid authenticated record %j', async (record) => {
    const fixture = await malicious();
    fixture.socket.receive(fixture.engine.encrypt(record));
    expect((await fixture.socket.closed).error?.code).toBe('PROTOCOL_ERROR');
    expect(fixture.received).toEqual([]);
    fixture.close();
  });

  test('rejects oversized declared messages without partial delivery', async () => {
    const fixture = await malicious({ maxMessageBytes: 100 });
    fixture.socket.receive(fixture.engine.encrypt(Buffer.from([17, 255, 255, 255, 255])));
    expect((await fixture.socket.closed).error?.code).toBe('MESSAGE_TOO_LARGE');
    fixture.close();
  });

  test('rejects nested starts and authenticated close during partial messages', async () => {
    for (const record of [Buffer.from([3]), Buffer.from([17, 0, 0, 0, 0])]) {
      const fixture = await malicious();
      fixture.socket.receive(fixture.engine.encrypt(messageRecords(Buffer.alloc(100_000), false).next().value!));
      fixture.socket.receive(fixture.engine.encrypt(record));
      expect((await fixture.socket.closed).error?.code).toBe('PROTOCOL_ERROR');
      fixture.close();
    }
  });
});
