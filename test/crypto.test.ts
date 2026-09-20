import { expect, test } from 'bun:test';
import { createHash, hkdfSync } from 'node:crypto';
import { NoiseCipher } from '../src/cipher.ts';
import { NoiseCrypto } from '../src/crypto.ts';
import { NoiseHandshake } from '../src/handshake.ts';
import { MAX_RECORDS_PER_DIRECTION, NOISE_PROTOCOL, connectionPrologue } from '../src/options.ts';
import { context, psk } from './helpers.ts';

test.each([0, 1, 15, 16, 17, 255, 256, 65_519])('AES-GCM authenticates %d bytes with additional data', (size) => {
  const tx = new NoiseCipher(psk);
  const rx = new NoiseCipher(psk);
  const plaintext = Buffer.alloc(size, 49);
  const aad = Buffer.from('transcript hash');
  const encrypted = tx.encrypt(plaintext, aad);
  expect(encrypted.length).toBe(size + 16);
  expect(rx.decrypt(encrypted, aad)).toEqual(plaintext);
  tx.destroy();
  rx.destroy();
});

test('failed tags or associated data destroy cipher state; no unauthenticated plaintext escapes', () => {
  for (const corruptTag of [true, false]) {
    const tx = new NoiseCipher(psk);
    const rx = new NoiseCipher(psk);
    const encrypted = tx.encrypt(Buffer.from('sensitive'), Buffer.from('bound'));
    const altered = Buffer.from(encrypted);
    if (corruptTag) altered[altered.length - 1]! ^= 1;
    expect(() => rx.decrypt(altered, Buffer.from(corruptTag ? 'bound' : 'wrong'))).toThrow('authentication failed');
    expect(rx.remaining).toBe(0);
    expect(() => rx.decrypt(encrypted, Buffer.from('bound'))).toThrow('closed');
    tx.destroy();
  }
});

test('invalid frame sizes destroy cipher state and do not modify caller key bytes', () => {
  const key = Buffer.alloc(32, 19);
  for (const length of [0, 15, 65_536]) {
    const cipher = new NoiseCipher(key);
    expect(() => cipher.decrypt(Buffer.alloc(length))).toThrow();
    expect(cipher.remaining).toBe(0);
  }
  const cipher = new NoiseCipher(key);
  expect(() => cipher.encrypt(Buffer.alloc(65_520))).toThrow('size limit');
  expect(cipher.remaining).toBe(0);
  expect(key).toEqual(Buffer.alloc(32, 19));
});

test('handshake ordering and reuse violations destroy state', () => {
  const a = new NoiseHandshake(true, psk, Buffer.alloc(0));
  const b = new NoiseHandshake(false, psk, Buffer.alloc(0));
  expect(() => b.write()).toThrow('protocol');
  expect(() => b.read(a.write())).toThrow('protocol');
  expect(() => a.write()).toThrow('protocol');
  const early = new NoiseHandshake(true, psk, Buffer.alloc(0));
  expect(() => early.finish()).toThrow('protocol');
  expect(() => early.write()).toThrow('protocol');
  const initiator = new NoiseHandshake(true, psk, Buffer.alloc(0));
  const responder = new NoiseHandshake(false, psk, Buffer.alloc(0));
  responder.read(initiator.write());
  initiator.read(responder.write());
  expect(initiator.complete).toBe(true);
  const keys = initiator.finish();
  expect(() => initiator.finish()).toThrow('protocol');
  expect(() => initiator.write()).toThrow('protocol');
  keys.tx.fill(0);
  keys.rx.fill(0);
  responder.destroy();
});

test('fresh ephemeral keys are generated and caller PSKs are copied before mutation', () => {
  const key = Buffer.from(psk);
  const a = new NoiseHandshake(true, key, Buffer.alloc(0));
  const b = new NoiseHandshake(false, key, Buffer.alloc(0));
  key.fill(0);
  const first = a.write();
  expect(b.read(first).length).toBe(0);
  a.read(b.write());
  const next = new NoiseHandshake(true, psk, Buffer.alloc(0));
  expect(next.write().subarray(0, 32)).not.toEqual(first.subarray(0, 32));
  a.destroy(); b.destroy(); next.destroy();
});

test('authenticated low-order ephemeral public keys fail at X25519 and cannot produce transport keys', () => {
  const prologue = connectionPrologue(context);
  const hash = (...input: Buffer[]) => createHash('sha256').update(Buffer.concat(input)).digest();
  for (const value of [0, 1]) {
    const ephemeral = Buffer.alloc(32);
    ephemeral[0] = value;
    const initial = Buffer.from(NOISE_PROTOCOL);
    const mixed = Buffer.from(hkdfSync('sha256', psk, initial, Buffer.alloc(0), 96));
    const h = hash(hash(hash(initial, prologue), mixed.subarray(32, 64)), ephemeral);
    const next = Buffer.from(hkdfSync('sha256', ephemeral, mixed.subarray(0, 32), Buffer.alloc(0), 64));
    const cipher = new NoiseCipher(next.subarray(32));
    const frame = Buffer.concat([ephemeral, cipher.encrypt(Buffer.alloc(0), h)]);
    const responder = new NoiseHandshake(false, psk, prologue);
    expect(responder.read(frame).length).toBe(0);
    expect(() => responder.write()).toThrow('authentication failed');
    expect(() => responder.finish()).toThrow('protocol');
    cipher.destroy(); mixed.fill(0); next.fill(0);
  }
});

test('the socket crypto engine disallows handshake payloads and destroys both directions on a bad record', () => {
  const malicious = new NoiseHandshake(true, psk, connectionPrologue(context));
  const target = new NoiseCrypto(false, psk, connectionPrologue(context), MAX_RECORDS_PER_DIRECTION);
  expect(() => target.receiveHandshake(malicious.write(Buffer.from('no 0-RTT')))).toThrow('protocol');
  expect(() => target.sendHandshake()).toThrow('protocol');
  malicious.destroy();
  const a = new NoiseCrypto(true, psk, Buffer.alloc(0), MAX_RECORDS_PER_DIRECTION);
  const b = new NoiseCrypto(false, psk, Buffer.alloc(0), MAX_RECORDS_PER_DIRECTION);
  b.receiveHandshake(a.sendHandshake());
  a.receiveHandshake(b.sendHandshake());
  const record = a.encrypt(Buffer.alloc(0));
  record[record.length - 1]! ^= 1;
  expect(() => b.decrypt(record)).toThrow('authentication failed');
  expect(() => b.encrypt(Buffer.alloc(0))).toThrow('not open');
  expect(b.sendRemaining).toBe(0);
  a.destroy();
});
