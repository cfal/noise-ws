import { randomBytes } from 'node:crypto';
import { connectNoiseWebSocket, createNoiseServer, type NoiseWebSocket } from '../src/index.ts';

const psk = randomBytes(32);
const context = 'noise-ws-benchmark/v1';
const noise = createNoiseServer();
const server = Bun.serve({
  hostname: '0.0.0.0', port: 0, websocket: noise.websocket,
  fetch(request, server) { return noise.upgrade(request, server, { psk, context, onMessage: (socket, message) => socket.send(message) }); },
});
const url = `ws://127.0.0.1:${server.port}/`;
let active: NoiseWebSocket | undefined;
let receive: () => void = () => {};
const measurements: Record<string, string | number> = { bun: Bun.version, platform: `${process.platform}-${process.arch}` };
const deadline = setTimeout(() => { console.error('Benchmark deadline exceeded'); process.exit(1); }, 60_000);

async function roundTrips(socket: NoiseWebSocket, payload: Uint8Array, count: number, batch: boolean): Promise<number> {
  const done = Promise.withResolvers<void>();
  let received = 0;
  receive = () => {
    if (++received === count) done.resolve();
    else if (!batch) socket.send(payload);
  };
  const start = performance.now();
  if (batch) for (let i = 0; i < count; i++) socket.send(payload);
  else socket.send(payload);
  await done.promise;
  return performance.now() - start;
}

try {
  const handshakes: number[] = [];
  for (let i = 0; i < 100; i++) {
    const start = performance.now();
    active = connectNoiseWebSocket(url, { psk, context, onMessage: () => receive() });
    await active.ready;
    handshakes.push(performance.now() - start);
    if (i < 99) active.close();
  }
  handshakes.sort((a, b) => a - b);
  measurements.handshake_p50_ms = +handshakes[50]!.toFixed(3);
  measurements.handshake_p95_ms = +handshakes[95]!.toFixed(3);
  const socket = active!;
  const small = Buffer.alloc(128, 71);
  await roundTrips(socket, small, 100, false);
  measurements.small_roundtrip_mean_us = +(await roundTrips(socket, small, 1_000, false) * 1_000 / 1_000).toFixed(1);
  measurements.streaming_roundtrips_per_second = Math.round(10_000 * 1_000 / await roundTrips(socket, small, 10_000, true));
  const big = Buffer.alloc(16 * 1024 * 1024, 73);
  const duration = await roundTrips(socket, big, 8, false);
  measurements.large_bidirectional_mib_per_second = +(2 * 8 * 16 * 1_000 / duration).toFixed(1);
  console.log(JSON.stringify(measurements, null, 2));
} finally {
  clearTimeout(deadline);
  active?.close();
  noise.close();
  await server.stop(true);
}
