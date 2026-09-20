import { cp, mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

const repository = dirname(import.meta.dir);
const temporary = join(homedir(), 'tmp');
await mkdir(temporary, { recursive: true });
const root = await mkdtemp(join(temporary, 'noise-ws-compile-'));

async function run(command: string[], cwd: string): Promise<void> {
  const process = Bun.spawn(command, { cwd, stdout: 'pipe', stderr: 'pipe' });
  const stdout = new Response(process.stdout).text();
  const stderr = new Response(process.stderr).text();
  const timer = setTimeout(() => process.kill(), 120_000);
  try {
    const code = await process.exited;
    const output = (await stdout) + (await stderr);
    if (code !== 0) throw new Error(`Smoke subprocess exited ${code}:\n${output}`);
  } finally { clearTimeout(timer); }
}

try {
  await run([process.execPath, 'pm', 'pack', '--ignore-scripts', '--destination', root], repository);
  const archive = (await readdir(root)).find((name) => name.endsWith('.tgz'));
  if (!archive) throw new Error('Package archive was not produced');
  const consumer = join(root, 'consumer');
  const runtime = join(root, 'runtime');
  await mkdir(consumer);
  await mkdir(runtime);
  await writeFile(join(consumer, 'package.json'), JSON.stringify({
    private: true, type: 'module', dependencies: { '@cfal/noise-ws': `file:${join(root, archive)}` },
    devDependencies: { '@types/bun': '1.4.2', typescript: '6.0.3' },
  }));
  await cp(join(import.meta.dir, 'fixtures/smoke.ts'), join(consumer, 'smoke.ts'));
  await cp(join(import.meta.dir, 'fixtures/consumer.ts'), join(consumer, 'consumer.ts'));
  await writeFile(join(consumer, 'tsconfig.json'), JSON.stringify({
    compilerOptions: { target: 'ESNext', module: 'Preserve', moduleResolution: 'Bundler', types: ['bun'], strict: true, noEmit: true },
    include: ['consumer.ts'],
  }));
  await run([process.execPath, 'install', '--ignore-scripts'], consumer);
  await run([process.execPath, 'node_modules/typescript/bin/tsc', '--project', 'tsconfig.json'], consumer);
  const metadata = await Bun.file(join(consumer, 'node_modules/@cfal/noise-ws/package.json')).json();
  if (Object.keys(metadata.dependencies ?? {}).length) throw new Error('Production package must have zero dependencies');
  await run([process.execPath, 'run', 'smoke.ts'], consumer);
  const binary = join(runtime, process.platform === 'win32' ? 'smoke.exe' : 'smoke');
  await run([process.execPath, 'build', '--compile', './smoke.ts', '--outfile', binary], consumer);
  // The resulting executable must not depend on any source or dependency files.
  await rm(consumer, { recursive: true });
  await rm(join(root, archive));
  await run([binary], runtime);
  console.log(`Packaged declarations, source and standalone client/server passed (Bun ${Bun.version}, ${process.platform}-${process.arch}).`);
} finally { await rm(root, { recursive: true, force: true }); }
