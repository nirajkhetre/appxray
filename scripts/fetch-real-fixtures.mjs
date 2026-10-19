#!/usr/bin/env node
// Downloads official Electron builds for the current OS into a fixtures folder and writes
// expected.json for test/real. Used by CI; needs network access to github.com and npm.
//
//   node scripts/fetch-real-fixtures.mjs <dir> [version...]
//
// With no versions, uses an end-of-life line (22.3.27) and the newest stable release.
import { execFileSync } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

const [dir, ...requested] = process.argv.slice(2);
if (!dir) {
  console.error('usage: fetch-real-fixtures.mjs <dir> [version...]');
  process.exit(2);
}

const platform =
  process.platform === 'win32' ? 'win32' : process.platform === 'darwin' ? 'darwin' : 'linux';
const arch = process.arch === 'arm64' ? 'arm64' : 'x64';

async function latestElectron() {
  const response = await fetch('https://registry.npmjs.org/electron/latest');
  if (!response.ok) throw new Error(`npm returned ${response.status}`);
  return (await response.json()).version;
}

const versions = requested.length > 0 ? requested : ['22.3.27', await latestElectron()];
await mkdir(dir, { recursive: true });
const expected = {};

for (const version of versions) {
  const name = `electron-v${version}-${platform}-${arch}`;
  const zip = path.join(dir, `${name}.zip`);
  const url = `https://github.com/electron/electron/releases/download/v${version}/${name}.zip`;
  console.log(`downloading ${url}`);
  const response = await fetch(url);
  if (!response.ok || !response.body) throw new Error(`${url} returned ${response.status}`);
  await pipeline(Readable.fromWeb(response.body), createWriteStream(zip));
  const target = path.join(dir, name);
  await mkdir(target, { recursive: true });
  // tar (bsdtar) extracts zip archives on Windows 10+, macOS and most Linux CI images.
  execFileSync(
    process.platform === 'linux' ? 'unzip' : 'tar',
    process.platform === 'linux' ? ['-q', zip, '-d', target] : ['-xf', zip, '-C', target],
    {
      stdio: 'inherit',
    },
  );
  expected[name] = { electron: version, fuses: true };
}

await writeFile(path.join(dir, 'expected.json'), `${JSON.stringify(expected, null, 2)}\n`);
console.log(`wrote ${Object.keys(expected).length} fixtures to ${dir}`);
