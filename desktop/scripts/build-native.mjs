import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { prepareNativeArtifact } from './native-artifact.mjs';

const desktop = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workspace = resolve(desktop, '..');
if (process.platform !== 'win32') throw new Error('The Windows package must be built on Windows.');
const result = spawnSync('cargo', ['build', '--release', '--locked', '--message-format=json-render-diagnostics', '--manifest-path', resolve(workspace, 'rust/Cargo.toml'), '-p', 'pman-cli'], {
  cwd: workspace, stdio: ['ignore', 'pipe', 'inherit'], windowsHide: true,
  shell: false, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
});
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
const destination = resolve(desktop, 'src-tauri/bin');
prepareNativeArtifact(result.stdout, destination);
console.log('Native pm.exe prepared for the Windows installer.');
