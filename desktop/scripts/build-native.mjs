import { spawnSync } from 'node:child_process';
import { mkdirSync, copyFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const desktop = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workspace = resolve(desktop, '..');
if (process.platform !== 'win32') throw new Error('The Windows package must be built on Windows.');
const result = spawnSync('cargo', ['build', '--release', '--locked', '--manifest-path', resolve(workspace, 'rust/Cargo.toml'), '-p', 'pman-cli'], {
  cwd: workspace, stdio: 'inherit', windowsHide: true,
});
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
const source = resolve(workspace, 'rust/target/release/pm.exe');
if (!existsSync(source)) throw new Error('Native pm.exe was not produced.');
const destination = resolve(desktop, 'src-tauri/bin');
mkdirSync(destination, { recursive: true });
copyFileSync(source, resolve(destination, 'pm.exe'));
console.log('Native pm.exe prepared for the Windows installer.');
