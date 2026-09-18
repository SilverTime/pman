import { fileURLToPath } from 'node:url';
import { createPmanClient as realClient } from '../index.mjs';
export function createPmanClient(options) {
  return realClient({ ...options, clientId: 'fixture', executable: process.execPath,
    executableArgs: [fileURLToPath(new URL('./fake-pm.mjs', import.meta.url))] });
}
