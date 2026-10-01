# pman Node client

Requires Node 18+ and the native `pm.exe` paired through the desktop. It never
loads a service profile, Cookie file, or token. CLI identity is verified locally.

```js
import { createPmanClient } from './index.mjs';
const client = createPmanClient({
  clientId: process.env.PMAN_CLIENT_ID, // real paired ID, such as client-<UUID>
  site: 'office-api',
  expectedOrigin: 'https://office.example.test',
});
const context = await client.getActiveContext(); // metadata only
const response = await client.request({
  method: 'POST',
  path: '/api/items',
  form: {},
});
```

Non-secret configuration: `PMAN_EXECUTABLE` (absolute native CLI path),
`PMAN_CLIENT_ID` (paired client ID), `PMAN_SITE` (fixed connection alias).
Copy the actual client ID from the desktop's generated configuration. Client
display names and harness names are not IDs. Missing `PMAN_CLIENT_ID` requires
pairing; the SDK never guesses an identity from a display name.
On Windows, the executable defaults to `%LOCALAPPDATA%\pman Vault\pm.exe`.
Custom installation locations must set `PMAN_EXECUTABLE`; the SDK never searches
PATH for an old Python `pm`. No shell is used. Requests go through stdin,
not command-line arguments. `PmanError.code` is stable; `reqId` is included for
pending approval. Show it to the user and wait for approval. The SDK never
automatically retries, approves, resumes service, or reads old service auth data.

A connection alias is required through `site` or `PMAN_SITE`; there is no built-in
workplace service. Existing consumers that pass `site` explicitly are unchanged.

Request data must be JSON-serializable. Circular references, BigInt values, or
failing serializers reject with `PmanError.code === 'invalid_request'` before
the request bridge is spawned; raw serialization errors are not exposed.

Run the synthetic protocol tests with `npm test` in this directory. They do not
connect to a real vault, paired client, or remote service.
