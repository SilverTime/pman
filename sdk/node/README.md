# pman Node client

Requires Node 18+ and the native `pm.exe` paired through the desktop. It never
loads an E10 Profile, Cookie file, or token. CLI identity is verified locally.

```js
import { createPmanClient } from './index.mjs';
const client = createPmanClient({
  clientId: process.env.PMAN_CLIENT_ID, // real paired ID, such as client-<UUID>
  site: 'e10-i18n',
  expectedOrigin: 'https://www.e-cology.com.cn',
});
const context = await client.getActiveContext(); // metadata only
const response = await client.request({
  method: 'POST',
  path: '/api/secondev/cm/todo/tool/getModuleCodes',
  query: { sf_request_type: 'ajax' },
  form: {},
});
```

Non-secret configuration: `PMAN_EXECUTABLE` (absolute native CLI path),
`PMAN_CLIENT_ID` (paired client ID), `PMAN_E10_SITE` (fixed connection alias).
Copy the actual client ID from the desktop's generated configuration. Client
display names and harness names are not IDs. Missing `PMAN_CLIENT_ID` requires
pairing; the SDK never guesses an identity from a display name.
On Windows, the executable defaults to `%LOCALAPPDATA%\pman Vault\pm.exe`.
Custom installation locations must set `PMAN_EXECUTABLE`; the SDK never searches
PATH for an old Python `pm`. No shell is used. Requests go through stdin,
not command-line arguments. `PmanError.code` is stable; `reqId` is included for
pending approval. Show it to the user and wait for approval. The SDK never
automatically retries, approves, resumes service, or reads old E10 auth data.

The migrated `e10-i18n` Skill has an identical local copy named
`scripts/pman-client.mjs`. An explicit `PMAN_SDK_PATH` may select another local
version. Keep both copies synchronized when updating the protocol.
