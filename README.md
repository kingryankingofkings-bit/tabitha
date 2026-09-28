# TabBridge

**Consent-gated, end-to-end encrypted, audited messaging between AI agents in different browser tabs.**

TabBridge is a Manifest V3 extension for Chromium and Firefox. It lets tabs form authenticated
**rooms** so that AI agents (in-page agents, or you through the side-panel Agent Console) can hold
a real back-and-forth conversation across tabs: prompts, responses, task state and files. Before
anything crosses between tabs, **you** have to approve the pairing and its per-direction
permissions. Every exchange is written to a tamper-evident audit log.

> Status: MVP (v0.1.0). A dedicated security review is still pending; see
> [DECISIONS.md → OPEN SECURITY QUESTIONS](DECISIONS.md#open-security-questions).

| Doc | What's in it |
|---|---|
| [PRD.md](PRD.md) | Problem, user stories, MoSCoW, acceptance criteria |
| [DECISIONS.md](DECISIONS.md) | Transport, encryption, pairing, permissions, versioning, **threat model** |
| [SPEC.md](SPEC.md) | Single source of truth: modules, wire formats, signatures, limits |
| [DESIGN.md](DESIGN.md) | "Customs House" design system and tokens |
| [demo/WALKTHROUGH.md](demo/WALKTHROUGH.md) | Step-by-step end-to-end demo |

---

## Setup

Requirements: Node ≥ 20, plus Chrome/Chromium ≥ 116 or Firefox ≥ 128.

```bash
npm install
npm run build          # → dist/chrome and dist/firefox
npm test               # unit + integration tests (vitest)
npm run test:e2e       # Playwright: real extension in Chromium, two demo origins
```

**Chrome / Edge / Brave:** open `chrome://extensions`, turn on *Developer mode*, choose
*Load unpacked*, and select `dist/chrome`.
**Firefox:** open `about:debugging#/runtime/this-firefox`, choose *Load Temporary Add-on…*,
and select `dist/firefox/manifest.json`.

TabBridge installs with **no access to any website**. You turn it on one site at a time (see
below).

## Pairing flow (what the user does)

1. **Enable the site.** Open the TabBridge toolbar popup on the tab, choose
   **Enable TabBridge on `https://site`**, and accept the browser's permission prompt. Only
   then is the agent API injected on that exact origin.
2. **Start pairing in tab A.** In the popup, choose **Start pairing**. Pick what *this tab
   may send* and what *the other tab may send* (prompts, task updates, files with
   per-type and size limits), and pick an expiry (15 min, 1 h, or 8 h). The popup shows a
   **6-digit code**. The code only ever appears in TabBridge's own UI, never on a web page.
3. **Join in tab B.** Open the popup on tab B and choose **Join with code**. Enter the code
   and review both origins and both directions' permissions. Then choose **Approve** or
   **Reject**.
4. The two tabs exchange keys and confirm them. The room becomes **active**, and both
   agents get a `room` event.
5. **Revoke at any time.** You can close the room (popup, dashboard, or console), narrow
   its permissions (they can only shrink; widening means pairing again), or **Pause all**.
   Rooms also end automatically when a tab closes, navigates, or reloads, when the site is
   disabled, or when the room expires.

A page can call `requestPairing()`, but that only puts a badge on the toolbar icon. Consent
always happens in extension UI.

## Security model (overview)

| Property | How |
|---|---|
| **Origin isolation** | Access is opt-in per origin through the browser's native permission prompt. The background router takes each sender's origin from the browser (`port.sender`), never from the message. Top frame only. The API appears only after the router accepts the exact origin. |
| **Explicit consent** | Pairing is started and joined only from extension-owned UI, using a single-use code (120 s TTL, 3 wrong guesses cancel it, a global lockout applies). The approval screen shows both origins and both directions' permissions. |
| **Encrypted transport** | End-to-end between the two endpoints: ECDH P-256 → HKDF-SHA-256 (bound to a transcript of both keys, both origins and the grant) → AES-256-GCM, with the frame header authenticated as AAD. The router forwards ciphertext only. |
| **Policy enforcement** | Router checks: membership, per-direction kind/MIME permissions, size caps (text 32 KiB, files up to 8 MiB), rate limits, strict sequence numbers (replay protection), expiry, and the global pause. |
| **File safety** | Allowlist checked by magic bytes (txt, md, csv, json, png, jpeg, gif, webp, pdf). HTML, SVG, scripts, executables and archives are always refused. File names are sanitized. Validation runs on the sender *and again* on the receiver, which also checks the SHA-256. Provenance is attached to every file. |
| **Audit** | A hash-chained log of every pairing, room event, routed or rejected frame, and content record (full prompt text, and file name, type, size and SHA-256, never file bytes). You can verify, export and clear it from the dashboard. |

**Limits, stated plainly:**
- TabBridge does **not** scan file contents; a valid PDF or image can still be malicious.
  Files are never opened or downloaded automatically.
- All scripts on an enabled origin are treated as that origin's agent.
- Within one browser, end-to-end encryption is defense in depth: the background router is
  the trust anchor. See DECISIONS.md D2.

The full threat model is in DECISIONS.md.

---

## AI integration guide: public API (`apiVersion: 1`)

The API is available as `window.tabBridge`, but only on origins the user has enabled.
It is small, versioned and frozen. Everything below is stable for `apiVersion: 1`.

### Detect and connect (with graceful degradation)

```js
async function getTabBridge(timeoutMs = 3000) {
  if (window.tabBridge) return window.tabBridge;
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(null), timeoutMs);
    addEventListener('tabbridge:ready', () => { clearTimeout(t); resolve(window.tabBridge); }, { once: true });
  });
}

const tb = await getTabBridge();
if (!tb) {
  // Not installed, or not enabled for this site: keep working standalone.
} else {
  const session = await tb.connect({ apiVersion: 1, agentName: 'My Research Agent' });
}
```

### Receive prompts and reply (the conversation loop)

```js
session.on('prompt', async (msg) => {
  // msg: { id, roomId, type: 'prompt', text, threadId, inReplyTo?, from: { origin, kind, agentName }, sentAt, receivedAt }
  const answer = await myModel.complete(msg.text);   // your agent logic
  await msg.reply(answer);                           // sends a 'response' with inReplyTo = msg.id
});
```

### Ask another tab and await its reply

```js
const [room] = (await session.rooms()).filter((r) => r.state === 'active');
const reply = await session.ask(room.roomId, 'Summarize the open questions', { timeoutMs: 60_000 });
console.log(reply.text);
```

### Task state and files

```js
await session.sendTask(room.roomId, { taskId: 'draft-1', status: 'running', progress: 0.4, summary: 'Drafting section 2' });

await session.sendFile(room.roomId, fileInput.files[0]);                    // File: name taken from the file
await session.sendFile(room.roomId, blob, { name: 'chart.png' });          // Blob: name required

session.on('file', ({ file, provenance, from }) => {
  // file: File (validated). provenance: { fromOrigin, fromKind, roomId, frameId, sha256, detectedType, size, sentAt, receivedAt, validated: true }
});
session.on('task', ({ task, from }) => {});
session.on('room', (room) => {});            // RoomView: state, peer, outbound/inbound grants, expiresAt
session.on('error', ({ code, message }) => {});
```

### Reference

| Member | Description |
|---|---|
| `tabBridge.version` | Extension version string |
| `tabBridge.apiVersions` | Supported API versions, `[1]` |
| `tabBridge.connect({apiVersion, agentName})` | Attaches this page's agent and returns a `Session`. Idempotent. |
| `session.rooms()` | `RoomView[]` for this tab |
| `session.requestPairing({note?})` | Asks the user to pair this tab (shows a badge only) |
| `session.send(roomId, {type, text, threadId?, inReplyTo?})` | Sends a prompt or response. Resolves once the peer's agent has received it. |
| `session.ask(roomId, text, {threadId?, timeoutMs?})` | Sends a prompt and resolves with the matching response (default timeout 60 s, max 600 s) |
| `session.sendTask(roomId, {taskId, status, progress?, summary?, threadId?})` | `status` is one of `queued running blocked done failed cancelled` |
| `session.sendFile(roomId, blob, {name?, threadId?})` | Validated on send and again on receipt |
| `session.leave(roomId)` | Closes the room |
| `session.on(event, cb)` / `off` | Events: `prompt`, `response`, `task`, `file`, `room`, `error`. `on` returns an unsubscribe function. |
| `session.close()` | Detaches the agent. Peers then get `NO_AGENT`. |

**Errors.** Every method rejects with an `Error` whose `name` is `'TabBridgeError'` and which
carries a stable `code`: `NOT_PERMITTED`, `PEER_UNAVAILABLE`, `NO_AGENT`,
`DELIVERY_TIMEOUT`, `TIMEOUT`, `PAUSED`, `RATE_LIMITED`, `PAYLOAD_TOO_LARGE`,
`ROOM_NOT_ACTIVE`, `ROOM_CLOSED`, `ROOM_EXPIRED`, `FILE_TYPE_DENIED`, `FILE_TYPE_MISMATCH`,
`FILE_TOO_LARGE`, `FILE_NAME_INVALID`, `FILE_EMPTY`, `UNSUPPORTED_VERSION`, and so on. The
full list is in SPEC.md §9. New codes can be added in minor releases; removing or renaming
one requires `apiVersion: 2`.

**Limits:** text is at most 32 KiB (UTF-8); task summaries at most 2,048 characters; files at
most the room's cap (at most 8 MiB); 60 frames and 16 MiB per minute per sender; at most 8
rooms per tab.

### Agent Console (sidebar agent)

When the other tab has no in-page agent, open the **Agent Console** side panel from the
popup. It joins rooms as an endpoint of its own (`tabbridge://console`), so you can read
incoming prompts, reply, post task updates, and send files by hand.

### External agents (Native Messaging): planned

The endpoint kind `native` is reserved in the protocol but not accepted in v1. See
DECISIONS.md D5 for the design.

---

## Development

```
src/shared/      contracts: types, limits, errors, encoding, protocol validators, crypto
src/background/  router (policy enforcement point), pairing, permissions, audit, state, platform glue
src/endpoint/    Endpoint: E2E crypto + send/receive validation (content script and side panel)
src/content/     isolated-world bridge + MAIN-world window.tabBridge shim
src/files/       file type detection, name sanitization, provenance
src/ui/          popup, dashboard, side panel (vanilla TS, "Customs House" tokens)
scripts/         build (esbuild → dist/chrome, dist/firefox, dist/chrome-e2e)
test/            unit, integration (router + endpoints + real crypto), e2e (Playwright)
demo/            two demo agents + static server + walkthrough
```

`dist/chrome-e2e` is a test-only build. It pre-grants host access to `localhost` and
`127.0.0.1` so automated tests don't need the browser's permission prompt. Never ship it.
