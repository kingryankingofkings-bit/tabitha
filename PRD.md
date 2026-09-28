# TabBridge — Product Requirements Document

Status: MVP · Version 0.1 · Owner: TabBridge core

## 1. Problem statement

People now work with several AI agents at once, often spread across browser tabs: a
planning assistant in one tab, a research tool in another, a coding assistant in a third.
Today the only way to move work between them is copy and paste. That is slow and lossy,
and it leaves no record, so nobody can later say what one AI told another or which file it
handed over.

The obvious fixes all put the user at risk:

- **Shared page storage or `BroadcastChannel`** only works for tabs on the same origin, and
  every script on the page can read it.
- **Cloud relays** send the user's prompts and files to a third party.
- **"Agent" browser extensions with `<all_urls>` access** hand one piece of software the
  whole browser, and usually don't show what moved.

**TabBridge** is a browser extension that lets tabs form authenticated, user-approved
**rooms**. Inside a room, AI agents can have a real two-way conversation: they exchange
prompts and responses, share task state, and transfer files. Every exchange is
end-to-end encrypted, checked against the permissions the user granted, validated by size
and type, and written to an audit log the user can read. Safety is the product.

## 2. Users and personas

| Persona | Need |
|---|---|
| **Power user ("Operator")** | Runs 2–4 AI tools in tabs and wants them to hand off work, while seeing and controlling exactly what crosses between them. |
| **Agent developer ("Integrator")** | Builds a web-based AI agent and wants a small, stable, documented API for talking to agents in other tabs, without writing a relay. |
| **Security-minded admin ("Auditor")** | Needs to confirm that nothing moves without consent and that every transfer can be traced back later. |

## 3. User stories

1. As an Operator, I can turn TabBridge on for a specific site. My browser asks me to grant
   that site's permission, and sites I haven't enabled cannot see or reach TabBridge at all.
2. As an Operator, I can pair two tabs using a short code that appears only in TabBridge's
   own UI. Before approving, I can see both origins and exactly what each side may send.
3. As an Operator, I can choose separate permissions for each direction (for example,
   A may send prompts and PDFs to B, but B may only reply with text) and an expiry time.
4. As an Operator, I can end a room, narrow its permissions, or pause everything at once,
   and each change takes effect immediately.
5. As an Operator, I can open an audit log that shows every prompt, response, task update
   and file (name, type, size, hash) an AI sent or received, including rejected attempts.
   I can verify that the log has not been altered, and I can export or clear it.
6. As an Integrator, I can detect whether TabBridge is available. If it is, I can connect,
   send a prompt to a paired tab, and `await` its reply (`ask`). I can also receive prompts
   and `reply()` to them, which gives a real conversation loop.
7. As an Integrator, I can send a file and trust that the receiver gets it only if it
   matches the declared type and size, with provenance attached (origin, room, hash).
8. As an Integrator, my page keeps working with clear, typed errors when the other tab has
   no agent, when TabBridge is not installed, or when the user has not granted a permission.
9. As an Operator whose second tab has no AI agent, I can use the TabBridge side panel
   ("Agent Console") as the other end of the room, reading prompts and replying by hand.
10. As an Auditor, I can read a threat model that lists which attacks are blocked and which
    are out of scope.

## 4. Features (MoSCoW)

### Must
- M1 Per-origin opt-in through the browser's native host-permission prompt. The agent API
  is exposed only on enabled origins.
- M2 Pairing with a 6-digit code shown and entered only in extension-owned UI, with a TTL,
  an attempt limit and a global lockout.
- M3 Consent that shows both origins and the permissions for each direction before a room
  opens.
- M4 End-to-end encryption between the two endpoints (ECDH P-256 → HKDF-SHA-256 →
  AES-256-GCM), with the header authenticated as AAD, strict sequence numbers against
  replay, and key confirmation.
- M5 Router-side policy enforcement: sender origin taken from the browser, room membership,
  direction permissions, size caps, rate limits, expiry and a global pause.
- M6 Two-way prompt/response loop (`send`, `ask`, `reply`) with thread and reply-to
  linking, plus task-state messages.
- M7 File transfer with an allowlist checked by magic bytes, size caps, file-name
  sanitization, a SHA-256 hash and provenance. Files are validated by the sender and
  validated again by the receiver.
- M8 Hash-chained, tamper-evident audit log that records routing decisions and content,
  with viewing, verifying, exporting and clearing.
- M9 Revocation: close a room, narrow permissions, pause everything, and close rooms
  automatically when a tab closes, navigates or reloads, or when a site's access is removed.
- M10 Versioned public agent API (`apiVersion: 1`) with a stable set of error codes.
- M11 Graceful degradation: feature detection, typed errors (`NO_AGENT`,
  `PEER_UNAVAILABLE`, `NOT_PERMITTED`…), and the side-panel console as a fallback endpoint.
- M12 MV3 builds for Chromium and Firefox from one codebase.
- M13 Unit tests for the protocol and validation layers, a Node integration test and a
  Playwright E2E demo.

### Should
- S1 Dashboard page listing sites, rooms, grants and the audit log, with filtering.
- S2 A page-initiated `requestPairing()` that only flags the tab (badge) for the user.
- S3 Service-worker restart resilience: endpoints resume with a secret token and keep
  their keys.
- S4 Audit export as JSON with chain verification.

### Could
- C1 Pairing by picking a tab (with no code) for tabs whose origins differ.
- C2 Chunked or streamed transfer for files larger than 8 MiB.
- C3 Rooms with more than two members (would need group keys).
- C4 Sidebar agent backed by a model API instead of a human.

### Won't (this MVP)
- W1 External agents over Native Messaging. The `native` endpoint kind is reserved and
  designed but not built (see DECISIONS.md).
- W2 Pairing across devices or browsers (WebRTC or relay).
- W3 Malware or content scanning of files inside the browser.
- W4 Persisting ciphertext or plaintext queues for offline peers.
- W5 Messaging from inside iframes (top frame only).

## 5. Acceptance criteria

| # | Criterion | Verified by |
|---|---|---|
| AC1 | On an origin that is not enabled, `window.tabBridge` is `undefined` and no `tabbridge:ready` event fires. | E2E + router unit test (hello rejected) |
| AC2 | A room opens only after (a) the initiator starts pairing in extension UI, (b) the joiner enters the matching code in extension UI and approves, and (c) both endpoints confirm their keys. | Integration + pairing unit tests |
| AC3 | A wrong code 3 times invalidates it. More than 10 failures a minute locks pairing for 60 s. Codes expire after 120 s. | Pairing unit tests |
| AC4 | Tab A calls `ask()`. Tab B's agent receives the prompt and calls `reply()`. Tab A's `ask()` resolves with that text. This works in both directions within one room. | Integration + E2E |
| AC5 | A frame whose kind or MIME type the grant does not allow for that direction is rejected with `NOT_PERMITTED` and logged. | Router unit + integration |
| AC6 | Replayed or out-of-order frames (bad `seq`), spoofed `from` values and frames from non-members are rejected. | Router unit |
| AC7 | A valid PNG under the cap is delivered with provenance. An HTML file renamed `.png` is rejected (`FILE_TYPE_MISMATCH`/`FILE_TYPE_DENIED`) on the sender side, and also on the receiver side if a compromised sender pushes it through. | Validation unit + integration |
| AC8 | Closing, expiring, pausing or narrowing a room takes effect on the next frame. | Router unit + integration |
| AC9 | Every routed or rejected frame and every pairing or room lifecycle event has an audit entry, and `verifyChain` passes. Editing any stored entry makes verification fail. | Audit unit + integration |
| AC10 | The router sees only ciphertext for frame bodies (no plaintext field in routed frames). | Protocol/router unit |
| AC11 | `npm run build` produces `dist/chrome` and `dist/firefox` with valid MV3 manifests. | Build + E2E load |

## 6. Out of scope and known limits
- Scanning file content. TabBridge checks type, size and name only. A valid PDF can still
  be malicious, so receivers never auto-open or auto-download files.
- Protection against a compromised browser, a compromised OS, or other scripts running in
  the same origin as an enabled page (the origin's main world is the unit of trust).
- Hiding plaintext from TabBridge's own background: the user asked for full-text audit.
- Firefox is supported through a build target, but automated tests run only on Chromium in
  CI (see the demo walkthrough for the manual Firefox checklist).
