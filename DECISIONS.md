# TabBridge: Architecture Decisions

Each decision below lists the options we considered, their trade-offs, and the choice we
made. The chosen designs are specified precisely in `SPEC.md`. Where a requirement was
hard to meet securely, we flag it here instead of dropping it.

Decisions the user confirmed during planning:
- **D0.1** Site access is opt-in, one origin at a time, through the browser's own
  host-permission prompt.
- **D0.2** The audit log keeps full prompt and response text (up to 32 KiB) and task
  state. For files it keeps the name, type, size and SHA-256 hash, never the bytes.
- **D0.3** External (Native Messaging) agents are designed but not built in the MVP.

---

## D1. Transport

| Option | Pros | Cons |
|---|---|---|
| **A. Extension messaging** (content script ↔ background via `runtime.Port`, with the background acting as a hub) | Works across origins. Page scripts and other extensions cannot observe it. The browser tells us each sender's tab, frame and origin. No network hop. Available in Chrome and Firefox MV3. | The background can see every frame, so it has to be trusted. MV3 background workers get suspended, so state has to be persisted and endpoints have to resume. Chrome serializes messages as JSON, so binary data must be base64-encoded (about 33% overhead). |
| B. `BroadcastChannel` | Very simple. | Same-origin only, so it can't bridge two different sites. Every script in the origin can read it, including third-party scripts and any other tab of that origin. No sender authentication. |
| C. WebRTC data channels | DTLS is built in. Opens a path to pairing across devices later. | Needs a signaling path, which would be (A) anyway. Complicated inside MV3 service workers (no `RTCPeerConnection` in the SW). ICE can expose local IPs. Too much machinery for peers in one browser. |
| D. Local relay server (localhost WebSocket) | Could bridge browsers and external agents. | Requires a native install. Any local process or web page can hit `localhost`, which creates a new attack surface (DNS rebinding, CSRF against localhost). Needs its own authentication. Violates the "nothing leaves the browser" posture. |

**Choice: A, plus application-layer end-to-end encryption (see D2).**

The background runs a **router**. It is the policy enforcement point (PEP): it takes the
sender's origin from the browser, checks room membership, direction grants, size caps,
rate limits, sequence numbers and expiry, then forwards ciphertext. The in-page agent
reaches its content script through a private `MessagePort`. That port is handed over once
at `document_start` and is never sent through `window.postMessage` again.

## D2. Encryption

The concept requires "encrypted transport". Within a single browser, extension messaging
already runs over IPC that pages and other extensions cannot read. So we asked what
encryption actually adds and designed for that, rather than encrypting for show.

| Option | Pros | Cons |
|---|---|---|
| **A. End-to-end between the two endpoints** (ECDH P-256 → HKDF-SHA-256 → AES-256-GCM; the background forwards ciphertext) | Protects against misrouting: a frame delivered to the wrong endpoint can't be decrypted. No plaintext sits in router state. A future remote or native hop is already covered. The receiver authenticates the header (AAD). | The router can enforce policy only on headers, so content checks run at the endpoints: both sides validate (see D6). Keys exist only in memory, so a reload ends membership. |
| B. Encrypt each hop to the background | Simple. | Adds nothing over browser IPC. |
| C. No encryption, rely on browser IPC | Simplest. | Fails the stated requirement and leaves nothing in place for future transports. |

**Choice: A.** We document the limit honestly. The background tells each endpoint which
public key belongs to its peer. In other words, the background acts as the certificate
authority inside the browser, and a compromised background would defeat E2E. That is
acceptable because a compromised extension background already controls everything the
extension can reach. What E2E does buy us:
1. **Defense in depth against router bugs.** A frame sent to the wrong endpoint cannot be
   decrypted there. The recipient's key confirmation would fail and the room would close.
2. **No plaintext at rest in routing state.** Only headers, counters and ciphertext hashes
   are persisted. The full text lives only in the audit log, which is a separate, explicit
   store the user asked for (D0.2).
3. **Receiver-side verification** of header claims such as size and MIME type against the
   decrypted plaintext, carried out in the receiver's own renderer process.
4. **Readiness for transports that leave the browser** (native or cross-device) without
   changing the protocol.

Key details:
- Each room gets a fresh ECDH key pair. Private keys are non-extractable `CryptoKey`s held
  in memory only.
- `info = "tabbridge/v1/room-key" || SHA-256(canonical transcript)`. The transcript binds
  the roomId, both endpointIds, both origins, both public keys, and the grant. If the
  background tampered with the grant, the derived keys would differ and confirmation would
  fail.
- Each frame gets a random 96-bit IV. With a 256-bit key, the birthday bound on random IVs
  is 2³² frames per room, far above anything a room will send, and rooms expire within
  8 hours.
- The AAD is the canonical JSON of the header, so `from`, `seq`, `kind`, `size` and
  `mime` are all authenticated.

## D3. Pairing and establishing trust

| Option | Pros | Cons |
|---|---|---|
| **A. 6-digit code shown and typed only in extension UI** | Pages can't read it or type it. It ties the user's intent to two specific tabs, which beats a race by a hostile tab that asks to pair at the same moment. Works when both tabs share an origin. | The user has to switch tabs and type 6 digits. |
| B. QR code | Good across devices. | Pointless within one browser. |
| C. Pick the tab from a list | Fewer steps. | Tab titles can be spoofed. Two tabs on the same origin look identical. Easy to click the wrong one. |
| D. Consent prompt injected into the page | Convenient. | The page controls its own DOM, so it can fake, cover or click-jack the prompt. **Rejected outright.** |

**Choice: A.** Option C is listed as a Could for a later version, and only for tabs with
different origins.

Flow:
1. Initiator: open the popup on tab A, choose the permissions for each direction and an
   expiry, and click "Start". The popup shows the code.
2. Joiner: open the popup on tab B, choose "Join", type the code, review both origins and
   both grants, and click "Approve".
3. Both endpoints receive a key request, create key pairs and share their public keys.
   The router sends each side the full transcript, and each side derives the room key.
4. Each endpoint sends an encrypted `confirm` frame carrying the transcript hash. The
   room becomes `active` only after both sides confirm.

Codes expire after 120 s and allow 3 tries each. More than 10 failed lookups across all
codes in 60 s locks pairing for 60 s. With 10⁶ possible codes and those limits, a
guessing attack is not practical, and only extension UI can submit codes anyway. A page
can call `requestPairing()`, but that only sets a badge on its tab.

## D4. Permission model and revocation

Each room carries a **Grant**, which holds one `DirectionGrant` for each direction:
- `prompts`: may send prompt and response messages.
- `tasks`: may send task-state updates.
- `files`: may send files, plus `fileTypes` (a subset of the global allowlist) and
  `maxFileBytes` (at most 8 MiB).
- A room-wide expiry of 15 minutes, 1 hour (the default) or 8 hours, and a rate limit of
  60 frames and 16 MiB per minute per sender.

Revocation paths, each checked on the next frame:
- Close the room in the popup, dashboard or side panel.
- **Narrow** the grant. Permissions can only be reduced mid-room. Widening them means
  pairing again, so the "approved" state can never quietly grow.
- **Pause all.** A global kill switch rejects every frame and every pairing attempt.
- **Site disabled.** Removing an origin's permission closes all of its rooms and
  unregisters its scripts.
- **Lifecycle.** The room closes when a tab closes, when an endpoint changes origin, when
  it fails to resume within 30 s (navigation or reload: its keys are gone), or when the
  room expires (checked on each frame and swept every minute with `alarms`).

## D5. Schema versioning and the agent-facing API

- The **wire protocol** carries `v: 1` in every endpoint↔router message and every frame
  header. The router rejects unknown versions with `UNSUPPORTED_VERSION`, and a new
  version must be added as a new code path. Unknown fields are rejected, not ignored,
  because strict schemas shrink the parser attack surface.
- The **public agent API** is `window.tabBridge`, a frozen object. It appears only after
  the router accepts the origin, and `tabbridge:ready` is dispatched at that point.
  - `connect({apiVersion: 1, agentName})` negotiates the version. Unsupported versions
    get `UNSUPPORTED_VERSION` along with the list in `tabBridge.apiVersions`.
  - Surface: `rooms`, `requestPairing`, `send`, `ask`, `sendTask`, `sendFile`, `on`/`off`
    for `prompt | response | task | file | room | error`, and `close`.
  - Error codes are a closed, documented set. Adding a code is a minor change; removing
    or renaming one requires `apiVersion: 2`.
  - Semantic versioning: the extension version and `tabBridge.version` are separate.
    `apiVersion` changes only on breaking changes.
- **External agents** (reserved endpoint kind `"native"`): later, a Native Messaging host
  would connect to the background with `runtime.connectNative`. It would be registered in
  the dashboard (user opt-in, per host name) and would take part in pairing exactly like a
  panel endpoint, with its own ECDH keys in the host process. This adds a trust boundary
  (any local process able to run the host binary), so it is deferred until it can get its
  own security review.

## D6. File transfer and validation

- Files travel as a single frame with a hard cap of 8 MiB; the per-room default is 2 MiB.
  In Chrome, JSON serialization turns this into roughly 11 MiB of base64, well under the
  message limit. Chunking is a Could.
- The allowlist is detected from magic bytes and content, never from the declared type
  alone: `text/plain`, `text/markdown`, `text/csv`, `application/json`, `image/png`,
  `image/jpeg`, `image/gif`, `image/webp`, `application/pdf`.
- These are always refused: HTML, SVG, XML, JavaScript, executables, archives, and any
  text file that begins like markup (`<!doctype`, `<html`, `<script`, `<svg`, `<?xml`).
  Text must be valid UTF-8 with no NUL bytes, and JSON must parse.
- File names are normalized to NFC. Path components, control characters, bidi and
  zero-width characters are stripped. Reserved Windows names are rejected. The last
  extension must match the detected type, so `x.pdf.exe` is rejected. Names are capped at
  128 characters.
- Validation happens **twice**: the sender checks before encrypting, and the receiver
  checks after decrypting, including that the SHA-256 in the metadata matches the bytes
  received. The router checks the header MIME against the grant and the size against the
  cap.
- Provenance recorded with each file: `{fromOrigin, fromKind, roomId, frameId, sha256,
  detectedType, size, sentAt, receivedAt}`. It is attached to the delivered `File` object
  and written to the audit log.
- **Limit:** there is no malware scanning. A structurally valid PDF or image can still
  exploit a vulnerable viewer. TabBridge never auto-opens or auto-downloads files; it
  hands them to the receiving agent as in-memory `File` objects.

## D7. Background persistence and restarts

MV3 service workers stop after about 30 s idle, which disconnects every port. Router state
(endpoints, rooms, sequence counters, pairings) is kept in `storage.session`. That storage
lives in memory and is gone after a browser restart. At `welcome`, each endpoint receives
a random 128-bit `resumeToken`, which it keeps only in the isolated world's memory. After
the background restarts, the endpoint reconnects with `{endpointId, resumeToken}`, and the
router accepts the resume only if the tab and origin still match. The endpoint keeps its
E2E keys throughout.

## D8. Where consent UI lives

All consent screens are extension pages: the action popup, the dashboard and the side
panel. None of them is ever drawn into web content. The only way a page can signal is
the badge set by `requestPairing()`.

---

## Threat model

**Assets:** prompt and response text, files, task state, the user's consent decisions, and
the audit log.

**Trust boundaries:**
1. Web page main world, including every script on that origin (untrusted relative to the
   extension)
2. Content script in the isolated world (partly trusted; it shares a renderer process with
   the page)
3. Background router (trusted)
4. Extension UI pages (trusted)
5. Other extensions and other tabs (untrusted)

| # | Attacker / attempt | Mitigation |
|---|---|---|
| T1 | A site that was not enabled probes for TabBridge or tries to talk to it | No host permission, so nothing is injected. Match patterns can't include ports, so the router checks the exact origin (scheme, host and port) at `hello`; if the origin is not enabled, the API is never defined. See OSQ-1 for the remaining signal. |
| T2 | A hostile page pairs itself with another tab without the user | Pairing can only be started or joined from extension UI, which pages can't reach (the UI port checks the extension origin). `requestPairing()` only sets a badge. |
| T3 | A hostile tab races a legitimate pairing | The code is shown only in extension UI, and the joiner review screen lists both origins. |
| T4 | Brute-forcing the pairing code | TTL of 120 s, 3 tries per code, a global lockout, and only UI can submit codes. |
| T5 | Spoofing a sender (`from`), its origin or its tab | The router derives identity from `port.sender` and overwrites or validates `from`. Origins in the transcript come from the router. |
| T6 | Replaying or reordering frames | Strict `seq = last + 1` per sender and room, checked at the router and again by the receiver, which tracks its own counter. `frameId` is deduplicated. |
| T7 | Tampering with a header (kind, size or MIME) to slip past policy | The header is AES-GCM AAD, so tampering fails decryption. The receiver checks the plaintext size and type against the header. |
| T8 | Sending kinds or types the grant doesn't allow | Router PEP plus a check at the sender endpoint. |
| T9 | Oversized payloads or flooding (DoS) | Caps per kind, a check that ciphertext length equals `size + 28`, a per-sender rate limit, a cap on rooms per endpoint, and bounded audit retention. |
| T10 | Disguised files (HTML renamed `.png`, polyglots, double extensions, bidi tricks in names) | Magic-byte detection, markup sniffing on text, name sanitization and extension/type match, checked on both ends. |
| T11 | An iframe on an enabled page posts fake handshake messages | Top frame only. The handshake requires `event.source === window` and accepts only the first port; frames from `frameId !== 0` are rejected. |
| T12 | A page script tampers with `window.tabBridge` or intercepts replies | The API is a frozen, non-writable property. **Accepted:** same-origin scripts are the agent's own trust unit, so they can use the API exactly as the agent can. |
| T13 | The page navigates to another origin while a room is open | New document, new endpoint with no keys. The old endpoint's resume fails and the room closes. Resume is bound to both tab and origin. |
| T14 | A frame is misrouted to the wrong tab (router bug) | The recipient can't decrypt it, reports a violation, and the room closes. |
| T15 | Other extensions | They can't connect to our ports: `externally_connectable` is not declared, and `onConnectExternal` is not handled. |
| T16 | Tampering with the audit log in storage | A hash chain with an anchor makes tampering evident: `verifyChain` fails. It is not tamper-proof against local malware. |
| T17 | A hostile endpoint floods the audit log with fake content records | The router accepts a content record only for a `frameId` it actually routed for that endpoint, once per direction. |
| T18 | A compromised renderer for the sending tab (code running in the isolated world) | The receiver re-validates independently. The router enforces headers. That renderer's own room is compromised, which is unavoidable. |

**Out of scope:** a compromised browser, OS or extension background; malicious content
inside valid files (D6); side channels such as timing and traffic sizes; users who approve
malicious pairings despite the warnings.

---

## OPEN SECURITY QUESTIONS

These were noticed during design and build but **not fully verified**. They go to the
dedicated security review session.

- **OSQ-1 Port-agnostic match patterns.** Chrome and Firefox match patterns ignore
  ports, so enabling `http://localhost:8080` also injects the isolated content script
  into `http://localhost:9000`. The router rejects the `hello` there and the API is never
  defined, but the MAIN-world shim still runs and posts one handshake `postMessage`,
  which a page could use to detect TabBridge. Need to measure how visible this is.
- **OSQ-2 Firefox Xray and `MessagePort` transfer between MAIN and ISOLATED.** This has
  not been tested automatically (there is no Firefox in CI). Need to confirm that
  `event.source === window` and `event.ports` behave the same way under Xray wrappers.
- **OSQ-3 Race in handshake port capture.** A page script that runs before our MAIN shim
  could post a fake `hs1` port first and receive our isolated world's `ready` event. This
  is same-origin, so it is within the accepted trust unit (T12), but check whether it
  enables anything beyond what the page could already do.
- **OSQ-4 Audit writes are debounced.** Entries are batched to `storage.local` (about
  250 ms). If the service worker is killed inside that window, recent entries could be
  lost. Consider write-through for `frame.*` records.
- **OSQ-5 Rate-limit and sequence state in `storage.session`** is written through on
  every frame. Check that concurrent frames arriving while the worker wakes cannot
  interleave in a way that lets a replayed `seq` through.
- **OSQ-6 Base64 and JSON parsing cost.** A near-8 MiB frame is parsed in the service
  worker and the receiver. Check memory spikes and whether a burst within the rate limit
  can exhaust the worker's memory.
- **OSQ-7 `resumeToken` handling.** The router stores only a SHA-256 of each token and
  compares it in constant time, and a resume must also match the tab ID, origin and kind.
  Still to verify: whether a compromised renderer holding one tab's token can do anything
  beyond resuming that same tab's endpoint.
- **OSQ-8 Page scripts can observe `tabbridge:ready` and handshake timing.** Minor
  fingerprinting, on enabled origins only.
- **OSQ-9 PDF and image payloads.** They pass validation but may carry exploits. Receivers
  get `File` objects; check that no TabBridge UI (such as the side panel) renders received
  images or PDFs inline without sandboxing.
- **OSQ-10 Narrowing a grant is not re-bound in the E2E transcript.** The key stays
  derived from the original grant. The router enforces the narrower grant, but the
  receiver endpoint also needs the updated grant (sent in `room-update`) and should
  enforce it. Verify that it does.
- **OSQ-11 Chrome `sender.origin` vs `sender.url`.** The fallback to `new URL(sender.url)`
  on Firefox and older Chrome needs checking for `about:blank`, `blob:`, `data:` and
  opaque-origin documents. These should all be rejected.
- **OSQ-12 Side-panel endpoint identity.** The router recognizes the panel by its
  extension URL. Confirm that no other extension page can impersonate it, and whether
  several panels (one per window) should share a single identity.
