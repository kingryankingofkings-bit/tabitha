# TabBridge — Security Review

Reviewer: dedicated security-audit session
Commit reviewed: `84b1f8d` (branch `claude/tabbridge-extension-mvp-lmsx1a`)
Scope: whole extension (`src/**`), build (`scripts/build.mjs`), manifests, docs.
Method: read every module against SPEC/DECISIONS/README, then verified behavior
against the implementation (one finding confirmed with a Router-level probe, since
removed). No fixes were applied.

## Summary

The security model is, for the most part, implemented as documented and is
well-constructed. The strong parts are genuinely strong:

- **Origin is taken only from the browser.** Sender identity is derived from
  `port.sender` in `classifyEndpointSender` (`src/background/router.ts:241`) and never
  from message fields; the frame path overwrites/validates `header.from` against the
  port's endpoint (`router.ts:1230`), and the receiver additionally pins `from` to the
  transcript peer (`src/endpoint/endpoint.ts:850`).
- **The API is not present on non-enabled origins.** The isolated script only announces
  itself and only lets `window.tabBridge` be defined after the router returns `welcome`
  (`src/content/isolated.ts:147`, `src/content/page-api.ts:395`); a `rejected` hello
  leaves nothing defined.
- **Pages cannot self-pair.** `requestPairing` only sets a badge (`router.ts:1014`);
  `pair.start/lookup/approve` are reachable only over the `tb.ui` port, which
  `connectUi` restricts to this extension's own pages (`router.ts:400`).
- **Encryption is sound.** ECDH P-256 (non-extractable) → HKDF-SHA-256 with the salt =
  roomId and info bound to a transcript hash that commits to both keys, both origins and
  the grant → AES-256-GCM with the header authenticated as AAD, random 96-bit IV per
  frame (`src/shared/crypto.ts`). Keys live only in memory; the resume token is stored
  only as a SHA-256 and compared in constant time (`router.ts:935`). No key material is
  logged or persisted.
- **File validation** runs on the sender and independently on the receiver, with a
  magic-byte allowlist, denied-signature list, active-content sniffing, strict UTF-8/
  control-char rules, name sanitization, and a SHA-256 re-check on receipt
  (`src/files/validate.ts`, `endpoint.ts:952`).
- **No unsafe DOM sinks** in the UI: everything is built with `createElement`/
  `textContent`; `h()` forbids `innerHTML`/`srcdoc`/`javascript:` URLs
  (`src/ui/lib/dom.ts:7`,`:31`). No prototype-pollution path was found; record maps are
  guarded by `own()`/`Map`, and audit `data` is sanitized with `Object.defineProperty`
  (so a `__proto__` key becomes an own property, `src/background/audit.ts:131`).

The findings below are, with one exception, Medium and lower. The most important is a
**consent-binding gap at pairing approval (M1)**: approval re-resolves the joiner by tab
id and is not tied to the endpoint/origin the user reviewed, so the room can open bound
to a different (already-enabled) origin than the one shown on the consent screen. The
second (M2) is that the plaintext content records in the audit log are **self-reported by
endpoints and optional**, so the "full audit log of everything an AI sent or received"
holds at the metadata level but not, guaranteed, at the content level.

No Critical finding. No web-reachable path was found that moves data between tabs without
a user approving a pairing.

| ID | Severity | Title |
|----|----------|-------|
| M1 | Medium | Pairing approval binds to the joiner tab, not the reviewed endpoint/origin (consent TOCTOU) |
| M2 | Medium | Audit content records are endpoint-self-reported and optional (completeness/fidelity vs. the "full audit" claim) |
| L1 | Low | Audit hash chain is unkeyed; README calls it "tamper-evident" without the caveat |
| L2 | Low | Pairing global lockout is a self-inflicted denial-of-service; failure counter resets on legitimate `start` |
| L3 | Low | Fixed-window rate limit permits a 2× burst across window edges |
| L4 | Low | Large-frame parsing cost in the service worker (memory/CPU spike) |
| L5 | Low | Any extension page at `ui/sidepanel.html`, and the pop-out `?tabId=N`, are treated as trusted without further binding |
| L6 | Low | Router state and audit persistence fail open / can lose the most recent entries |
| I1–I6 | Info | Full-text audit exposure, peer-chosen timestamps, polyglot files, Firefox unverified, detection signal, HTTP peers |

Every item in DECISIONS.md's OPEN SECURITY QUESTIONS is resolved in the final section.

---

## Medium

### M1. Pairing approval binds to the joiner *tab*, not the endpoint/origin the user reviewed

**Files:** `src/background/router.ts:1350` (`resolveConnected`), `router.ts:1508`–`1572`
(`pair.approve`), `src/ui/lib/pairing.ts:266` (approve handler passes `{tabId}`).

**What the model claims.** DECISIONS D3/T3 and the README say the join screen shows both
origins and "Before approving, I can see … exactly what each side may send," i.e. the
user approves *those origins*.

**What the code does.** `pair.lookup` builds the preview's joiner origin from the endpoint
resolved *at lookup time* (`router.ts:1497`,`1501`). `pair.approve` independently calls
`resolveConnected(sel)` again (`router.ts:1514`), where `sel = {tabId}` comes from the
popup (`pairing.ts:268`,`110`). `resolveConnected({tabId})` returns *the most-recently
created connected page endpoint for that tab* (`router.ts:1355`). The initiator is pinned
— approve re-checks `irec.origin === res.initiator.origin` and the exact endpointId
(`router.ts:1537`) — but there is **no equivalent check that the joiner still is the
endpoint/origin shown in the preview.** If the joiner tab's document changes to a
different *already-enabled* origin between review and the approve click, the room opens
bound to the new origin.

**Confirmed.** A Router-level probe (enable `a`, `b-good`, `c-evil`; start on tab 1;
`lookup` on tab 2 while it is `b-good` → preview shows `https://b-good.example`; disconnect
tab 2's endpoint and connect a new one on the same tab id with origin
`https://c-evil.example`; `approve` on tab 2) opens the room with the **joiner member
origin = `https://c-evil.example`**, i.e. not the origin the preview displayed. The probe
asserted exactly this and passed.

**Attack scenario.** The initiator A is a trusted agent the user is about to hand prompts/
files to. The user opens the join popup on a tab showing a site they trust and have
enabled (B), and reviews "joining as B". A page that can drive that tab's navigation to a
second enabled origin C (an attacker origin the user also enabled, or a trusted origin the
attacker can redirect through) flips the tab to C during the short manual approval window.
On approve, A's grant now applies to C, and A's subsequent prompts/files go to C — an
origin the user did not review. Provenance and the audit log will faithfully record C
(they read the transcript peer, see Q6), so the record is consistent but the *consent* was
for B.

**Why Medium, not High.** Both origins must already be user-enabled, the attacker must
control the joiner tab's navigation, and it is a race against a manual click. It is not a
full consent bypass (a room still requires an approval), but it does break the specific
guarantee that the approved origins are the bound origins.

**Fix.** Bind approval to the reviewed endpoint, not the tab. Have `pair.lookup` return an
opaque `previewId` (or the resolved `endpointId`), and require `pair.approve` to carry it;
in `approve`, re-resolve and verify the joiner endpoint's `endpointId` **and** `origin`
match the previewed values (mirroring the initiator re-check at `router.ts:1537`), failing
with `PEER_UNAVAILABLE`/`PAIRING_EXPIRED` if the tab now hosts a different endpoint. The UI
already reviews per lookup, so this is a router-side tightening.

### M2. Audit content records are endpoint-self-reported and optional

**Files:** `src/background/router.ts:1143` (`onAuditDetail`), `router.ts:1287`–`1299`
(`frame.routed`), `src/endpoint/endpoint.ts:793`,`993` (endpoints choose whether/what to
report).

**What the model claims.** The concept and README describe "a full audit log of
everything an AI sent or received."

**What the code does.** For each routed frame the router *always* writes a `frame.routed`
metadata record with `from`, `to`, `kind`, `size`, `seq` and `ctSha256`
(`router.ts:1289`) — this part is guaranteed and tamper-evident. The **plaintext**
content, however, is only ever written from an `audit-detail` message that the endpoints
send voluntarily (`content.sent` from the sender, `content.received` from the receiver,
`router.ts:1155`). The router cannot verify it, because it never has the key (by design,
E2E). Consequences:

1. **Withholding:** a malicious or buggy endpoint can simply never send `audit-detail`.
   The frame is still delivered and `frame.routed` still logged, but there is **no
   plaintext record** of what was sent/received — only kind/size/hash.
2. **Forgery of the "sent" side:** `onAuditDetail` checks only that the endpoint was the
   sender of a routed frame of that `kind`, once (`router.ts:1148`). It does **not** check
   `detail.sha256` against anything (the router only knows `ctSha256` over ciphertext).
   A compromised sending renderer can log a `content.sent` whose text differs from the
   bytes it actually encrypted and sent. (The receiver's independent `content.received`
   still reflects the true decrypted content, so the receive side remains trustworthy when
   the receiver is honest.)

**Impact.** The differentiator "a full audit log of everything an AI sent or received"
holds at the **metadata** level (always captured, hash-chained) but is **best-effort at
the content level**. An auditor cannot rely on the presence or exact text of `content.*`
records when either endpoint is hostile.

**Fix / documentation.** This is partly inherent to E2E + full-text audit and should be
stated as such in DECISIONS (today it is not called out). To raise the floor: (a) treat a
missing `content.received` for a delivered frame as an auditable anomaly (the router can
emit a `content.missing` marker after a timeout, since it knows a frame was routed);
(b) note in DECISIONS/README that `content.sent` is self-reported and that `content.*`
fidelity depends on endpoint integrity, while `frame.routed` (kind/size/`ctSha256`) is the
authoritative record.

---

## Low

### L1. Audit hash chain is unkeyed; "tamper-evident" is overstated in the README

**Files:** `src/background/audit.ts:57` (`hashEntry` = plain SHA-256 over `prevHash + '\n'
+ canonicalJson`), README line 9 ("a tamper-evident audit log").

`verifyChain` detects any edit that does not also recompute every subsequent hash. But the
chain has **no secret**: anything that can write `storage.local` (the extension itself, or
local malware with profile access) can drop the oldest entries and reset `anchor`, or
rewrite the entire log into a fresh internally-consistent chain, and `verify()` will pass.
DECISIONS T16 already says "not tamper-proof against local malware," and this is a
reasonable design choice for a browser extension — but the **README's unqualified
"tamper-evident"** oversells it. In-page scripts genuinely cannot alter it (content
scripts have no `chrome.storage` access, and `storage.session` stays `TRUSTED_CONTEXTS`,
`src/background/index.ts:79`); only trusted contexts and local malware can.

**Fix (doc):** qualify the README to "tamper-evident against in-page and cross-tab
tampering; not tamper-proof against code with local disk/extension-storage access." (No
keyed MAC is possible without a key the same attacker could read; if stronger evidence is
wanted, chain-anchor to an external append-only sink — out of MVP scope.)

### L2. Pairing lockout is a self-inflicted DoS; failure counter resets on legitimate `start`

**File:** `src/background/pairing.ts:159` (`recordFailure`), `pairing.ts:155` (`start`
resets `failuresSinceReset`).

Two observations, both already partly noted in OSQ-15:
- More than `PAIRING_GLOBAL_FAILS_PER_MIN` (10) wrong lookups in 60 s lock **all** pairing
  for 60 s (`pairing.ts:169`). Only extension UI can submit codes, so this is not
  remotely reachable, but a user who fat-fingers codes can lock themselves out, and any
  trusted extension page could trivially trigger it.
- `start` sets `failuresSinceReset = 0` (`pairing.ts:155`), so guesses interleaved with
  legitimate starts get slightly more than `PAIRING_MAX_FAILURES` tries against the code
  space before the "burn all active codes" rule fires. With a 10⁶ code space, 120 s TTL
  and the 10/min global cap, brute force remains impractical; this is a minor weakening of
  the per-code bound, not a break.

**Fix:** consider decoupling the global-failure lock from the per-initiator counter, and/or
not resetting `failuresSinceReset` on `start`. Low priority.

### L3. Fixed-window rate limit permits a 2× burst across a window edge

**File:** `src/background/permissions.ts:253` (`checkRate`, fixed 60 s window).

A fixed window (not sliding) allows up to `framesPerMinute` at the end of one window and
`framesPerMinute` again at the start of the next, i.e. ~2× the nominal rate across the
boundary (OSQ-17). With 60 frames/min and 16 MiB/min this is a minor DoS lever only.
A backwards clock lengthens the current window. **Fix:** sliding window or token bucket if
tighter bounds are wanted.

### L4. Large-frame parsing cost in the service worker

**Files:** `src/shared/protocol.ts` (`base64DecodedLength` is arithmetic — good), but the
router computes `sha256Hex(utf8Encode(ct))` over the full base64 string for every routed
frame (`router.ts:1286`), and the receiver base64-decodes, `JSON.parse`s and re-validates
up to ~8 MiB (`endpoint.ts`, `validate.ts:324`).

A near-8-MiB frame (≈11 MiB base64) is hashed in the worker and fully parsed/validated in
the receiver renderer. The per-sender rate limit (16 MiB/min) bounds sustained throughput,
but a burst can cause a transient memory/CPU spike (OSQ-6/25). Not a vulnerability on its
own; worth a bounded-work note. **Fix:** the SPEC already defers chunking; consider a lower
default `maxFileBytes` and/or hashing the decoded bytes lazily.

### L5. `ui/sidepanel.html` and the pop-out `?tabId=N` are trusted without further binding

**Files:** `src/background/router.ts:241` (any this-extension page at `PANEL_PATH` →
`kind:'panel'`), `src/ui/popup/main.ts:414` (pop-out opens `popup.html?tabId=<n>`).

- Any page of *this* extension served at `/ui/sidepanel.html` is classified as the panel
  endpoint with origin `tabbridge://console` (OSQ-12/20). Because there are no
  `web_accessible_resources` and pages cannot navigate to extension URLs, this is not
  web-reachable; the risk is only that the panel identity is path-based rather than tied to
  the actual side-panel surface. Low.
- The pop-out and E2E popup accept `?tabId=N` and will drive UI actions against any tab id
  (OSQ-26). Again only openable by the user / this extension, but it means "the popup is
  scoped to the active tab" is not enforced structurally. **Fix:** if desired, gate
  `?tabId` behind an internal nonce, or restrict panel classification to the actual side
  panel context.

### L6. Persistence fails open / can lose the most recent entries

**Files:** `src/background/router.ts:487` (save error logged, routing continues on
in-memory state), `src/background/audit.ts:361` (throttled save; up to `flushDelayMs`
of entries can be lost if the worker is killed).

Router state and audit persistence both fail soft: a failed `storage.session`/
`storage.local` write is logged and operation continues (OSQ-18/4). This is the right
availability choice, but it means the newest audit entries can be lost on an abrupt worker
kill, and router state can diverge from disk. Low; document the window and consider
write-through for `frame.routed`/`content.*` if audit durability is a hard requirement.

---

## Informational / confirmed-safe-as-designed

- **I1 — Full-text audit is readable by any trusted extension page** (`audit.export`/
  `audit.list`, `router.ts:1641`,`1660`). By design (D0.2, OSQ-27): the log holds full
  prompt/response text, and export writes plaintext to disk. No untrusted context can
  reach it, but a user should understand the export contains cleartext. Consider a
  one-line warning on export.
- **I2 — Peer-chosen `sentAt`** (`endpoint.ts:938`,`949`,`970` copy `h.ts` into delivered
  messages/provenance). Authenticated (AAD) but not sanity-checked (OSQ-23); an endpoint
  can set an implausible timestamp on its own messages. Cosmetic.
- **I3 — Polyglot files** (OSQ-9/24). A structurally valid image/PDF carrying appended
  script passes validation; the receiver gets a `File` with the *detected* type. Safe only
  as long as consumers keep that MIME and nothing renders it inline. The side panel does
  not render images/PDFs inline and previews text only via `textContent`
  (`src/ui/sidepanel/main.ts:386`), and `downloadBytes` saves as
  `application/octet-stream` with the object URL revoked after 1 s (`dom.ts:192`) —
  confirmed safe within the extension; the caveat is for external agents.
- **I4 — Firefox paths are unverified here** (no Firefox in this environment): the
  MAIN↔ISOLATED `MessagePort` handshake under Xray (OSQ-2), `registerContentScripts({world:
  'MAIN'})`, `storage.session`, and `sidebar_action` (OSQ-29). Code paths look correct
  against `@types/chrome`, but they need a real Firefox 128+ run (the manual checklist in
  `demo/WALKTHROUGH.md §C` covers this).
- **I5 — Detection signal on enabled origins** (OSQ-1/8). On an enabled origin the MAIN
  shim posts a handshake and dispatches `tabbridge:ready`, observable to page scripts. This
  is same-origin (the origin's own trust unit) and expected. On a *non*-enabled origin
  sharing a host but a different port, the isolated script's `hello` is rejected and
  nothing is defined, but the MAIN shim still runs and posts one `hs1` (OSQ-1) — a minor
  fingerprinting bit. Accept or scope match patterns more tightly if desired.
- **I6 — Plain-HTTP peers.** Pairing warns when either side is HTTP (`pairing.ts:218`) but
  allows it; content on an HTTP origin can be altered on the network. Documented risk;
  the warning is good.

---

## Answers to the review's seven questions

1. **Consent gating.** Enforced on the paths that matter: no API on non-enabled origins;
   pairing start/approve only via the trusted UI port; `requestPairing` only sets a badge;
   frames require an `active` room whose grant was set at an approved pairing; error/retry
   paths (reconnect, resume) re-derive identity from `port.sender` and cannot manufacture a
   room. **One gap:** approval is bound to the joiner *tab*, not the reviewed endpoint
   (**M1**), so the bound origin can differ from the displayed one. No path was found that
   moves data with *no* approval.
2. **Message handling.** Validators are strict and reject unknown keys/types
   (`src/shared/protocol.ts`); the header is validated before use on the frame fast-path
   (`router.ts:1215`). No prototype-pollution path found (record maps guarded by `own()`/
   `Map`; audit `data` sanitized via `defineProperty`). File metadata and prompt payloads
   cannot inject into the UI (no HTML sinks). Schema is single-version `v:1` with
   `UNSUPPORTED_VERSION` on mismatch; no downgrade path exists.
3. **Pairing and trust.** Codes are 6-digit, single-use, 120 s TTL, 3-tries-then-burn,
   with a global lockout; replay of a consumed code fails (`pairing.ts`). Spoofing the
   sender is blocked (identity from the port). Revocation (`room.close`, narrowing, global
   pause, site-disable, tab-close, expiry) is immediate and checked at the start of every
   op and on every frame (`router.ts:746`,`1209`+). The one weakness is the approval
   binding (**M1**); lockout is a self-DoS (**L2**).
4. **Encryption.** Correct primitives, transcript-bound key derivation, header-as-AAD,
   per-frame random IV, non-extractable keys, constant-time token/hash comparisons, no keys
   in logs or storage, single version (no downgrade). Confirmed safe.
5. **Audit log.** Append-only and hash-chained in memory and on disk; in-page scripts
   cannot reach it (no content-script storage access; `storage.session` trusted-only). It
   is tamper-*evident* against in-page/cross-tab tampering but **not** tamper-proof against
   code with extension-storage/disk access, because the chain is unkeyed (**L1**), and
   plaintext content records are self-reported and optional (**M2**). Metadata records
   (`frame.routed`) are always written and are the authoritative record.
6. **Provenance.** Cannot be falsified by a sender's payload: `from`/`fromOrigin` are taken
   from the verified transcript peer (`endpoint.ts:920`,`970`), and inbound frames must
   carry `from == transcript peer` (`endpoint.ts:850`). Provenance faithfully reflects the
   room's peer; the *correctness of that peer's origin* depends on approval binding (**M1**).
7. **OPEN SECURITY QUESTIONS** — resolved below.

### Resolution of DECISIONS.md OPEN SECURITY QUESTIONS

| OSQ | Resolution |
|-----|-----------|
| 1 Port-agnostic match patterns | Confirmed-safe with residual signal. Router rejects the `hello` on the wrong port; API never defined. Minor detection bit (I5). |
| 2 Firefox Xray / MessagePort | **Unverified** here (no Firefox). Needs a real Firefox 128+ run (I4). |
| 3 Handshake port capture race | Confirmed-safe *within the same origin's trust unit* (T12). A same-origin script can grab the port but gains nothing it couldn't already do as the agent. See I5/L-none. |
| 4 Audit debounce | Confirmed as designed; small loss window on abrupt worker kill (**L6**). |
| 5 Rate/seq state in storage.session | Confirmed-safe. State is written through before messages are posted (outbox pattern, `router.ts:481`); seq is only advanced on accept and not on reject; replay uses `seq == last+1` + a recent-frameId set. No interleave found. |
| 6 Base64/JSON cost | Real but low: transient CPU/memory on large frames, bounded by rate limit (**L4**). |
| 7 resumeToken handling | Confirmed-safe. Stored as SHA-256, constant-time compared, bound to tabId+origin+kind, rotated on each resume (`router.ts:935`,`950`). |
| 8 ready/handshake observability | Confirmed-safe (same-origin, expected). Minor fingerprinting (I5). |
| 9 PDF/image payloads | Confirmed-safe inside the extension (no inline render; octet-stream download). Polyglot caveat for external consumers (I3). |
| 10 Narrowing not re-bound in transcript | Confirmed-safe. The endpoint enforces `intersect(RoomView, transcript-bound grant)` with the earlier expiry (`endpoint.ts:624`); narrowing takes effect, widening is impossible. |
| 11 sender.origin vs sender.url | Confirmed-safe. Both are cross-checked and must agree; opaque/`blob:`/`data:`/`about:` are rejected (`router.ts:250`–`271`). |
| 12 Side-panel identity | Low (**L5**): path-based panel classification, not web-reachable. |
| 13 Unkeyed audit anchor | As-designed but README overclaims (**L1**). |
| 14 File-frame size slack | Confirmed-safe. The 1028-byte slack at the router is envelope overhead; the receiver enforces the exact file-byte cap (`endpoint.ts:954`). |
| 15 Pairing counter reset | Low (**L2**). |
| 16 Codes in storage.session | Confirmed-acceptable. `storage.session` is in-memory and trusted-context-only; codes are short-lived. Not reachable by content scripts. |
| 17 Fixed-window rate limit | Low (**L3**). |
| 18 Persistence fails open | Low (**L6**), correct availability trade-off. |
| 19 Duplicate endpoints per tab | Confirmed-safe. `LOADED_FLAG`/`hasOwnProperty(w,'tabBridge')` guard double-injection (`isolated.ts:63`, `page-api.ts:21`); router picks the most-recent live endpoint per tab (which is the mechanism behind M1, not a separate bug). |
| 20 sidepanel.html as a tab | Low (**L5**). |
| 21 Handshake port visibility | Confirmed-safe within the same-origin trust unit (T12). |
| 22 Seq desync after resume | Confirmed as a robustness issue, not a security break: a re-posted, already-accepted frame that later gets an early-stage rejection can strand the sender's counter, failing subsequent sends **closed** (`endpoint.ts:790`). No bytes leak; the room simply stops working. Worth hardening. |
| 23 Peer-chosen timestamps | Info (I2). |
| 24 Polyglots / bidi in text | Info (I3). Text file *contents* are not scanned for bidi (only names are); acceptable and documented. |
| 25 Main-thread cost | Low (**L4**). |
| 26 Side-panel gesture / pop-out tabId | Low (**L5**). |
| 27 Audit export shows plaintext | Info (I1), by design. |
| 28 Timers in a suspended worker | Confirmed-safe. The 1-minute `alarms` sweep plus start-of-op `housekeeping()` bound any missed `setTimeout` to ~1 minute (`router.ts:746`, `index.ts:115`). |
| 29 Firefox APIs | **Unverified** (I4). |

---

## Verdict

**The core claim — "nothing moves between tabs without the user approving the pairing and
its permissions" — holds as implemented in its strongest form: no room, and therefore no
cross-tab message, exists without an explicit approval through trusted extension UI, and
the API is absent on origins the user has not enabled.**

It does **not** fully hold in its stricter form — "you approve the pairing *and its
origins*." Because approval is bound to the joiner tab rather than to the endpoint whose
origin was reviewed (**M1**, confirmed), the origin that ends up bound to the room can
differ from the one shown on the consent screen when the joiner tab is navigated to another
already-enabled origin during the approval window. Combined with the audit log's content
records being endpoint-self-reported and optional (**M2**), the two central differentiators
— consent-gated origins and a full content audit — each have a real gap that should be
closed before the model is advertised without caveats.

Recommended before release: fix **M1** (bind approve to the reviewed endpointId+origin),
address **M2** (mark self-reported content and/or flag missing `content.received`), and
correct the **L1** README wording. Everything else is Low/Informational and can be
scheduled. Encryption, origin isolation, input validation, file safety and the no-self-pair
guarantee are solid.
