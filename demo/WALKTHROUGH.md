# TabBridge end-to-end walkthrough

This walkthrough pairs two tabs, runs an AI prompt exchange in both directions, and
transfers a file that is validated on both ends. You can run it automatically or by hand.

## A. Automated (about 20 s, headless Chromium)

```bash
npm install
npm run demo            # builds dist/chrome-e2e, then runs demo/run-demo.mjs
HEADED=1 npm run demo   # same, in a visible browser window (needs a display)
```

The script prints each step:

1. Two demo agents open on **two origins**: `http://127.0.0.1:<A>/planner.html` and
   `http://127.0.0.1:<B>/researcher.html`. Before the sites are enabled,
   `window.tabBridge` is absent, and the pages report `unavailable` and keep running
   standalone (graceful degradation).
2. The user enables TabBridge on both origins from the popup.
3. The Planner tab starts pairing and picks its permissions: both directions may send
   prompts and tasks, and only Planner→Researcher may send PNG files. The popup shows a
   6-digit code. In the Researcher tab's popup, the user enters the code, reviews both
   origins and both directions, and approves. Both sides exchange and confirm keys, and
   the room becomes ACTIVE.
4. **Bidirectional loop:** Planner calls `ask()`. Researcher's agent answers with `reply()`
   and posts task updates (`running` → `done`). Then Researcher calls `ask()` and Planner
   answers.
5. **Files:** Planner sends a real PNG, which is delivered with provenance and a SHA-256.
   Planner then tries an HTML file named `.png`, which is refused before it leaves the tab
   (`FILE_TYPE_MISMATCH`). Researcher tries to send a file, which is refused with
   `NOT_PERMITTED` because that direction wasn't granted.
6. **Audit:** the dashboard lists every routing and content record, and *Verify chain*
   reports the chain intact.
7. **Revocation:** closing the room in the popup closes it for both agents.

The same flow runs with assertions in `npm run test:e2e` (`test/e2e/extension.spec.ts`).

> `dist/chrome-e2e` is identical to `dist/chrome` except that it pre-grants host access to
> `localhost`/`127.0.0.1`, because automated browsers can't click the browser's permission
> prompt. Enabling a site still goes through TabBridge's own `site.enable` flow and exact-origin check.

## B. Manual (Chrome, Edge or Brave)

1. `npm run build`, then load `dist/chrome` unpacked (`chrome://extensions` → Developer mode →
   Load unpacked).
2. `npm run demo:serve`. It serves `http://127.0.0.1:5301/planner.html` and
   `http://127.0.0.1:5302/researcher.html`. Open each in its own tab.
3. In each tab, open the TabBridge popup and choose **Enable TabBridge on …**. Accept the
   browser's permission prompt. The page status changes to `connected` (the page reloads
   itself once the API appears).
4. In the Planner tab's popup, choose **Start pairing**, pick permissions, and **Start**.
   Note the code.
5. In the Researcher tab's popup, choose **Join with code**, enter the code, review the
   origins and permissions, and **Approve**.
6. In Planner, type a question and choose **Ask (await reply)**. The Researcher mock agent
   answers, and task updates arrive. Repeat from the Researcher tab.
7. Choose **Send sample PNG** (accepted), then **Send HTML disguised as .png** (refused).
8. Open the dashboard (popup → *Open dashboard*) to browse the audit log and choose
   **Verify chain**.
9. Optional: open the **Agent Console** side panel and pair it with a tab to act as a manual
   "sidebar agent" for a page that has no agent of its own.

## C. Manual Firefox checklist (not covered by automated tests)

Firefox is a supported build target, but CI only runs Chromium, so verify these by hand
on Firefox ≥ 128:

- [ ] `npm run build`, then `about:debugging` → *Load Temporary Add-on* →
      `dist/firefox/manifest.json`. It loads with no manifest warnings about unsupported keys.
- [ ] Enabling a site from the popup shows Firefox's host-permission prompt. If the popup
      closes during the prompt, the site still ends up enabled (router
      `permissions.onAdded`).
- [ ] `window.tabBridge` appears only on enabled origins. The MAIN↔ISOLATED `MessagePort`
      handshake works under Xray wrappers (DECISIONS.md OSQ-2).
- [ ] Pairing, the conversation, task updates, and the PNG transfer and disguised-file
      rejection all behave as in section B.
- [ ] The sidebar (`sidebar_action`) Agent Console can pair and reply.
- [ ] Closing a tab closes its rooms. After the event page is suspended and resumed,
      rooms keep working (resume token).
