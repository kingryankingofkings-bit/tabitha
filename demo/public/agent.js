// TabBridge demo agent. Uses ONLY the public API (window.tabBridge, apiVersion 1).
// Two personas share this file: "planner" and "researcher" (from <body data-role>).
// The "AI" here is a deterministic mock so the demo and E2E tests are reproducible;
// swap `think()` for a real model call to use a live agent.
'use strict';

(() => {
  const role = document.body.dataset.role === 'researcher' ? 'researcher' : 'planner';
  const agentName = role === 'planner' ? 'Planner (demo)' : 'Researcher (demo)';
  const $ = (id) => document.querySelector(`[data-testid="${id}"]`);
  let session = null;
  let activeRoomId = null;

  // A real 1x1 PNG, and an HTML payload disguised with a .png name (must be rejected).
  const PNG_B64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
  const pngBytes = () => Uint8Array.from(atob(PNG_B64), (c) => c.charCodeAt(0));

  function log(kind, text, extra = {}) {
    const li = document.createElement('li');
    li.dataset.testid = 'log';
    li.dataset.kind = kind;
    for (const [k, v] of Object.entries(extra)) li.dataset[k] = String(v);
    const tag = document.createElement('span');
    tag.className = 'tag';
    tag.textContent = kind;
    const body = document.createElement('span');
    body.textContent = text; // never innerHTML: peer content is untrusted
    li.append(tag, body);
    $('log-list').prepend(li);
  }

  function setStatus(s) {
    $('tb-status').textContent = s;
  }

  // Deterministic mock "model".
  function think(prompt) {
    if (role === 'researcher') {
      const words = prompt.split(/\s+/).filter(Boolean);
      return `Research notes on "${prompt}": found ${words.length} key terms; top source agrees. Confidence: high.`;
    }
    return `Plan for "${prompt}": 1) scope it, 2) gather sources, 3) draft, 4) review.`;
  }

  function renderRooms(rooms) {
    const ul = $('rooms');
    ul.replaceChildren();
    for (const r of rooms) {
      const li = document.createElement('li');
      li.dataset.testid = 'room';
      li.dataset.roomId = r.roomId;
      li.dataset.state = r.state;
      li.textContent = `${r.state.toUpperCase()} · peer ${r.peer.origin}${r.peer.agentName ? ` (${r.peer.agentName})` : ''} · you may send: ${[
        r.outbound.prompts && 'prompts',
        r.outbound.tasks && 'tasks',
        r.outbound.files && `files [${r.outbound.fileTypes.join(', ')}]`,
      ]
        .filter(Boolean)
        .join(', ') || 'nothing'}`;
      ul.append(li);
    }
    const active = rooms.find((r) => r.state === 'active');
    activeRoomId = active ? active.roomId : null;
    for (const b of document.querySelectorAll('button[data-needs-room]')) b.disabled = !activeRoomId;
  }

  async function refreshRooms() {
    if (session) renderRooms(await session.rooms());
  }

  async function withRoom(fn) {
    if (!activeRoomId) return log('error', 'No active room — pair this tab first.');
    try {
      await fn(activeRoomId);
    } catch (e) {
      log('error', `${e.code ?? 'ERROR'}: ${e.message}`, { code: e.code ?? 'ERROR' });
    }
  }

  async function main() {
    // Graceful degradation: wait briefly for the extension, else run standalone.
    const tb =
      window.tabBridge ??
      (await new Promise((resolve) => {
        const t = setTimeout(() => resolve(null), 3000);
        addEventListener('tabbridge:ready', () => { clearTimeout(t); resolve(window.tabBridge); }, { once: true });
      }));
    if (!tb) {
      setStatus('unavailable');
      log('info', 'TabBridge is not available on this page (not installed or not enabled for this site). Running standalone.');
      // Late enablement (user enables the site after load) still works:
      addEventListener('tabbridge:ready', () => location.reload(), { once: true });
      return;
    }
    setStatus('ready');
    session = await tb.connect({ apiVersion: 1, agentName });
    setStatus('connected');
    log('info', `Connected as "${agentName}" (TabBridge ${tb.version}, API v${session.apiVersion}).`);

    session.on('room', (r) => {
      log('room', `Room ${r.roomId.slice(0, 8)} is ${r.state}${r.closedReason ? ` (${r.closedReason})` : ''}`, { state: r.state });
      refreshRooms();
    });
    session.on('prompt', async (m) => {
      log('prompt-in', m.text, { from: m.from.origin });
      const taskId = `task-${m.id.slice(0, 8)}`;
      try {
        await session.sendTask(m.roomId, { taskId, status: 'running', progress: 0.5, summary: 'thinking…', threadId: m.threadId });
      } catch (e) {
        log('error', `task update failed: ${e.code}`);
      }
      await m.reply(think(m.text));
      log('response-out', `replied to ${m.id.slice(0, 8)}`);
      try {
        await session.sendTask(m.roomId, { taskId, status: 'done', progress: 1, summary: 'answered', threadId: m.threadId });
      } catch (e) {
        log('error', `task update failed: ${e.code}`);
      }
    });
    session.on('response', (m) => log('response-in', m.text, { inReplyTo: m.inReplyTo }));
    session.on('task', (t) => log('task-in', `${t.task.taskId}: ${t.task.status}${t.task.summary ? ` — ${t.task.summary}` : ''}`, { status: t.task.status }));
    session.on('file', (f) => {
      log('file-in', `${f.file.name} (${f.file.type}, ${f.file.size} B) sha256=${f.provenance.sha256.slice(0, 16)}… from ${f.provenance.fromOrigin}`, {
        name: f.file.name,
        sha256: f.provenance.sha256,
      });
    });
    session.on('error', (e) => log('error', `${e.code}: ${e.message}`, { code: e.code }));
    await refreshRooms();
  }

  $('ask').addEventListener('click', () =>
    withRoom(async (roomId) => {
      const q = $('question').value.trim() || (role === 'planner' ? 'What are the risks of cross-tab AI agents?' : 'How should we structure the report?');
      log('prompt-out', q);
      const reply = await session.ask(roomId, q, { timeoutMs: 30_000 });
      log('answer', reply.text, { inReplyTo: reply.inReplyTo });
    }),
  );
  $('send-png').addEventListener('click', () =>
    withRoom(async (roomId) => {
      const r = await session.sendFile(roomId, new Blob([pngBytes()], { type: 'image/png' }), { name: 'chart.png' });
      log('file-out', `chart.png delivered (${r.frameId.slice(0, 8)})`);
    }),
  );
  $('send-disguised').addEventListener('click', () =>
    withRoom(async (roomId) => {
      const html = new Blob(['<!doctype html><script>alert(1)</script>'], { type: 'image/png' });
      await session.sendFile(roomId, html, { name: 'totally-an-image.png' });
      log('file-out', 'UNEXPECTED: disguised file was accepted');
    }),
  );
  $('send-picked').addEventListener('click', () =>
    withRoom(async (roomId) => {
      const f = $('file-input').files[0];
      if (!f) return log('error', 'Pick a file first.');
      await session.sendFile(roomId, f);
      log('file-out', `${f.name} delivered`);
    }),
  );
  $('request-pairing').addEventListener('click', async () => {
    if (!session) return;
    await session.requestPairing({ note: `${agentName} would like to pair` });
    log('info', 'Pairing requested — open the TabBridge toolbar popup to continue.');
  });

  main().catch((e) => {
    setStatus('error');
    log('error', `${e.code ?? 'ERROR'}: ${e.message}`);
  });
})();
