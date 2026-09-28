// Minimal static server for the demo agent pages. Serving the same files on two ports gives
// two distinct origins (http://127.0.0.1:<portA> and http://127.0.0.1:<portB>).
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), 'public');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
const HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

function handler(req, res) {
  const url = new URL(req.url ?? '/', 'http://x');
  let path = normalize(decodeURIComponent(url.pathname)).replace(/^([/\\])+/, '');
  if (path === '' || path.endsWith('/')) path += 'index.html';
  if (path.includes('..')) {
    res.writeHead(400).end();
    return;
  }
  readFile(join(ROOT, path))
    .then((body) => {
      res.writeHead(200, { 'Content-Type': TYPES[extname(path)] ?? 'application/octet-stream', ...HEADERS });
      res.end(body);
    })
    .catch(() => res.writeHead(404, HEADERS).end('not found'));
}

/** Start one server per requested port (0 = any free port). Resolves with base URLs + close(). */
export async function startServers(ports = [0, 0], host = '127.0.0.1') {
  const servers = await Promise.all(
    ports.map(
      (port) =>
        new Promise((resolve, reject) => {
          const s = createServer(handler);
          s.once('error', reject);
          s.listen(port, host, () => resolve(s));
        }),
    ),
  );
  return {
    urls: servers.map((s) => `http://${host}:${s.address().port}`),
    close: () => Promise.all(servers.map((s) => new Promise((r) => s.close(r)))),
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { urls } = await startServers([5301, 5302]);
  console.log(`Planner agent:    ${urls[0]}/planner.html`);
  console.log(`Researcher agent: ${urls[1]}/researcher.html`);
  console.log('Enable TabBridge on both origins from the toolbar popup, then pair them. Ctrl+C to stop.');
}
