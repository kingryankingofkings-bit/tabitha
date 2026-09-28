#!/usr/bin/env node
// Build TabBridge. SPEC.md §14.
//   node scripts/build.mjs          → dist/chrome, dist/firefox
//   node scripts/build.mjs --e2e    → also dist/chrome-e2e (NEVER shipped: pre-grants localhost hosts)
// Fails with a non-zero exit code on any missing input, bundling error, or invalid output.

import { build } from 'esbuild';
import { existsSync } from 'node:fs';
import { copyFile, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, posix, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(ROOT, 'dist');
const E2E = process.argv.includes('--e2e');

const pkg = JSON.parse(await readFile(join(ROOT, 'package.json'), 'utf8'));
const VERSION = pkg.version;
if (typeof VERSION !== 'string' || !/^\d+(\.\d+){0,3}$/.test(VERSION)) fail(`package.json version "${VERSION}" is not a valid extension version`);

const UI_PAGES = ['popup', 'dashboard', 'sidepanel'];

/** output path (no extension) → source entry */
const ENTRIES = {
  background: 'src/background/index.ts',
  'content/isolated': 'src/content/isolated.ts',
  'content/page-api': 'src/content/page-api.ts',
  ...Object.fromEntries(UI_PAGES.map((n) => [`ui/${n}`, `src/ui/${n}/main.ts`])),
};
const HTML = Object.fromEntries(UI_PAGES.map((n) => [`ui/${n}.html`, `src/ui/${n}/index.html`]));
const STYLES_DIR = 'src/ui/styles';

function fail(msg) {
  console.error(`\n✖ build failed: ${msg}`);
  process.exit(1);
}

// ------------------------------------------------------------------ manifests

const DESCRIPTION = 'Consent-gated, encrypted, audited AI-agent messaging between browser tabs.';
const CSP = { extension_pages: "script-src 'self'; object-src 'none'; base-uri 'none'" };

function chromeManifest() {
  return {
    manifest_version: 3,
    name: 'TabBridge',
    version: VERSION,
    description: DESCRIPTION,
    minimum_chrome_version: '116',
    permissions: ['storage', 'scripting', 'activeTab', 'alarms', 'sidePanel'],
    optional_host_permissions: ['http://*/*', 'https://*/*'],
    background: { service_worker: 'background.js' },
    action: { default_title: 'TabBridge', default_popup: 'ui/popup.html' },
    side_panel: { default_path: 'ui/sidepanel.html' },
    options_ui: { page: 'ui/dashboard.html', open_in_tab: true },
    content_security_policy: CSP,
  };
}

function firefoxManifest() {
  return {
    manifest_version: 3,
    name: 'TabBridge',
    version: VERSION,
    description: DESCRIPTION,
    permissions: ['storage', 'scripting', 'activeTab', 'alarms'],
    optional_host_permissions: ['http://*/*', 'https://*/*'],
    background: { scripts: ['background.js'] },
    action: { default_title: 'TabBridge', default_popup: 'ui/popup.html' },
    sidebar_action: { default_panel: 'ui/sidepanel.html', default_title: 'TabBridge Console' },
    options_ui: { page: 'ui/dashboard.html', open_in_tab: true },
    content_security_policy: CSP,
    browser_specific_settings: { gecko: { id: 'tabbridge@tabbridge.invalid', strict_min_version: '128.0' } },
  };
}

function chromeE2eManifest() {
  return { ...chromeManifest(), host_permissions: ['http://127.0.0.1/*', 'http://localhost/*'] };
}

const TARGETS = [
  { name: 'chrome', manifest: chromeManifest },
  { name: 'firefox', manifest: firefoxManifest },
  ...(E2E ? [{ name: 'chrome-e2e', manifest: chromeE2eManifest }] : []),
];

// ------------------------------------------------------------------ inputs

const missing = [...Object.values(ENTRIES), ...Object.values(HTML), STYLES_DIR].filter((p) => !existsSync(join(ROOT, p)));
if (missing.length) fail(`missing input file(s):\n  ${missing.join('\n  ')}`);
const cssFiles = (await readdir(join(ROOT, STYLES_DIR))).filter((f) => f.endsWith('.css')).sort();
if (cssFiles.length === 0) fail(`no .css files in ${STYLES_DIR}`);

// ------------------------------------------------------------------ build

const started = Date.now();
await rm(DIST, { recursive: true, force: true }); // clean every output dir (incl. stale e2e builds)

const summary = [];
for (const target of TARGETS) {
  const out = join(DIST, target.name);
  await mkdir(out, { recursive: true });
  try {
    await build({
      absWorkingDir: ROOT,
      entryPoints: Object.fromEntries(Object.entries(ENTRIES).map(([o, s]) => [o, join(ROOT, s)])),
      outdir: out,
      bundle: true,
      format: 'iife',
      platform: 'browser',
      target: ['chrome116', 'firefox128'],
      minify: false,
      sourcemap: false,
      charset: 'utf8',
      legalComments: 'none',
      define: { __TB_VERSION__: JSON.stringify(VERSION) },
      logLevel: 'warning',
    });
  } catch (e) {
    fail(`esbuild (${target.name}): ${e instanceof Error ? e.message : e}`);
  }
  for (const [dest, src] of Object.entries(HTML)) {
    await mkdir(dirname(join(out, dest)), { recursive: true });
    await copyFile(join(ROOT, src), join(out, dest));
  }
  await mkdir(join(out, 'ui/styles'), { recursive: true });
  for (const f of cssFiles) await copyFile(join(ROOT, STYLES_DIR, f), join(out, 'ui/styles', f));
  await writeFile(join(out, 'manifest.json'), JSON.stringify(target.manifest(), null, 2) + '\n');
  summary.push({ target: target.name, out });
}

// ------------------------------------------------------------------ validate outputs

async function listFiles(dir) {
  const out = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await listFiles(p)));
    else out.push(p);
  }
  return out;
}

/** Local script/style references in an extension HTML page (relative to the page). */
function htmlRefs(html) {
  const refs = [];
  const re = /<(script|link)\b[^>]*>/gi;
  let m;
  while ((m = re.exec(html))) {
    const tag = m[0];
    const attr = /\b(?:src|href)\s*=\s*["']([^"']+)["']/i.exec(tag);
    if (attr) refs.push(attr[1]);
    else if (m[1].toLowerCase() === 'script') refs.push(null); // inline script
  }
  return refs;
}

const problems = [];
for (const { target, out } of summary) {
  const manifestPath = join(out, 'manifest.json');
  let manifest;
  try {
    manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  } catch (e) {
    problems.push(`${target}: manifest.json does not parse (${e.message})`);
    continue;
  }
  if ('web_accessible_resources' in manifest) problems.push(`${target}: web_accessible_resources must not be declared`);
  if ('externally_connectable' in manifest) problems.push(`${target}: externally_connectable must not be declared`);
  if (target !== 'chrome-e2e' && 'host_permissions' in manifest) problems.push(`${target}: host_permissions only allowed in chrome-e2e`);

  const referenced = [
    manifest.background?.service_worker,
    ...(manifest.background?.scripts ?? []),
    manifest.action?.default_popup,
    manifest.side_panel?.default_path,
    manifest.options_ui?.page,
    manifest.sidebar_action?.default_panel,
    // Registered at runtime by platform.syncContentScripts / injectIntoOpenTabs:
    'content/isolated.js',
    'content/page-api.js',
  ].filter(Boolean);
  for (const ref of referenced) {
    if (!existsSync(join(out, ref))) problems.push(`${target}: manifest references missing file ${ref}`);
  }
  for (const page of Object.keys(HTML)) {
    const html = await readFile(join(out, page), 'utf8');
    for (const ref of htmlRefs(html)) {
      if (ref === null) {
        problems.push(`${target}: ${page} has an inline <script> (blocked by CSP script-src 'self')`);
        continue;
      }
      if (/^[a-z][a-z0-9+.-]*:/i.test(ref) || ref.startsWith('//')) {
        problems.push(`${target}: ${page} references remote resource ${ref}`);
        continue;
      }
      const resolved = posix.normalize(posix.join(posix.dirname(page), ref.split(/[?#]/)[0]));
      if (resolved.startsWith('..') || !existsSync(join(out, resolved))) problems.push(`${target}: ${page} references missing file ${ref}`);
    }
  }
}
if (problems.length) fail(`output validation:\n  ${problems.join('\n  ')}`);

// ------------------------------------------------------------------ summary

console.log(`TabBridge ${VERSION} built in ${Date.now() - started} ms${E2E ? ' (with e2e target)' : ''}`);
for (const { target, out } of summary) {
  const files = await listFiles(out);
  let bytes = 0;
  for (const f of files) bytes += (await stat(f)).size;
  console.log(`  ${relative(ROOT, out).padEnd(18)} ${String(files.length).padStart(3)} files  ${(bytes / 1024).toFixed(1).padStart(8)} KiB`);
}
