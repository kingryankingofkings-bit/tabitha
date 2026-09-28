// Cross-browser extension namespace. Firefox exposes `browser` (promise-based); Chrome MV3's
// `chrome` is promise-based too. We type against @types/chrome for both.
declare const browser: typeof chrome | undefined;

export const ext: typeof chrome =
  typeof browser !== 'undefined' && browser?.runtime ? browser : (globalThis as unknown as { chrome: typeof chrome }).chrome;

export const isFirefox = (): boolean => typeof browser !== 'undefined' && !!browser?.runtime;
