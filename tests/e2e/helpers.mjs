// Helpers for end-to-end tests: a WordPress Playground instance, the
// reference service, and a cookie-aware "administrator browser".
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { State } from '../../bin/lib/state.mjs';
import { createService } from '../../bin/lib/service.mjs';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** Starts Playground; resolves with { url, stop }. Reuses SP_WP_URL when set. */
export async function startWordPress({ port = 9411, php = '8.3', blueprint = 'blueprint.json', extraArgs = [] } = {}) {
  if (process.env.SP_WP_URL) return { url: process.env.SP_WP_URL, stop: async () => {} };
  const url = `http://127.0.0.1:${port}`;
  const child = spawn(
    'npx',
    [
      'wp-playground-cli', 'server',
      `--port=${port}`, `--php=${php}`,
      `--mount=${ROOT}:/wordpress/wp-content/plugins/site-portrait`,
      `--blueprint=${path.join(ROOT, 'tests/e2e', blueprint)}`,
      '--define', 'WP_ENVIRONMENT_TYPE', 'local',
      '--define-bool', 'SITE_PORTRAIT_DEV_MODE', 'true',
      ...extraArgs,
    ],
    { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], detached: true },
  );
  let output = '';
  child.stdout.on('data', (d) => (output += d));
  child.stderr.on('data', (d) => (output += d));
  const deadline = Date.now() + 240_000;
  while (!output.includes('Ready!')) {
    if (child.exitCode !== null || Date.now() > deadline) throw new Error(`Playground failed to start:\n${output}`);
    await new Promise((r) => setTimeout(r, 500));
  }
  return {
    url,
    output: () => output,
    stop: async () => {
      try {
        process.kill(-child.pid, 'SIGTERM');
      } catch {
        // Already stopped.
      }
    },
  };
}

/** Starts the reference service on a free port with a fresh state directory. */
export async function startService({ autoApprove = true } = {}) {
  const probe = http.createServer();
  await new Promise((r) => probe.listen(0, '127.0.0.1', r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));

  const state = new State(fs.mkdtempSync(path.join(os.tmpdir(), 'sp-service-')));
  const logs = [];
  const url = `http://127.0.0.1:${port}`;
  const service = createService({ state, publicUrl: url, autoApprove, log: (m) => logs.push(m) });
  await new Promise((r) => service.server.listen(port, '127.0.0.1', r));
  return {
    url,
    state,
    logs,
    confirmations: service.confirmations,
    stop: () => new Promise((r) => service.server.close(r)),
  };
}

/** Minimal cookie-aware HTTP client acting as the administrator's browser. */
export class Browser {
  constructor(base) {
    this.base = base;
    this.cookies = new Map();
  }

  async request(url, { method = 'GET', form, follow = true } = {}) {
    let target = new URL(url, this.base).toString();
    let body = form ? new URLSearchParams(form).toString() : undefined;
    for (let hops = 0; hops < 10; hops++) {
      const sameSite = new URL(target).origin === new URL(this.base).origin;
      const headers = {};
      if (sameSite && this.cookies.size) headers.Cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
      if (body) headers['Content-Type'] = 'application/x-www-form-urlencoded';
      const res = await fetch(target, { method, headers, body, redirect: 'manual' });
      if (sameSite) {
        for (const c of res.headers.getSetCookie()) {
          const [pair] = c.split(';');
          const i = pair.indexOf('=');
          this.cookies.set(pair.slice(0, i), pair.slice(i + 1));
        }
      }
      const location = res.headers.get('location');
      if (follow && location && res.status >= 300 && res.status < 400) {
        target = new URL(location, target).toString();
        method = 'GET';
        body = undefined;
        await res.arrayBuffer();
        continue;
      }
      return { status: res.status, url: target, text: await res.text(), location };
    }
    throw new Error('Too many redirects');
  }

  async login(user = 'admin', password = 'password') {
    await this.request('/wp-login.php');
    const r = await this.request('/wp-login.php', {
      method: 'POST',
      form: { log: user, pwd: password, rememberme: 'forever', 'wp-submit': 'Log In', testcookie: '1' },
    });
    if (!r.url.includes('/wp-admin')) throw new Error(`Login failed (${r.status} ${r.url})`);
  }
}

/** Extracts the hidden fields of the form posting to a given admin action. */
export function formFields(html, action) {
  const re = new RegExp(`<form[^>]*action="([^"]*action=site_portrait_${action}[^"]*)"[^>]*>([\\s\\S]*?)</form>`);
  const m = re.exec(html);
  if (!m) throw new Error(`Form ${action} not found`);
  const fields = {};
  for (const input of m[2].matchAll(/<input[^>]*type="hidden"[^>]*>/g)) {
    const name = /name="([^"]+)"/.exec(input[0])?.[1];
    const value = /value="([^"]*)"/.exec(input[0])?.[1] ?? '';
    if (name) fields[name] = value;
  }
  return { action: m[1].replace(/&amp;/g, '&'), fields };
}

/** Text of the admin notices on a page. */
export function notices(html) {
  return [...html.matchAll(/<div class="notice notice-(\w+)[^"]*"><p>([\s\S]*?)<\/p>/g)].map((m) => `${m[1]}: ${m[2]}`);
}

/** Waits until fn() returns a truthy value. */
export async function waitFor(fn, timeout = 30_000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('Timed out');
}
