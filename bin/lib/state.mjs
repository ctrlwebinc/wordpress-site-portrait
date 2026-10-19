// SPDX-License-Identifier: Apache-2.0
// Persistent state of the reference service (JSON file). Reloaded on every
// use so that the "serve" process and CLI commands can share it.
import fs from 'node:fs';
import path from 'node:path';
import { generateKey, keyFromPkcs8, publicJwk, endorse } from './protocol.mjs';

export class State {
  constructor(dir) {
    this.dir = dir;
    this.file = path.join(dir, 'state.json');
  }

  load() {
    if (!fs.existsSync(this.file)) {
      const key = generateKey();
      this.save({ keys: [{ pkcs8: key.pkcs8, endorsements: [] }], pairings: {} });
    }
    return JSON.parse(fs.readFileSync(this.file, 'utf8'));
  }

  save(data) {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(this.file, JSON.stringify(data, null, 2), { mode: 0o600 });
  }

  update(fn) {
    const data = this.load();
    const result = fn(data);
    this.save(data);
    return result;
  }

  /** Current signing key (the first one). */
  signingKey() {
    return keyFromPkcs8(this.load().keys[0].pkcs8);
  }

  /** Public JWKS, endorsements included (PROTOCOL.md §11.1). */
  jwks() {
    return {
      keys: this.load().keys.map((k) => {
        const jwk = { ...publicJwk(keyFromPkcs8(k.pkcs8)), use: 'sig', alg: 'Ed25519' };
        return k.endorsements.length ? { ...jwk, endorsements: k.endorsements } : jwk;
      }),
    };
  }

  /** Adds a new key endorsed by the current one and makes it current. */
  rotateKey({ keepPrevious = true } = {}) {
    return this.update((data) => {
      const current = keyFromPkcs8(data.keys[0].pkcs8);
      const next = generateKey();
      const entry = { pkcs8: next.pkcs8, endorsements: [endorse(next.kid, current)] };
      data.keys = keepPrevious ? [entry, ...data.keys] : [entry];
      return next.kid;
    });
  }

  pairing(id) {
    const pairings = this.load().pairings;
    if (id) return pairings[id] ?? null;
    const all = Object.values(pairings).sort((a, b) => b.created_at - a.created_at);
    return all[0] ?? null;
  }

  savePairing(pairing) {
    this.update((data) => {
      data.pairings[pairing.pairing_id] = pairing;
    });
  }

  deletePairing(id) {
    return this.update((data) => {
      const existed = Boolean(data.pairings[id]);
      delete data.pairings[id];
      return existed;
    });
  }
}
