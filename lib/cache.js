// Result cache: in-memory + on-disk under .cache/.
// Key = sha256(script + '\0' + model + '\0' + promptVersion).
// Stored value: { events:[...modelEvents], usage, model, promptVersion, createdAt }.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export function cacheKey(script, model, promptVersion, source = '') {
  // `source` is injected into the model prompt, so it must be part of the key —
  // otherwise the same script with a different source URL returns a stale analysis.
  return crypto.createHash('sha256').update(`${script}\0${model}\0${promptVersion}\0${source}`).digest('hex');
}

export function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

export class ResultCache {
  constructor(dir, maxEntries = 200) {
    this.dir = dir;
    this.mem = new Map();
    this.maxEntries = maxEntries;
    try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  }

  _file(key) {
    return path.join(this.dir, `${key}.json`);
  }

  get(key) {
    if (this.mem.has(key)) return this.mem.get(key);
    try {
      const raw = fs.readFileSync(this._file(key), 'utf8');
      const val = JSON.parse(raw);
      this.mem.set(key, val);
      return val;
    } catch {
      return null;
    }
  }

  set(key, value) {
    // Bound in-memory growth with simple insertion-order (FIFO) eviction; the
    // on-disk copy remains as a cold cache.
    this.mem.delete(key);
    this.mem.set(key, value);
    while (this.mem.size > this.maxEntries) {
      const oldest = this.mem.keys().next().value;
      this.mem.delete(oldest);
    }
    try {
      fs.writeFileSync(this._file(key), JSON.stringify(value));
    } catch (err) {
      // disk failure is non-fatal; memory cache still serves this process
      console.error(`[cache] disk write failed: ${err.message}`);
    }
  }
}
