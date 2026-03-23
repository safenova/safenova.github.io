'use strict';

/* ============================================================
   DATABASE  —  IndexedDB abstraction
   ============================================================ */
const DB = (() => {
    let _db = null;

    async function init() {
        InitLog.step('DB open (SafeNovaEFS)');
        return new Promise((res, rej) => {
            let settled = false;
            const timer = setTimeout(() => {
                if (!settled) { settled = true; InitLog.error('DB open (SafeNovaEFS)', 'timeout'); rej(new Error('SafeNovaEFS open timeout')); }
            }, 8000);
            const done = (db) => { if (!settled) { settled = true; clearTimeout(timer); _db = db; InitLog.done('DB open (SafeNovaEFS)'); res(); } };
            const fail = (e) => { if (!settled) { settled = true; clearTimeout(timer); InitLog.error('DB open (SafeNovaEFS)', e); rej(e); } };

            const req = indexedDB.open(DB_NAME, DB_VERSION);
            req.onupgradeneeded = e => {
                InitLog.step('DB schema upgrade');
                try {
                    const db = e.target.result;
                    if (!db.objectStoreNames.contains('containers')) {
                        db.createObjectStore('containers', { keyPath: 'id' });
                    }
                    if (!db.objectStoreNames.contains('files')) {
                        const fs = db.createObjectStore('files', { keyPath: 'id' });
                        fs.createIndex('cid', 'cid');
                    }
                    if (!db.objectStoreNames.contains('vfs')) {
                        db.createObjectStore('vfs', { keyPath: 'cid' });
                    }
                    if (!db.objectStoreNames.contains('chunks')) {
                        db.createObjectStore('chunks', { keyPath: 'id' });
                    }
                    InitLog.done('DB schema upgrade');
                } catch (err) { InitLog.error('DB schema upgrade', err); fail(err); }
            };
            req.onsuccess = e => done(e.target.result);
            req.onerror = () => fail(req.error);
            req.onblocked = () => {
                // Another connection prevents upgrade; close it by requesting versionchange on self
                InitLog.error('DB open (SafeNovaEFS)', 'blocked — waiting for other connections to close');
                // Keep waiting — the blocked event does NOT mean failure, just delay.
                // If it takes longer than the timeout above, we fail gracefully.
            };
        });
    }

    function rw(store) { return _db.transaction(store, 'readwrite').objectStore(store); }
    function ro(store) { return _db.transaction(store, 'readonly').objectStore(store); }
    function wrap(req) { return new Promise((r, j) => { req.onsuccess = () => r(req.result); req.onerror = () => j(req.error); }); }

    // Reassemble a chunked file record: reads N chunks from 'chunks' store,
    // merges them into a single ArrayBuffer, sets rec.blob, deletes rec._chunked.
    function _reassemble(rec) {
        return new Promise((resolve, reject) => {
            const count = rec._chunked, id = rec.id;
            const tx = _db.transaction('chunks', 'readonly'),
                store = tx.objectStore('chunks'),
                parts = new Array(count);
            let totalSize = 0, pending = count;
            for (let i = 0; i < count; i++) {
                const req = store.get(id + '_' + i);
                req.onsuccess = () => {
                    const d = req.result?.data;
                    if (d) { parts[i] = d; totalSize += d.byteLength; }
                    if (--pending === 0) {
                        const merged = new Uint8Array(totalSize);
                        let off = 0;
                        for (const p of parts) { if (p) { merged.set(new Uint8Array(p), off); off += p.byteLength; } }
                        rec.blob = merged.buffer;
                        delete rec._chunked;
                        resolve(rec);
                    }
                };
                req.onerror = () => reject(req.error);
            }
        });
    }

    // Pre-deletion corruption: overwrite the first 8 bytes of every encrypted blob with zeros.
    // This ensures ciphertext is irrecoverable even if the storage engine doesn't
    // immediately reclaim the underlying pages. Best-effort — always resolves so deletion proceeds.
    function _corruptFileBlobs(ids) {
        return new Promise((resolve) => {
            if (!ids.length) { resolve(); return; }
            const tx = _db.transaction(['files', 'chunks'], 'readwrite'),
                fs = tx.objectStore('files'),
                cs = tx.objectStore('chunks');
            tx.oncomplete = () => resolve();
            tx.onerror = (e) => { e.preventDefault(); resolve(); };
            tx.onabort = () => resolve();
            ids.forEach(id => {
                const req = fs.get(id);
                req.onsuccess = () => {
                    const rec = req.result;
                    if (rec?._chunked) {
                        // Large file: corrupt first 8 bytes of the first chunk
                        const cr = cs.get(id + '_0');
                        cr.onsuccess = () => {
                            const chunk = cr.result;
                            if (chunk?.data) {
                                new Uint8Array(chunk.data, 0, Math.min(8, chunk.data.byteLength)).fill(0);
                                cs.put(chunk);
                            }
                        };
                        cr.onerror = (e) => e.preventDefault();
                    } else if (rec?.blob) {
                        // Inline file: corrupt first 8 bytes of the blob
                        new Uint8Array(rec.blob, 0, Math.min(8, rec.blob.byteLength)).fill(0);
                        fs.put(rec);
                    }
                };
                req.onerror = (e) => e.preventDefault();
            });
        });
    }

    return {
        init,
        /* containers */
        getContainers: () => wrap(ro('containers').getAll()),
        saveContainer: (c) => wrap(rw('containers').put(c)),
        deleteContainer: (id) => wrap(rw('containers').delete(id)),

        /* files */
        saveFile: async (f) => {
            const blobSize = f.blob ? (f.blob.byteLength ?? 0) : 0;
            if (blobSize > FILE_CHUNK_SIZE) {
                const chunkCount = Math.ceil(blobSize / FILE_CHUNK_SIZE),
                    tx = _db.transaction(['files', 'chunks'], 'readwrite'),
                    fs = tx.objectStore('files'),
                    cs = tx.objectStore('chunks');
                fs.put({ id: f.id, cid: f.cid, iv: f.iv, blob: null, _chunked: chunkCount });
                for (let i = 0; i < chunkCount; i++) {
                    const start = i * FILE_CHUNK_SIZE;
                    cs.put({ id: f.id + '_' + i, data: f.blob.slice(start, Math.min(start + FILE_CHUNK_SIZE, blobSize)) });
                }
                return new Promise((r, j) => { tx.oncomplete = () => r(); tx.onerror = () => j(tx.error); });
            }
            return wrap(rw('files').put(f));
        },
        getFile: async (id) => {
            let rec;
            try { rec = await wrap(ro('files').get(id)); }
            catch (e) { console.error('[DB] Failed to read file record:', id, e); return null; }
            if (!rec) return rec;
            if (rec._chunked) return _reassemble(rec);
            return rec;
        },
        getFilesByCid: async (cid) => {
            let recs;
            try {
                recs = await wrap(ro('files').index('cid').getAll(cid));
            } catch {
                // Fallback: key cursor → individual reads (handles unreadable oversized records)
                const keys = await new Promise((res, rej) => {
                    const tx = _db.transaction('files', 'readonly'),
                        idx = tx.objectStore('files').index('cid'),
                        r = [],
                        req = idx.openKeyCursor(IDBKeyRange.only(cid));
                    req.onsuccess = () => { const c = req.result; if (!c) { res(r); return; } r.push(c.primaryKey); c.continue(); };
                    req.onerror = () => rej(req.error);
                });
                recs = [];
                for (const key of keys) {
                    try { const r = await wrap(ro('files').get(key)); if (r) recs.push(r); }
                    catch (e) { console.error('[DB] Skipping unreadable file:', key, e); }
                }
            }
            const chunked = recs.filter(r => r._chunked);
            if (chunked.length) await Promise.all(chunked.map(r => _reassemble(r)));
            return recs;
        },
        deleteFile: async (id) => {
            let chunked = 0;
            try { const rec = await wrap(ro('files').get(id)); if (rec?._chunked) chunked = rec._chunked; }
            catch { /* unreadable record — not chunked */ }
            if (chunked) {
                const tx = _db.transaction(['files', 'chunks'], 'readwrite');
                tx.objectStore('files').delete(id);
                const cs = tx.objectStore('chunks');
                for (let i = 0; i < chunked; i++) cs.delete(id + '_' + i);
                return new Promise((r, j) => { tx.oncomplete = () => r(); tx.onerror = () => j(tx.error); });
            }
            return wrap(rw('files').delete(id));
        },
        // Batch-delete multiple file records (and their chunks) in IndexedDB
        deleteFiles: async (ids) => {
            if (!ids || !ids.length) return;
            // Phase 1: check which files are chunked (read-only, safe for broken records)
            const chunkInfo = new Map();
            await new Promise((resolve) => {
                const tx = _db.transaction('files', 'readonly'),
                    store = tx.objectStore('files');
                let pending = ids.length;
                const done = () => { if (--pending === 0) resolve(); };
                ids.forEach(id => {
                    const req = store.get(id);
                    req.onsuccess = () => { if (req.result?._chunked) chunkInfo.set(id, req.result._chunked); done(); };
                    req.onerror = (e) => { e.preventDefault(); done(); };
                });
            });
            // Phase 2: delete file records + associated chunks
            const stores = chunkInfo.size ? ['files', 'chunks'] : ['files'],
                tx = _db.transaction(stores, 'readwrite'),
                fs = tx.objectStore('files');
            ids.forEach(id => fs.delete(id));
            if (chunkInfo.size) {
                const cs = tx.objectStore('chunks');
                for (const [id, count] of chunkInfo) {
                    for (let i = 0; i < count; i++) cs.delete(id + '_' + i);
                }
            }
            return new Promise((r, j) => { tx.oncomplete = () => r(); tx.onerror = () => j(tx.error); });
        },
        // Batch-save multiple file records in a single IndexedDB transaction (with chunking for large blobs)
        saveFiles: (files) => new Promise((res, rej) => {
            if (!files || !files.length) { res(); return; }
            const hasChunked = files.some(f => f.blob && (f.blob.byteLength ?? 0) > FILE_CHUNK_SIZE),
                stores = hasChunked ? ['files', 'chunks'] : ['files'],
                tx = _db.transaction(stores, 'readwrite'),
                fileStore = tx.objectStore('files'),
                chunkStore = hasChunked ? tx.objectStore('chunks') : null;
            files.forEach(f => {
                const blobSize = f.blob ? (f.blob.byteLength ?? 0) : 0;
                if (blobSize > FILE_CHUNK_SIZE) {
                    const chunkCount = Math.ceil(blobSize / FILE_CHUNK_SIZE);
                    fileStore.put({ id: f.id, cid: f.cid, iv: f.iv, blob: null, _chunked: chunkCount });
                    for (let i = 0; i < chunkCount; i++) {
                        const start = i * FILE_CHUNK_SIZE;
                        chunkStore.put({ id: f.id + '_' + i, data: f.blob.slice(start, Math.min(start + FILE_CHUNK_SIZE, blobSize)) });
                    }
                } else {
                    fileStore.put(f);
                }
            });
            tx.oncomplete = () => res();
            tx.onerror = () => rej(tx.error);
        }),
        // Batch-read specific file records by id array in a single IDB transaction.
        // Returns a Map<id, record> so callers can look up by id in O(1).
        getFilesByIds: (ids) => new Promise((res, rej) => {
            if (!ids || !ids.length) { res(new Map()); return; }
            const tx = _db.transaction('files', 'readonly'),
                store = tx.objectStore('files'),
                result = new Map(),
                chunkedRecs = [];
            let pending = ids.length;
            ids.forEach(id => {
                const req = store.get(id);
                req.onsuccess = () => {
                    if (req.result) {
                        result.set(id, req.result);
                        if (req.result._chunked) chunkedRecs.push(req.result);
                    }
                    if (--pending === 0) {
                        if (chunkedRecs.length) {
                            Promise.all(chunkedRecs.map(r => _reassemble(r))).then(() => res(result)).catch(rej);
                        } else res(result);
                    }
                };
                req.onerror = (event) => {
                    console.error('[DB] Failed to read file:', id, req.error);
                    event.preventDefault();
                    if (--pending === 0) {
                        if (chunkedRecs.length) {
                            Promise.all(chunkedRecs.map(r => _reassemble(r))).then(() => res(result)).catch(rej);
                        } else res(result);
                    }
                };
            });
        }),

        /* vfs */
        saveVFS: (cid, iv, blob) => wrap(rw('vfs').put({ cid, iv, blob })),
        getVFS: (cid) => wrap(ro('vfs').get(cid)),
        deleteVFS: (cid) => wrap(rw('vfs').delete(cid)),

        /* nuke container — corrupts blobs, then deletes everything (uses key cursor to avoid deserializing large blobs) */
        async nukeContainer(cid) {
            const ids = await new Promise((resolve, reject) => {
                const tx = _db.transaction('files', 'readonly'),
                    idx = tx.objectStore('files').index('cid'),
                    r = [],
                    req = idx.openKeyCursor(IDBKeyRange.only(cid));
                req.onsuccess = () => { const c = req.result; if (!c) { resolve(r); return; } r.push(c.primaryKey); c.continue(); };
                req.onerror = () => reject(req.error);
            });
            if (ids.length) {
                await _corruptFileBlobs(ids); // zero-overwrite first 8 bytes of each encrypted blob
                await this.deleteFiles(ids);
            }
            await this.deleteVFS(cid);
            await this.deleteContainer(cid);
        }
    };
})();
