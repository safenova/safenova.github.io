'use strict';

/* ============================================================
   INCOGNITO DETECTOR  v1.6.2 (adapted)

   Algorithm ported from:
   https://github.com/Joe12387/detectIncognito
   MIT License — Copyright (c) 2021-2025 Joe Rutkowski <Joe@dreggle.com>

   Re-implemented as plain ES6 (no TypeScript, no bundler).
   Covers: Chrome 76+, Edge, Brave, Opera, Safari 13+, Firefox, IE.
   ============================================================ */

/**
 * Detect whether the current tab is running in a private / incognito context.
 * @returns {Promise<{isPrivate: boolean, browserName: string}>}
 */
function detectIncognito() {
    return new Promise(function (resolve, reject) {
        let browserName = 'Unknown';
        let callbackSettled = false;

        function __callback(isPrivate) {
            if (callbackSettled) return;
            callbackSettled = true;
            resolve({ isPrivate, browserName });
        }

        // ── Engine fingerprint ────────────────────────────────────
        // Each JS engine produces a unique error.message.length for (-1).toFixed(-1):
        //   V8 (Chrome/Edge/…) → 51
        //   JavaScriptCore (Safari) → 44 or 43
        //   SpiderMonkey (Firefox) → 25
        function feid() {
            let id = 0;
            try { (-1).toFixed(-1); } catch (e) { id = e.message.length; }
            return id;
        }

        function isSafari() { const f = feid(); return f === 44 || f === 43; }
        function isChrome() { return feid() === 51; }
        function isFirefox() { return feid() === 25; }
        function isMSIE() { return navigator.msSaveBlob !== undefined; }

        function identifyChromium() {
            const ua = navigator.userAgent;
            if (ua.match(/Chrome/)) {
                if (navigator.brave !== undefined) return 'Brave';
                if (ua.match(/Edg/)) return 'Edge';
                if (ua.match(/OPR/)) return 'Opera';
                return 'Chrome';
            }
            return 'Chromium';
        }

        // ── Safari ───────────────────────────────────────────────

        async function currentSafariTest() {
            // Modern Safari private mode: getDirectory() throws "unknown transient reason"
            try {
                await navigator.storage.getDirectory();
                __callback(false);
            } catch (e) {
                const msg = (e instanceof Error) ? e.message : String(e);
                __callback(msg.includes('unknown transient reason'));
            }
        }

        function safari13to18Test() {
            // Safari 13-18: storing a Blob in IDB throws "are not yet supported" in private mode
            const tmp = String(Math.random());
            try {
                const dbReq = indexedDB.open(tmp, 1);
                dbReq.onupgradeneeded = (ev) => {
                    const db = ev.target.result;
                    const finish = (priv) => { __callback(priv); };
                    try {
                        db.createObjectStore('t', { autoIncrement: true }).put(new Blob());
                        finish(false);
                    } catch (err) {
                        const msg = (err instanceof Error) ? err.message : String(err);
                        finish(msg.includes('are not yet supported'));
                    } finally {
                        db.close();
                        indexedDB.deleteDatabase(tmp);
                    }
                };
                dbReq.onerror = () => __callback(false);
            } catch {
                __callback(false);
            }
        }

        function oldSafariTest() {
            const openDB = window.openDatabase;
            const storage = window.localStorage;
            try { openDB(null, null, null, null); } catch { __callback(true); return; }
            try { storage.setItem('test', '1'); storage.removeItem('test'); } catch { __callback(true); return; }
            __callback(false);
        }

        async function safariPrivateTest() {
            if (typeof navigator.storage?.getDirectory === 'function') {
                await currentSafariTest();
            } else if (navigator.maxTouchPoints !== undefined) {
                safari13to18Test();
            } else {
                oldSafariTest();
            }
        }

        // ── Chrome / Chromium ─────────────────────────────────────

        function getQuotaLimit() {
            return window?.performance?.memory?.jsHeapSizeLimit ?? 1073741824;
        }

        // Chrome 76+: private mode caps webkitTemporaryStorage quota to ~2× jsHeapSizeLimit
        function storageQuotaChromePrivateTest() {
            navigator.webkitTemporaryStorage.queryUsageAndQuota(
                function (_used, quota) {
                    const quotaInMib = Math.round(quota / (1024 * 1024));
                    const quotaLimitInMib = Math.round(getQuotaLimit() / (1024 * 1024)) * 2;
                    __callback(quotaInMib < quotaLimitInMib);
                },
                function (e) {
                    reject(new Error('detectIncognito failed to query storage quota: ' + e.message));
                }
            );
        }

        // Chrome 50-75: webkitRequestFileSystem fails in private mode
        function oldChromePrivateTest() {
            window.webkitRequestFileSystem(0, 1, () => __callback(false), () => __callback(true));
        }

        function chromePrivateTest() {
            if (self.Promise !== undefined && self.Promise.allSettled !== undefined) {
                storageQuotaChromePrivateTest();
            } else {
                oldChromePrivateTest();
            }
        }

        // ── Firefox ──────────────────────────────────────────────

        async function firefoxPrivateTest() {
            if (typeof navigator.storage?.getDirectory === 'function') {
                // Modern Firefox private mode: getDirectory() throws "Security error"
                try {
                    await navigator.storage.getDirectory();
                    __callback(false);
                } catch (e) {
                    const msg = (e instanceof Error) ? e.message : String(e);
                    __callback(msg.includes('Security error'));
                }
            } else {
                // Older Firefox: IDB open fails immediately in private mode
                const req = indexedDB.open('inPrivate');
                req.onerror = (event) => {
                    if (req.error && req.error.name === 'InvalidStateError') event.preventDefault();
                    __callback(true);
                };
                req.onsuccess = () => {
                    indexedDB.deleteDatabase('inPrivate');
                    __callback(false);
                };
            }
        }

        // ── IE ───────────────────────────────────────────────────

        function msiePrivateTest() {
            __callback(window.indexedDB === undefined);
        }

        // ── Main ─────────────────────────────────────────────────

        async function main() {
            if (isSafari()) {
                browserName = 'Safari';
                await safariPrivateTest();
            } else if (isChrome()) {
                browserName = identifyChromium();
                chromePrivateTest();
            } else if (isFirefox()) {
                browserName = 'Firefox';
                await firefoxPrivateTest();
            } else if (isMSIE()) {
                browserName = 'Internet Explorer';
                msiePrivateTest();
            } else {
                reject(new Error('detectIncognito cannot determine the browser'));
            }
        }

        main().catch(reject);
    });
}

/* ============================================================
   INCOGNITO WARNING UI
   ============================================================ */

/**
 * Show the full-screen incognito warning and wait for the user to dismiss it.
 * Uses a 3-second countdown before "Continue" is enabled — same pattern
 * as confirmDeleteContainer() in home.js.
 * @returns {Promise<void>} resolves when the user clicks Continue.
 */
function showIncognitoWarning() {
    return new Promise((resolve) => {
        const el = document.getElementById('incognito-warning');
        const btn = document.getElementById('incognito-continue-btn');
        const lbl = document.getElementById('incognito-continue-lbl');

        el.style.display = 'flex';

        let remaining = 3;
        lbl.textContent = `Wait\u2026 ${remaining}`;
        btn.disabled = true;

        const timer = setInterval(() => {
            remaining--;
            if (remaining > 0) {
                lbl.textContent = `Wait\u2026 ${remaining}`;
            } else {
                clearInterval(timer);
                btn.disabled = false;
                lbl.textContent = 'I understand, Continue';
            }
        }, 1000);

        btn.onclick = () => {
            clearInterval(timer);
            btn.onclick = null;
            el.style.display = 'none';
            resolve();
        };
    });
}
