'use strict';

/* ============================================================
   SafeNova Proactive — Runtime Protection Module
   Version 2

   Loads BEFORE all other application scripts. Every other
   module checks window.__snvGuard.active at boot; if the
   guard is absent or inactive the app refuses to start.

   Responsibilities
   ─────────────────
   1. Capture all security-critical native function references
      at the earliest possible moment (before any extension or
      injected script can tamper)

   2. Verify that those natives are still native on every tick
      (1 s interval): crypto.subtle.*, crypto.getRandomValues,
      IDBFactory, Storage, btoa/atob, TextEncoder

   3. Install protective hooks on outbound network APIs to
      intercept external requests in real time:
        • fetch / XMLHttpRequest.open / navigator.sendBeacon
          → block any request whose origin differs from the
            current page origin

   4. Watchdog: every tick verify our hooks are still in place
      (reference-equality check); if removed or replaced,
      silently re-hook without alerting (extensions like
      Adblock often wrap these APIs legitimately)

   5. On any real threat (native crypto/storage/encoding
      tamper, or external network request):
        a. Immediately wipe all snv-* keys from localStorage
           and sessionStorage using captured native references
           (bypasses any hook that may have been placed on
           Storage methods)
        b. Show a dismissible overlay warning the user and
           advising them to audit their browser extensions

   Intentionally excluded from checks:
   • console namespace — overrides are common and benign
   • Function.prototype.toString — protected via captured ref
     (_fnToString); live checks cause false positives from
     extensions that legitimately wrap it
   • document.createElement — extensions create elements
     (including <script>) for their own content scripts;
     blocking this causes false positives
   ============================================================ */

(() => {

    /* ──────────────────────────────────────────────────────────
       0.  Earliest possible capture — before anything else runs
       ────────────────────────────────────────────────────────── */

    // Capture Function.prototype.toString before anyone can spoof it.
    // All subsequent "is this native?" checks use this reference directly.
    const _fnToString = Function.prototype.toString;

    // A genuine native function's body is exactly `{ [native code] }` with
    // nothing else inside — no source lines, no comments.
    // A simple .includes('[native code]') test is fooled by:
    //   function fake() { // [native code]\n  return 1; }
    // The regex requires [native code] to be the ONLY content of the body,
    // which covers both Chrome (single-line) and Firefox (indented) formats.
    const _isNative = fn =>
        typeof fn === 'function' && /\{\s*\[native code\]\s*\}\s*$/.test(_fnToString.call(fn));

    const _origin = window.location.origin;

    /* ──────────────────────────────────────────────────────────
       1.  Lock in native references
       ────────────────────────────────────────────────────────── */
    const _N = Object.freeze({
        // Network
        fetch: window.fetch,
        xhrOpen: XMLHttpRequest.prototype.open,
        xhrSend: XMLHttpRequest.prototype.send,
        sendBeacon: navigator.sendBeacon,

        // DOM
        createElement: Document.prototype.createElement,
        appendChild: Element.prototype.appendChild,

        // Crypto
        getRandomValues: crypto.getRandomValues,
        subtleEncrypt: crypto.subtle.encrypt,
        subtleDecrypt: crypto.subtle.decrypt,
        subtleImportKey: crypto.subtle.importKey,
        subtleExportKey: crypto.subtle.exportKey,
        subtleDeriveKey: crypto.subtle.deriveKey,
        subtleDigest: crypto.subtle.digest,

        // IndexedDB
        idbOpen: IDBFactory.prototype.open,

        // Storage (prototype-level, covers both localStorage and sessionStorage)
        storageGetItem: Storage.prototype.getItem,
        storageSetItem: Storage.prototype.setItem,
        storageRemoveItem: Storage.prototype.removeItem,
        storageClear: Storage.prototype.clear,
        storageKey: Storage.prototype.key,
        storageLength: Object.getOwnPropertyDescriptor(Storage.prototype, 'length')?.get,

        // Encoding
        btoa: window.btoa,
        atob: window.atob,
        textEncode: TextEncoder.prototype.encode,

        // Document.cookie descriptor (validate getter/setter not replaced)
        cookieDesc: Object.getOwnPropertyDescriptor(Document.prototype, 'cookie'),

        // UI — captured so our alert overlay cannot itself be intercepted
        alert: window.alert,
    });

    /* ──────────────────────────────────────────────────────────
       2.  Functions that must remain native (we never hook them)
           Each entry: [display name, live-reference getter]

           Function.prototype.toString is deliberately excluded:
           it is protected by the captured _fnToString reference
           and extensions (Adblock, Dark Reader) routinely wrap
           it, causing false positives on every tick.
       ────────────────────────────────────────────────────────── */
    const _NATIVE_CHECKS = [
        ['crypto.getRandomValues', () => crypto.getRandomValues],
        ['crypto.subtle.encrypt', () => crypto.subtle.encrypt],
        ['crypto.subtle.decrypt', () => crypto.subtle.decrypt],
        ['crypto.subtle.importKey', () => crypto.subtle.importKey],
        ['crypto.subtle.exportKey', () => crypto.subtle.exportKey],
        ['crypto.subtle.deriveKey', () => crypto.subtle.deriveKey],
        ['crypto.subtle.digest', () => crypto.subtle.digest],
        ['IDBFactory.prototype.open', () => IDBFactory.prototype.open],
        ['Storage.prototype.getItem', () => Storage.prototype.getItem],
        ['Storage.prototype.setItem', () => Storage.prototype.setItem],
        ['Storage.prototype.removeItem', () => Storage.prototype.removeItem],
        ['btoa', () => window.btoa],
        ['atob', () => window.atob],
        ['TextEncoder.prototype.encode', () => TextEncoder.prototype.encode],
    ];

    /* ──────────────────────────────────────────────────────────
       3.  Threat response
       ────────────────────────────────────────────────────────── */
    let _lastAlertAt = 0;
    const _ALERT_COOLDOWN_MS = 10_000;

    // Use captured native Storage references — bypasses any potential
    // hook placed on Storage.prototype by a malicious extension
    function _nukeStorage() {
        const removeFrom = (store) => {
            try {
                const len = _N.storageLength.call(store);
                const keys = [];
                for (let i = 0; i < len; i++) {
                    const k = _N.storageKey.call(store, i);
                    if (k?.startsWith('snv-')) keys.push(k);
                }
                keys.forEach(k => _N.storageRemoveItem.call(store, k));
            } catch { /* storage access denied — skip */ }
        };
        removeFrom(sessionStorage);
        removeFrom(localStorage);
    }

    function _showAlert(reason) {
        const render = () => {
            // Remove any stale alert
            try { document.getElementById('snv-proactive-alert')?.remove(); } catch { }

            // Use the captured native createElement so hooks cannot interfere
            const overlay = _N.createElement.call(document, 'div');
            overlay.id = 'snv-proactive-alert';
            overlay.style.cssText = [
                'position:fixed', 'inset:0', 'z-index:2147483647',
                'background:rgba(0,0,0,.85)',
                'display:flex', 'align-items:center', 'justify-content:center',
                'font-family:"Segoe UI",system-ui,-apple-system,sans-serif',
            ].join(';');

            // Build sanitised reason text (no HTML injection from the reason string)
            const safeReason = String(reason)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');

            overlay.innerHTML = `
<div style="max-width:520px;width:calc(100% - 96px);background:#1e1e1e;border:1px solid #f44747;border-radius:2px;padding:24px 28px;color:#d4d4d4;text-align:left;box-shadow:0 8px 32px rgba(0,0,0,.6)">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" style="color:#f44747;flex-shrink:0" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
      <path d="M12 8v5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
      <circle cx="12" cy="16" r="1" fill="currentColor"/>
    </svg>
    <span style="font-size:14px;font-weight:600;color:#f44747;letter-spacing:.01em">SafeNova Proactive</span>
  </div>
  <div style="font-size:12px;font-family:'Cascadia Code',Consolas,'Courier New',monospace;background:#252526;padding:8px 12px;border:1px solid #3c3c3c;border-radius:2px;margin-bottom:14px;word-break:break-all;color:#f44747">${safeReason}</div>
  <div style="font-size:13px;line-height:1.6;color:#d4d4d4;margin-bottom:6px">
    A suspicious operation was <strong style="color:#fff">blocked</strong> and all encrypted session keys have been <strong style="color:#fff">cleared</strong>.
  </div>
  <div style="font-size:13px;line-height:1.6;color:#858585;margin-bottom:18px">
    This may indicate a malicious browser extension attempting to intercept or exfiltrate data. Audit your installed extensions and reload.
  </div>
  <button id="snv-proactive-ok" style="background:#5a1a1a;color:#f44747;border:1px solid #7a2222;border-radius:2px;padding:6px 14px;font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;cursor:pointer">
    I understand — Reload
  </button>
</div>`;

            try {
                (document.body || document.documentElement)
                    .appendChild(overlay);
            } catch { }

            const btn = overlay.querySelector('#snv-proactive-ok');
            if (btn) {
                btn.addEventListener('click', () => {
                    overlay.remove();
                    window.location.reload();
                }, { once: true });
            }
        };

        if (document.body) {
            render();
        } else {
            window.addEventListener('DOMContentLoaded', render, { once: true });
        }
    }

    function _triggerAlert(reason) {
        // Always clear storage immediately — even if we rate-limit the UI
        _nukeStorage();

        const now = Date.now();
        if (now - _lastAlertAt < _ALERT_COOLDOWN_MS) return;
        _lastAlertAt = now;
        _showAlert(reason);
    }

    /* ──────────────────────────────────────────────────────────
       4.  URL origin check
       ────────────────────────────────────────────────────────── */
    function _isExternal(urlStr) {
        if (!urlStr) return false;
        try {
            // Relative URLs always resolve to same origin
            const parsed = new URL(String(urlStr), window.location.href);
            return parsed.origin !== _origin;
        } catch {
            return false; // malformed URL — let the browser handle it
        }
    }

    /* ──────────────────────────────────────────────────────────
       5.  Hook installation
           Hooks are named functions so we can do reference-
           equality checks in the watchdog.
       ────────────────────────────────────────────────────────── */
    const _H = {}; // live hook references — checked every tick

    function _installHooks() {
        // ── fetch ──────────────────────────────────────────────
        _H.fetch = function snvFetch(input, init) {
            const url = (input instanceof Request) ? input.url : String(input ?? '');
            if (_isExternal(url)) {
                _triggerAlert('Outbound fetch blocked → ' + url);
                return Promise.reject(new Error('[SafeNova Proactive] External fetch blocked'));
            }
            return _N.fetch.apply(this === window ? window : globalThis, arguments);
        };
        window.fetch = _H.fetch;

        // ── XMLHttpRequest.prototype.open ─────────────────────
        _H.xhrOpen = function snvXhrOpen(method, url) {
            if (_isExternal(String(url ?? ''))) {
                _triggerAlert('Outbound XHR blocked → ' + url);
                throw new Error('[SafeNova Proactive] External XHR blocked');
            }
            return _N.xhrOpen.apply(this, arguments);
        };
        XMLHttpRequest.prototype.open = _H.xhrOpen;

        // ── navigator.sendBeacon ───────────────────────────────
        if (_N.sendBeacon) {
            _H.sendBeacon = function snvSendBeacon(url, data) {
                if (_isExternal(String(url ?? ''))) {
                    _triggerAlert('sendBeacon to external URL blocked → ' + url);
                    return false;
                }
                return _N.sendBeacon.apply(navigator, arguments);
            };
            navigator.sendBeacon = _H.sendBeacon;
        }

        // document.createElement is intentionally NOT hooked.
        // Extensions (Adblock, Dark Reader, etc.) legitimately create
        // <script> elements for their content scripts — blocking this
        // causes widespread false positives on every page load.
    }

    /* ──────────────────────────────────────────────────────────
       6.  Watchdog  (runs every 1 000 ms)
       ────────────────────────────────────────────────────────── */
    function _tick() {
        // 6a. Verify our hooks are still in place.
        //     Extensions routinely wrap fetch/XHR for their own purposes
        //     (ad blocking, privacy, etc.), so we silently re-install
        //     without firing an alert — this is NOT a security threat,
        //     just normal browser extension behaviour.
        const hookTampered =
            window.fetch !== _H.fetch ||
            XMLHttpRequest.prototype.open !== _H.xhrOpen ||
            (_N.sendBeacon && navigator.sendBeacon !== _H.sendBeacon);

        if (hookTampered) {
            _installHooks(); // silent re-hook, no alert
        }

        // 6b. Verify security-critical natives are still native.
        //     We call the LIVE getter on each check, not our cached ref,
        //     so we catch live substitutions made after our capture.
        for (const [name, getLive] of _NATIVE_CHECKS) {
            let live;
            try { live = getLive(); } catch {
                _triggerAlert('Security-critical property was removed: ' + name);
                return;
            }
            if (!_isNative(live)) {
                _triggerAlert('Native function tampered: ' + name);
                return; // one alert per tick avoids spam
            }
        }
    }

    /* ──────────────────────────────────────────────────────────
       7.  Guard token — other modules check this at boot
       ────────────────────────────────────────────────────────── */
    try {
        Object.defineProperty(window, '__snvGuard', {
            value: Object.freeze({ active: true, version: 1 }),
            writable: false,
            configurable: false,
            enumerable: false,
        });
    } catch { /* already defined — harmless */ }

    /* ──────────────────────────────────────────────────────────
       8.  Boot
       ────────────────────────────────────────────────────────── */
    _installHooks();
    setInterval(_tick, 1000);

})();
