'use strict';

/* ============================================================
   SafeNova Proactive — Anti-Tamper Runtime Integrity Guard
   Version 4

   Loads BEFORE all other application scripts. Every other
   module checks window.__snvGuard.active at boot; if the
   guard is absent or inactive the app refuses to start.

   Responsibilities
   ─────────────────
   1. Capture all security-critical native function references
      at the earliest possible moment (before any extension or
      injected script can tamper), including typed arrays, Blob,
      URL, timers, and requestAnimationFrame

   2. Validate captured references — confirm every just-captured
      function is still truly native before trusting it; if any
      captured reference is already non-native the app refuses
      to start (pre-capture tampering guard)

   3. Verify that those natives are still native on every tick
      (1 s interval): crypto.subtle.*, crypto.getRandomValues,
      IDBFactory, Storage, btoa/atob, TextEncoder, Uint8Array,
      ArrayBuffer, DataView, Blob, URL, TextDecoder,
      CompressionStream, DecompressionStream

   4. Install protective hooks on outbound network APIs to
      intercept external requests in real time:
        • fetch / XMLHttpRequest.open / navigator.sendBeacon
          → block any request whose origin differs from the
            current page origin

   5. Watchdog resilience — three independent timer mechanisms
      (setInterval, recursive setTimeout, rAF chain) make it
      impossible to kill the watchdog without page-level control.
      clearInterval/clearTimeout are guarded — attempts to clear
      watchdog timer IDs are silently ignored.

   6. Dead man's switch — every tick dispatches 'snv:alive'.
      main.js monitors the heartbeat; if >3 s silence → auto-lock.

   7. On any real threat (native crypto/storage/encoding/array
      tamper, or external network request):
        a. Immediately wipe all snv-* keys from localStorage
           and sessionStorage using captured native references
        b. Show a dismissible overlay warning the user

   8. Visibility-change fast check — when tab becomes visible,
      an immediate full tick runs so attacks during background
      cannot exploit the ~1 s window.

   9. App function integrity (G1) — critical Crypto module methods
      (encrypt, decrypt, decryptBin, deriveKey, deriveKeyAndRaw) AND
      App.lockContainer are captured at window load and compared by
      reference on every tick.  Replacing any of them via the DevTools
      console triggers an immediate alert and key-wipe cycle.

  10. Debugger trap (G3) — on threat detection a 'debugger' statement
      fires every 50 ms for up to 5 minutes. If DevTools are open this
      pauses the JS engine, blocking follow-up console commands. Has
      zero cost when DevTools are closed (native no-op).

  11. Console threat log (G2) — every detected threat emits a styled
      red console.error, providing a forensic trace even if the visual
      overlay is later dismissed.

   Intentionally excluded from checks:
   • console namespace — overrides are common and benign
   • Function.prototype.toString — protected via captured ref
     (_fnToString); live checks cause false positives from
     extensions that legitimately wrap it
   • document.createElement — extensions create elements
     (including <script>) for their own content scripts;
     blocking this causes false positives
   • JSON.stringify/parse — DevTools and frameworks patch these
   • Promise / Promise.prototype.then — polyfills wrap these
   • performance.now — privacy extensions add jitter
   • Object.defineProperty — too many legitimate uses
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

    // Capture direct object references to the storage instances.
    // This is done BEFORE building _N because window.localStorage and
    // window.sessionStorage are live getters — if an attacker later
    // replaces them with Object.defineProperty, our saved refs still
    // point to the real storage objects, so _nukeStorage cannot be
    // fooled by a getter-level interception.
    const _ls = (() => { try { return window.localStorage; } catch { return null; } })();
    const _ss = (() => { try { return window.sessionStorage; } catch { return null; } })();

    /* ──────────────────────────────────────────────────────────
       0b. Pre-existence guard-token check
           If __snvGuard already exists on window an attacker
           pre-defined it (e.g. via MV2 document_start) to hold
           active:true while blocking our Object.defineProperty.
           We record this; __snvVerify will return false.
       ────────────────────────────────────────────────────────── */
    const _guardPreexisted = (function () {
        try { return Object.prototype.hasOwnProperty.call(window, '__snvGuard'); } catch { return true; }
    }());

    /* ──────────────────────────────────────────────────────────
       0c. Bootstrap-validate Function.prototype.toString and .call
           BEFORE building _N — avoids circular dependency.
           Uses structural checks (.name, .length) and String()
           coercion (a different code path from _fnToString.call)
           to cross-verify that the foundational helpers are genuine.
       ────────────────────────────────────────────────────────── */
    const _bootstrapNativeRe = /\{\s*\[native code\]\s*\}\s*$/;
    const _fnToStringValid =
        typeof _fnToString === 'function' &&
        _fnToString.name === 'toString' &&
        _fnToString.length === 0 &&
        (function () { try { return _bootstrapNativeRe.test(String(_fnToString)); } catch { return false; } }());
    const _fnCallValid =
        typeof Function.prototype.call === 'function' &&
        Function.prototype.call.name === 'call' &&
        Function.prototype.call.length === 1 &&
        (function () { try { return _bootstrapNativeRe.test(String(Function.prototype.call)); } catch { return false; } }());

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
        textDecode: TextDecoder.prototype.decode,

        // Typed Arrays & ArrayBuffer
        Uint8Array: window.Uint8Array,
        Uint8ArraySet: Uint8Array.prototype.set,
        Uint8ArraySubarray: Uint8Array.prototype.subarray,
        Uint8ArraySlice: Uint8Array.prototype.slice,
        ArrayBuffer: window.ArrayBuffer,
        ArrayBufferSlice: ArrayBuffer.prototype.slice,
        DataView: window.DataView,

        // Blob & URL
        Blob: window.Blob,
        createObjectURL: URL.createObjectURL,
        revokeObjectURL: URL.revokeObjectURL,

        // Compression (may be absent in older browsers)
        CompressionStream: window.CompressionStream ?? null,
        DecompressionStream: window.DecompressionStream ?? null,

        // Timers — captured BEFORE any code can replace them
        _setInterval: window.setInterval,
        _clearInterval: window.clearInterval,
        _setTimeout: window.setTimeout,
        _clearTimeout: window.clearTimeout,
        _requestAnimationFrame: window.requestAnimationFrame,

        // Document.cookie descriptor (validate getter/setter not replaced)
        cookieDesc: Object.getOwnPropertyDescriptor(Document.prototype, 'cookie'),

        // Function meta-methods — hardening for internal .call()/.apply() usages
        fnCall: Function.prototype.call,
        fnApply: Function.prototype.apply,

        // cancelAnimationFrame — needed for E4 guard
        _cancelAnimationFrame: window.cancelAnimationFrame ?? null,

        // MutationObserver — needed for E7 self-healing alert overlay
        MutationObserver: window.MutationObserver ?? null,

        // DOM access — captured to harden against attacker hooking getElementById/querySelector
        // after daemon.js loads. Used exclusively inside _wipeAppState() to reach
        // sensitive UI elements without going through potentially-patched window methods.
        docGetElementById: Document.prototype.getElementById ?? null,
        docQuerySelector: Document.prototype.querySelector ?? null,
        docQuerySelectorAll: Document.prototype.querySelectorAll ?? null,

        // Value setters — wipe decrypted plaintext from editor/input elements
        // without relying on the script-accessible .value property path which
        // could be intercepted via Object.defineProperty on the prototype.
        taValueSetter: Object.getOwnPropertyDescriptor(HTMLTextAreaElement?.prototype, 'value')?.set ?? null,
        inputValueSetter: Object.getOwnPropertyDescriptor(HTMLInputElement?.prototype, 'value')?.set ?? null,

        // Web Animations API — used to animate the security barrier veil without
        // a <style> injection (no injectable keyframe name to target via CSS).
        elementAnimate: Element.prototype.animate ?? null,

        // Diagnostics — captured before any attacker replacement so that
        // _logThreatToConsole output cannot be silenced by console.error = () => {}.
        consoleError: console.error?.bind(console) ?? null,

        // UI — captured so our alert overlay cannot itself be intercepted
        alert: window.alert,
    });

    /* ──────────────────────────────────────────────────────────
       1b. Pre-capture validation — confirm EVERY captured ref is
           truly native before we trust it.  If malicious code ran
           before daemon.js (e.g. via a MV2 document_start content
           script), any of the just-captured references could
           already be non-native wrappers.  We fail hard here:
           set __snvGuard.active = false so the app refuses to boot.
       ────────────────────────────────────────────────────────── */
    const _CAPTURE_MUST_BE_NATIVE = [
        _N.fetch, _N.xhrOpen, _N.xhrSend,
        _N.getRandomValues,
        _N.subtleEncrypt, _N.subtleDecrypt, _N.subtleImportKey,
        _N.subtleExportKey, _N.subtleDeriveKey, _N.subtleDigest,
        _N.idbOpen,
        _N.storageGetItem, _N.storageSetItem, _N.storageRemoveItem,
        _N.storageClear, _N.storageKey,
        _N.btoa, _N.atob,
        _N.textEncode, _N.textDecode,
        _N.Uint8ArraySet, _N.Uint8ArraySubarray, _N.Uint8ArraySlice,
        _N.ArrayBufferSlice,
        _N.createObjectURL, _N.revokeObjectURL,
        _N._setInterval, _N._clearInterval, _N._setTimeout,
        _N._clearTimeout, _N._requestAnimationFrame,
        _N.fnCall, _N.fnApply,
    ];
    // Constructors are native but toString prints differently — check them
    // with _isNative which already handles "function Uint8Array() { [native code] }"
    const _CAPTURE_MUST_BE_NATIVE_CTORS = [
        _N.Uint8Array, _N.ArrayBuffer, _N.DataView, _N.Blob,
    ];
    // Optional: CompressionStream / DecompressionStream may be null in older browsers
    if (_N.CompressionStream) _CAPTURE_MUST_BE_NATIVE_CTORS.push(_N.CompressionStream);
    if (_N.DecompressionStream) _CAPTURE_MUST_BE_NATIVE_CTORS.push(_N.DecompressionStream);

    let _captureClean = true;
    for (const fn of _CAPTURE_MUST_BE_NATIVE) {
        if (!_isNative(fn)) { _captureClean = false; break; }
    }
    if (_captureClean) {
        for (const ctor of _CAPTURE_MUST_BE_NATIVE_CTORS) {
            if (!_isNative(ctor)) { _captureClean = false; break; }
        }
    }
    // storageLength is a getter, not a plain function — validate separately
    if (_captureClean && _N.storageLength && typeof _N.storageLength !== 'function') {
        _captureClean = false;
    }
    // Factor in bootstrap validation results
    if (_captureClean && (!_fnToStringValid || !_fnCallValid)) {
        _captureClean = false;
    }
    // Factor in pre-existence of __snvGuard — indicates attacker setup
    if (_captureClean && _guardPreexisted) {
        _captureClean = false;
    }

    // Session canary — random, closure-private, unpredictable without reading
    // this IIFE's runtime state. Stored in __snvGuard._c; __snvVerify() confirms
    // it matches, proving the guard was defined by this IIFE not pre-injected.
    const _canary =
        (Math.random() * 0xffffffff >>> 0).toString(16) +
        (Math.random() * 0xffffffff >>> 0).toString(16) +
        Date.now().toString(36);

    /* ──────────────────────────────────────────────────────────
       2.  Functions that must remain native (we never hook them)
           Each entry: [display name, live-reference getter]

           Function.prototype.toString is deliberately excluded:
           it is protected by the captured _fnToString reference
           and extensions (Adblock, Dark Reader) routinely wrap
           it, causing false positives on every tick.
       ────────────────────────────────────────────────────────── */
    const _NATIVE_CHECKS = [
        // Crypto
        ['crypto.getRandomValues', () => crypto.getRandomValues],
        ['crypto.subtle.encrypt', () => crypto.subtle.encrypt],
        ['crypto.subtle.decrypt', () => crypto.subtle.decrypt],
        ['crypto.subtle.importKey', () => crypto.subtle.importKey],
        ['crypto.subtle.exportKey', () => crypto.subtle.exportKey],
        ['crypto.subtle.deriveKey', () => crypto.subtle.deriveKey],
        ['crypto.subtle.digest', () => crypto.subtle.digest],
        // IndexedDB
        ['IDBFactory.prototype.open', () => IDBFactory.prototype.open],
        // Storage
        ['Storage.prototype.getItem', () => Storage.prototype.getItem],
        ['Storage.prototype.setItem', () => Storage.prototype.setItem],
        ['Storage.prototype.removeItem', () => Storage.prototype.removeItem],
        // Encoding
        ['btoa', () => window.btoa],
        ['atob', () => window.atob],
        ['TextEncoder.prototype.encode', () => TextEncoder.prototype.encode],
        ['TextDecoder.prototype.decode', () => TextDecoder.prototype.decode],
        // Typed Arrays & ArrayBuffer (A1)
        ['Uint8Array', () => window.Uint8Array],
        ['Uint8Array.prototype.set', () => Uint8Array.prototype.set],
        ['Uint8Array.prototype.subarray', () => Uint8Array.prototype.subarray],
        ['Uint8Array.prototype.slice', () => Uint8Array.prototype.slice],
        ['ArrayBuffer', () => window.ArrayBuffer],
        ['ArrayBuffer.prototype.slice', () => ArrayBuffer.prototype.slice],
        ['DataView', () => window.DataView],
        // Blob & URL (A2)
        ['Blob', () => window.Blob],
        ['URL.createObjectURL', () => URL.createObjectURL],
        ['URL.revokeObjectURL', () => URL.revokeObjectURL],
    ];
    // CompressionStream / DecompressionStream — optional in older browsers
    if (window.CompressionStream) {
        _NATIVE_CHECKS.push(['CompressionStream', () => window.CompressionStream]);
    }
    if (window.DecompressionStream) {
        _NATIVE_CHECKS.push(['DecompressionStream', () => window.DecompressionStream]);
    }
    // Function meta-methods (E1b)
    _NATIVE_CHECKS.push(['Function.prototype.call', () => Function.prototype.call]);
    _NATIVE_CHECKS.push(['Function.prototype.apply', () => Function.prototype.apply]);

    /* ──────────────────────────────────────────────────────────
       3.  Threat response
       ────────────────────────────────────────────────────────── */
    let _lastAlertAt = 0;
    const _ALERT_COOLDOWN_MS = 10_000;

    // Wipe all snv-* keys from storage using a two-pass strategy:
    //   Pass 1 — overwrite every key value with zeros (destroys key
    //             material immediately; even if removeItem is later
    //             intercepted or fails, the actual bytes are gone)
    //   Pass 2 — delete the entries via the captured native prototype ref
    //
    // Uses _ls/_ss (captured object refs) as `this`, NOT the live
    // window.localStorage / window.sessionStorage getters, so a
    // getter-level replacement attack cannot redirect calls to a fake
    // storage object.
    function _nukeStorage() {
        const nuke = (store) => {
            if (!store) return;
            try {
                const len = _N.storageLength.call(store);
                const keys = [];
                for (let i = 0; i < len; i++) {
                    const k = _N.storageKey.call(store, i);
                    if (k?.startsWith('snv-')) keys.push(k);
                }
                if (!keys.length) return;

                // Pass 1: zero out the value — key material is gone
                //         even if the delete step is somehow blocked
                const zeros = '\x00'.repeat(256);
                keys.forEach(k => {
                    try { _N.storageSetItem.call(store, k, zeros); } catch { }
                });

                // Pass 2: delete the entries
                keys.forEach(k => {
                    try { _N.storageRemoveItem.call(store, k); } catch { }
                });
            } catch { /* storage access denied — skip */ }
        };
        nuke(_ss);
        nuke(_ls);
    }

    // Random class for the alert host element — generated once per page session.
    // ABP cosmetic-filter rules store class selectors persistently; a class that
    // changes on every page load cannot be persistently blocked across sessions.
    // Must start with a letter so it is valid as a CSS identifier.
    const _ALERT_HOST_CLS = 'x' + Math.random().toString(36).slice(2, 12);

    // F1: Reference-based alert overlay tracking.
    // Removal detection uses overlay.isConnected (reference-based),
    // which is unaffected by class changes or same-id decoys.
    let _alertOverlay = null;
    let _alertHealer = null; // Bug 1b: module-level ref so old healer can be disconnected

    function _showAlert(reason) {
        // CSS for alert internals — injected into ShadowRoot (external CSS cannot
        // penetrate closed shadows). Uses the same values as app.css .snv-* rules.
        // Every element receives _ALERT_HOST_CLS as first class for ABP-resistance.
        const _css = `
.snv-card{max-width:520px;width:calc(100% - 96px);background:#1e1e1e;border:1px solid #f44747;border-radius:2px;padding:24px 28px;color:#d4d4d4;text-align:left;box-shadow:0 8px 32px rgba(0,0,0,.6)}
.snv-header{display:flex;align-items:center;gap:10px;margin-bottom:16px}
.snv-icon{color:#f44747;flex-shrink:0}
.snv-title{font-size:14px;font-weight:600;color:#f44747;letter-spacing:.01em}
.snv-reason{font-size:12px;font-family:'Cascadia Code',Consolas,'Courier New',monospace;background:#252526;padding:8px 12px;border:1px solid #3c3c3c;border-radius:2px;margin-bottom:14px;word-break:break-all;color:#f44747}
.snv-desc{font-size:13px;line-height:1.6;color:#d4d4d4;margin-bottom:6px}
.snv-desc strong{color:#fff}
.snv-hint{font-size:13px;line-height:1.6;color:#858585;margin-bottom:18px}
.snv-btn{background:#5a1a1a;color:#f44747;border:1px solid #7a2222;border-radius:2px;padding:6px 14px;font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;cursor:pointer}
.snv-btn:hover{background:#7a2222}`;

        const render = () => {
            // Remove previous alert by stored reference, not by predictable selector
            try { _alertOverlay?.remove(); _alertOverlay = null; } catch { }

            // Bug 1b: Disconnect the previous healer before creating a new one.
            // Without this, the old MO keeps trying to re-append the old (already
            // removed) overlay on every body childList change, stacking overlays.
            if (_alertHealer) {
                try { _alertHealer.disconnect(); } catch { }
                _alertHealer = null;
            }

            const _rc = _ALERT_HOST_CLS; // shorthand for random class

            // Use the captured native createElement so hooks cannot interfere
            const overlay = _N.createElement.call(document, 'div');
            // F1: Random session-specific class — cannot be persistently blocked by
            //     cosmetic filters (class name is unguessable and changes every load).
            //     CSS class "snv-overlay" provides the visual styles; _rc defeats ABP.
            overlay.className = _rc + ' snv-overlay';
            // Critical properties use !important; inline !important beats any
            // author-stylesheet !important per the CSS cascade specification.
            for (const [p, v] of [
                ['position', 'fixed'],
                ['inset', '0'],
                ['z-index', '2147483647'],
                ['background', 'rgba(0,0,0,.85)'],
                ['display', 'flex'],
                ['align-items', 'center'],
                ['justify-content', 'center'],
                ['font-family', '"Segoe UI",system-ui,-apple-system,sans-serif'],
            ]) { try { overlay.style.setProperty(p, v, 'important'); } catch { } }
            _alertOverlay = overlay;

            const safeReason = String(reason)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');

            // E7: Closed ShadowRoot — content is invisible to document.querySelector
            // and to inline MutationObserver-based removal attacks. An attacker can
            // still remove the host element, but cannot find or suppress the button.
            let contentRoot = overlay;
            try {
                const shadow = overlay.attachShadow({ mode: 'closed' });
                contentRoot = shadow;
            } catch { /* ShadowRoot unavailable — fall back to plain overlay */ }

            // Inject styles into shadow (external CSS cannot reach closed shadow)
            contentRoot.innerHTML = `<style>${_css}</style>
<div class="${_rc} snv-card">
  <div class="${_rc} snv-header">
    <svg class="${_rc} snv-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
      <path d="M12 8v5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
      <circle cx="12" cy="16" r="1" fill="currentColor"/>
    </svg>
    <span class="${_rc} snv-title">SafeNova Proactive</span>
  </div>
  <div class="${_rc} snv-reason">${safeReason}</div>
  <div class="${_rc} snv-desc">
    A suspicious operation was <strong>blocked</strong> and all encrypted session keys have been <strong>cleared</strong>.
  </div>
  <div class="${_rc} snv-hint">
    This may indicate a malicious browser extension attempting to intercept or exfiltrate data. Audit your installed extensions and reload.
  </div>
  <button class="${_rc} snv-btn" id="snv-pa-ok">
    I understand — Reload
  </button>
</div>`;

            try {
                (document.body || document.documentElement).appendChild(overlay);
            } catch { }

            // querySelector searches contentRoot (shadow), not document scope
            const btn = contentRoot.querySelector('#snv-pa-ok');
            if (btn) {
                btn.addEventListener('click', () => {
                    overlay.remove();
                    window.location.reload();
                }, { once: true });
            }

            // E7: Self-healing — re-append and reinforce visibility if overlay was
            // removed from DOM OR hidden via a CSS cosmetic filter. Using
            // overlay.isConnected (reference-based) instead of getElementById so an
            // attacker removing the element but keeping a same-id decoy doesn't fool us.
            if (_N.MutationObserver) {
                const _healDeadline = Date.now() + 180_000;
                const _healer = new _N.MutationObserver(() => {
                    // Bug 1c: Stale closure guard — if a newer render() has replaced
                    // _alertOverlay, this healer is orphaned. Disconnect immediately
                    // instead of trying to re-add an overlay that was intentionally removed.
                    if (overlay !== _alertOverlay) { _healer.disconnect(); return; }
                    if (Date.now() > _healDeadline) { _healer.disconnect(); _alertHealer = null; return; }
                    if (!overlay.isConnected) {
                        try { (document.body || document.documentElement).appendChild(overlay); } catch { }
                    }
                    // Reinforce display:flex!important in case a stylesheet injection hid it
                    try { overlay.style.setProperty('display', 'flex', 'important'); } catch { }
                });
                _alertHealer = _healer;
                try {
                    _healer.observe(document.body || document.documentElement, { childList: true, subtree: false });
                } catch { }
            }
        };

        if (document.body) {
            render();
        } else {
            window.addEventListener('DOMContentLoaded', render, { once: true });
        }
    }

    /* ──────────────────────────────────────────────────────────
       G2.  Console threat log
       ────────────────────────────────────────────────────────── */
    // Prints a styled red error to the DevTools console using the captured
    // _N.consoleError reference, so an attacker who replaces console.error
    // after daemon.js loads cannot suppress the message.
    function _logThreatToConsole(reason) {
        try {
            const _ce = _N.consoleError || console.error.bind(console);
            _ce(
                '%c⛔️  SafeNova Proactive  │  THREAT DETECTED',
                'background:#6a0000;color:#ff5555;font-size:13px;font-weight:700;padding:3px 8px;border-radius:3px'
            );
            _ce('%c' + String(reason),
                'color:#ff4444;font-weight:600;font-size:12px;padding-left:4px'
            );
            _ce(
                '%cAll encrypted session keys have been cleared. The container is locked.',
                'color:#cc6666;padding-left:4px'
            );
        } catch { }
    }

    /* ──────────────────────────────────────────────────────────
       G3.  Debugger trap (Self-XSS / console attack deterrent)
       ────────────────────────────────────────────────────────── */
    // Schedules a 'debugger' statement every 50 ms after a threat fires.
    // When DevTools are open the JS engine pauses at each breakpoint, blocking
    // follow-up console commands. When DevTools are closed this is a no-op.
    // The interval ID is stored in _trapIds so window.clearInterval (our guarded
    // wrapper) silently drops any attempt to cancel it from untrusted code.
    // The trap self-cancels after 5 minutes.
    function _startDebuggerTrap() {
        if (_debugTrapActive) return;
        _debugTrapActive = true;
        const _trapEnd = Date.now() + 300_000;
        const _tidRef = { id: null };
        const _fire = function snvDebugTrap() {
            debugger; // intentional — Self-XSS deterrent // eslint-disable-line no-debugger
            if (Date.now() > _trapEnd) {
                _N._clearInterval.call(window, _tidRef.id);
                _trapIds.delete(_tidRef.id);
                _debugTrapActive = false;
            }
        };
        _tidRef.id = _N._setInterval.call(window, _fire, 50);
        _trapIds.add(_tidRef.id);
    }

    function _triggerAlert(reason) {
        // Always clear storage immediately — even if we rate-limit the UI
        _nukeStorage();

        // Directly zero in-memory app state — bypasses the event system;
        // works even if App.lockContainer or the snv:lock listener was patched.
        _wipeAppState();

        // G2: Emit red console error — forensic trace visible in DevTools.
        _logThreatToConsole(reason);

        // G3: Start debugger trap — freezes DevTools console if open.
        _startDebuggerTrap();

        // Also signal via event so lockContainer() runs its full cleanup.
        try { window.dispatchEvent(new CustomEvent('snv:lock', { detail: { reason } })); } catch { }

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
       5.  Hook installation — double-hook pattern
           The real logic lives in IIFE-private _*Impl closures.
           The publicly assigned functions are thin forwarders, so
           fetch.toString() / XMLHttpRequest.prototype.open.toString()
           reveals only the forwarder body — not the security logic.

           _fetchImpl, _xhrOpenImpl, _sendBeaconImpl are invisible
           from the DevTools console (closure scope, not on window).
       ────────────────────────────────────────────────────────── */

    // ── Inner implementations (closure-private) ────────────────
    const _fetchImpl = function (input) {
        const url = (input instanceof Request) ? input.url : String(input ?? '');
        if (_isExternal(url)) {
            _triggerAlert('Outbound fetch blocked → ' + url);
            return Promise.reject(new Error('[SafeNova Proactive] External fetch blocked'));
        }
        return _N.fetch.apply(this === window ? window : globalThis, arguments);
    };

    const _xhrOpenImpl = function (method, url) {
        if (_isExternal(String(url ?? ''))) {
            _triggerAlert('Outbound XHR blocked → ' + url);
            throw new Error('[SafeNova Proactive] External XHR blocked');
        }
        return _N.xhrOpen.apply(this, arguments);
    };

    const _sendBeaconImpl = function (url) {
        if (_isExternal(String(url ?? ''))) {
            _triggerAlert('sendBeacon to external URL blocked → ' + url);
            return false;
        }
        return _N.sendBeacon.apply(navigator, arguments);
    };

    /* ──────────────────────────────────────────────────────────
       App state emergency wipe
       Captured after window 'load' so window.App is available.
       Directly nullifies in-memory key material as a direct
       bypass when the snv:lock event handler in main.js might
       itself be patched or replaced by an attacker.
       ────────────────────────────────────────────────────────── */
    let _appRef = null;
    // _appCryptoRefs: frozen snapshot of critical Crypto method references.
    // Populated at 'load' (after crypto.js has executed). Used in tick 6d.
    let _appCryptoRefs = null;
    // _appMethodRefs: frozen snapshot of critical App security method references.
    // Populated at 'load'. Used in tick 6e to detect App.lockContainer replacement.
    let _appMethodRefs = null;
    // _debugTrapActive: prevents stacking multiple 50 ms debugger intervals.
    let _debugTrapActive = false;
    // _trapIds: guarded set of debugger-trap interval IDs.
    // Our window.clearInterval wrapper silently drops calls targeting these.
    const _trapIds = new Set();
    // _readApp: safe reader for the `App` global const (state.js).
    // `const App = {...}` in state.js goes into the JS global LEXICAL environment
    // record, NOT onto the global object (window), so `window.App` is always
    // undefined. The bare identifier `App` resolves it via the scope chain at
    // call time (same technique as bare `Crypto` for crypto.js).  The function
    // is defined as an arrow so callers can safely call it inside try/catch
    // without worrying about `this` binding.
    const _readApp = () => (typeof App !== 'undefined' ? App : null);
    try {
        window.addEventListener('load', function () {
            try { _appRef = _readApp(); } catch { }
            // G1: Capture critical Crypto method references for tamper detection.
            // 'Crypto' bare identifier resolves to the app's script-scope const
            // (declared in crypto.js as `const Crypto = ...`), NOT to window.Crypto
            // (browser WebCrypto API). JS checks the declarative environment record
            // before the object environment record in the scope chain, so the app's
            // Crypto const shadows window.Crypto. We verify identity with .encrypt
            // (app module has it; browser WebCrypto does not — it has .subtle).
            try {
                if (typeof Crypto !== 'undefined' && typeof Crypto.encrypt === 'function') {
                    _appCryptoRefs = Object.freeze({
                        encrypt: Crypto.encrypt,
                        decrypt: Crypto.decrypt,
                        encryptBin: Crypto.encryptBin,
                        decryptBin: Crypto.decryptBin,
                        deriveKey: Crypto.deriveKey,
                        deriveKeyAndRaw: Crypto.deriveKeyAndRaw,
                    });
                }
            } catch { }
            // G1 (App security methods): capture App.lockContainer by value so
            // that a console-level replacement (App.lockContainer = () => {})
            // is detected on the next tick.  We use _readApp() (bare identifier)
            // instead of window.App because state.js declares `const App = {...}`,
            // which lands in the lexical env record, NOT on the global object.
            try {
                const _a = _readApp();
                if (_a && typeof _a.lockContainer === 'function') {
                    _appMethodRefs = Object.freeze({
                        lockContainer: _a.lockContainer,
                    });
                }
            } catch { }
        }, { once: true });
    } catch { }

    // Tracks whether _wipeAppState has already installed the DOM lockdown.
    // The veil and forced-reload run exactly once per page lifetime;
    // subsequent calls (one per watchdog tick) only re-zero key material.
    let _wipeExecuted = false;

    function _wipeAppState() {
        // ── Part 1 (always): zero in-memory key material ─────────────
        try {
            const a = _appRef || _readApp();
            if (a) {
                try { if (a.key !== undefined) a.key = null; } catch { }
                try { if (a.container !== undefined) a.container = null; } catch { }
                try { if (a.clipboard !== undefined) a.clipboard = null; } catch { }
                try { if (a.thumbCache !== undefined) a.thumbCache = {}; } catch { }
                try { if (a.selection instanceof Set) a.selection.clear(); } catch { }
            }
        } catch { }

        // ── Part 2 (once): DOM content wipe + veil + reload ────────
        // Bug 1a: guard ensures this block executes only ONCE per page lifetime
        // so the watchdog firing 3×/s does not stack 3 veils/s or schedule
        // dozens of competing reload timers.
        if (_wipeExecuted) return;
        _wipeExecuted = true;

        // Bug 2: Directly wipe DOM-resident decrypted content.
        // These operations use exclusively captured native references so the
        // attacker cannot intercept them by patching the live window/proto chain.
        // Helper: call a captured Document prototype method with document as context.
        const _docCall = (fn, arg) => {
            if (!fn) return null;
            try { return fn.call(document, arg); } catch { return null; }
        };

        // 2a. Zero editor textarea — wipes decrypted file plaintext from the DOM.
        //     Use the captured HTMLTextAreaElement.prototype.value setter — if an
        //     attacker redefined the .value property on the element instance or
        //     prototype, our captured setter still reaches the native C++ binding.
        try {
            const ta = _docCall(_N.docGetElementById, 'editor-textarea');
            if (ta) {
                if (_N.taValueSetter) _N.taValueSetter.call(ta, '');
                else ta.value = '';
            }
        } catch { }

        // 2b. Zero password input so credential is not visible after lockdown.
        try {
            const pw = _docCall(_N.docGetElementById, 'unlock-pw');
            if (pw) {
                if (_N.inputValueSetter) _N.inputValueSetter.call(pw, '');
                else pw.value = '';
            }
        } catch { }

        // 2c. Force-close open modals (editor, viewer) using !important to beat
        //     any injected stylesheet that tries to keep them visible.
        for (const id of ['modal-editor', 'modal-viewer']) {
            try {
                const el = _docCall(_N.docGetElementById, id);
                if (el) el.style.setProperty('display', 'none', 'important');
            } catch { }
        }

        // 2d. Force the view back to home: deactivate desktop, activate home.
        //     Uses classList directly (no hooked setters needed here — classList
        //     is a live DOMTokenList backed by the browser engine, not patchable
        //     from JS in a way that affects our captured getElementById result).
        try {
            const desktop = _docCall(_N.docGetElementById, 'view-desktop');
            if (desktop) {
                desktop.classList.remove('active');
                desktop.style.setProperty('display', 'none', 'important');
            }
        } catch { }
        try {
            const home = _docCall(_N.docGetElementById, 'view-home');
            if (home) {
                home.classList.add('active');
                home.style.removeProperty('display');
            }
        } catch { }

        // 2e. Revoke active Blob URLs so decrypted content (thumbnails, file previews)
        //     is freed from memory and the browser can no longer serve their data.
        try {
            if (_N.docQuerySelectorAll) {
                const _blobs = _N.docQuerySelectorAll.call(
                    document, 'img[src^="blob:"],video[src^="blob:"],a[href^="blob:"]');
                for (let i = 0; i < _blobs.length; i++) {
                    try {
                        const src = _blobs[i].src || _blobs[i].href || '';
                        if (src) _N.revokeObjectURL(src);
                    } catch { }
                }
            }
        } catch { }

        // 2f. Clear in-memory VFS tree — holds decrypted file metadata and structure.
        try { if (typeof window.VFS !== 'undefined') window.VFS.init(); } catch { }

        // 2g. Close all floating window panels — they contain decrypted filenames and icons.
        try {
            if (typeof window.WinManager !== 'undefined') window.WinManager.closeAll();
        } catch { }

        // F3: Security barrier veil — animated diagonal stripes (Minecraft barrier style).
        // Covers all application content below the alert overlay.
        // z-index 2147483646: below alert (2147483647), above everything else.
        // CSS class "snv-veil" provides visual styles; _ALERT_HOST_CLS defeats ABP.
        //
        // Technique: linear-gradient (NOT repeating) over a square tile with stops at
        // 25 % / 50 % / 75 % / 100 %. This is the only approach that produces clean
        // parallel diagonal stripes without the diamond / hexagon artefacts that
        // repeating-linear-gradient produces when tiled with background-size.
        //
        // Tile size T = 32 px.  Animation: shift background-position by (T, T) per
        // cycle — the square tile guarantees a perfectly seamless loop at any speed.
        //
        // Stripe colours:
        //   dark band  → rgba(6, 0, 0, 0.92) — near-black with a faint red tint
        //   light band → rgba(155, 18, 18, 0.60) — muted dark red, semi-transparent
        //
        // NOTE: No background-color — stripes are semi-transparent so the app
        // content bleeds through, making the barrier visible but not fully opaque.
        try {
            const _T = 32; // tile side, px — must be even for clean 50 % boundary
            const _Tpx = _T + 'px';
            const _dark = 'rgba(6,0,0,.92)';
            const _red = 'rgba(155,18,18,.60)';
            const _barrier = [
                'linear-gradient(-45deg,',
                _dark + ' 0%,' + _dark + ' 25%,',
                _red + ' 25%,' + _red + ' 50%,',
                _dark + ' 50%,' + _dark + ' 75%,',
                _red + ' 75%,' + _red + ' 100%)',
            ].join('');
            const veil = _N.createElement.call(document, 'div');
            veil.className = _ALERT_HOST_CLS + ' snv-veil';
            for (const [p, v] of [
                ['position', 'fixed'],
                ['inset', '0'],
                ['z-index', '2147483646'],
                ['background-image', _barrier],
                ['background-size', _Tpx + ' ' + _Tpx],
                ['display', 'block'],
            ]) { try { veil.style.setProperty(p, v, 'important'); } catch { } }
            (document.body || document.documentElement).appendChild(veil);
            // Shifting background-position by exactly one tile (T, T) per iteration
            // is mathematically guaranteed to produce a seamless loop.
            if (_N.elementAnimate) {
                try {
                    _N.elementAnimate.call(veil,
                        [{ backgroundPosition: '0 0' },
                        { backgroundPosition: _Tpx + ' ' + _Tpx }],
                        { duration: 700, iterations: Infinity, easing: 'linear' }
                    );
                } catch { }
            }
        } catch { }
    }

    // ── Publicly visible hooks (thin forwarders only) ──────────
    const _H = {}; // live hook references — checked every tick

    function _installHooks() {
        // toString() on each of these shows only the one-liner forwarder.
        // The actual check logic inside _*Impl is unreachable from outside.
        _H.fetch = function snvFetch() { return _fetchImpl.apply(this, arguments); };
        window.fetch = _H.fetch;

        _H.xhrOpen = function snvXhrOpen() { return _xhrOpenImpl.apply(this, arguments); };
        XMLHttpRequest.prototype.open = _H.xhrOpen;

        if (_N.sendBeacon) {
            _H.sendBeacon = function snvSendBeacon() { return _sendBeaconImpl.apply(this, arguments); };
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
    let _heartbeatN = 0; // monotonic counter for dead man's switch (E5)
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

        // 6d. App function integrity — verify critical Crypto module methods
        //     have not been replaced via the DevTools console (Self-XSS / G1).
        //     'Crypto' (bare identifier) resolves to the app's script-scope const
        //     via the JS declarative env record (checked before the object env record
        //     where window.Crypto / WebCrypto lives).
        //     _appCryptoRefs is null until 'load' fires — early ticks are safe.
        if (_appCryptoRefs) {
            let _liveC = null;
            try { _liveC = Crypto; } catch { /* Crypto became undefined — treat as tampered */ }
            if (!_liveC ||
                _liveC.encrypt !== _appCryptoRefs.encrypt ||
                _liveC.decrypt !== _appCryptoRefs.decrypt ||
                _liveC.encryptBin !== _appCryptoRefs.encryptBin ||
                _liveC.decryptBin !== _appCryptoRefs.decryptBin ||
                _liveC.deriveKey !== _appCryptoRefs.deriveKey ||
                _liveC.deriveKeyAndRaw !== _appCryptoRefs.deriveKeyAndRaw
            ) {
                _triggerAlert('App function tampered: Crypto');
                return;
            }
        }

        // 6e. App method integrity — verify App.lockContainer has not been
        //     replaced via the DevTools console (Self-XSS).
        //     `const App = {...}` in state.js is in the JS global LEXICAL env
        //     record, not on window. Use _readApp() (bare identifier) to read it.
        //     Captures both: property replacement (App.lockContainer = () => {})
        //     and full object substitution.
        //     _appMethodRefs is null until 'load' fires — early ticks are safe.
        if (_appMethodRefs) {
            let _liveApp = null;
            try { _liveApp = _readApp(); } catch { }
            if (!_liveApp || _liveApp.lockContainer !== _appMethodRefs.lockContainer) {
                _triggerAlert('App function tampered: lockContainer');
                return;
            }
        }

        // 6c. Dead man's switch heartbeat — monotonic counter (C1/E5)
        //     main.js accepts ONLY events where counter is strictly increasing.
        //     An attacker faking snv:alive events cannot know the current count.
        try { window.dispatchEvent(new CustomEvent('snv:alive', { detail: { n: ++_heartbeatN } })); } catch { }
    }

    /* ──────────────────────────────────────────────────────────
       7.  Guard token, __snvVerify, __snvEmergencyLock
       ────────────────────────────────────────────────────────── */
    // Guard token includes the session canary for __snvVerify cross-check.
    // If _guardPreexisted == true, the attacker pre-defined this property as
    // non-configurable; our Object.defineProperty will throw but __snvVerify
    // will return false because the attacker's guard won't carry our _canary.
    try {
        Object.defineProperty(window, '__snvGuard', {
            value: Object.freeze({ active: _captureClean, version: 5, _c: _canary }),
            writable: false,
            configurable: false,
            enumerable: false,
        });
    } catch { /* pre-defined by attacker — __snvVerify will catch this */ }

    // __snvVerify — canary cross-check. main.js calls this instead of (or in addition
    // to) checking __snvGuard.active. Attacker who pre-defined __snvGuard cannot
    // produce the correct _canary without reading this IIFE's closure at runtime.
    try {
        Object.defineProperty(window, '__snvVerify', {
            value: function snvVerify() {
                return _captureClean &&
                    !_guardPreexisted &&
                    typeof window.__snvGuard === 'object' &&
                    window.__snvGuard !== null &&
                    window.__snvGuard._c === _canary;
            },
            writable: false,
            configurable: false,
            enumerable: false,
        });
    } catch { /* attacker pre-defined — main.js falls back to __snvGuard.active */ }

    // __snvEmergencyLock — exposed non-configurable function that wipes storage
    // and app state directly, bypassing the event system entirely.
    try {
        Object.defineProperty(window, '__snvEmergencyLock', {
            value: function snvEmergencyLock() { _nukeStorage(); _wipeAppState(); },
            writable: false,
            configurable: false,
            enumerable: false,
        });
    } catch { }

    // If captures were already tainted, do NOT start watchdog — just bail.
    // The app will show the "Proactive failed to initialize" screen.
    if (!_captureClean) return;

    /* ──────────────────────────────────────────────────────────
       8.  Boot — three independent timer mechanisms (B1-B4)
           Killing the watchdog requires neutralizing ALL THREE.
       ────────────────────────────────────────────────────────── */
    _installHooks();

    // Timer IDs for the watchdog — guarded against clearInterval/clearTimeout
    const _watchdogIds = new Set();

    // ── Mechanism 1: setInterval (1 000 ms) ────────────────────
    const _ivId = _N._setInterval.call(window, _tick, 1000);
    _watchdogIds.add(_ivId);

    // ── Mechanism 2: recursive setTimeout (~937 ms, prime offset) ─
    //    For recursive setTimeout the timer IDs change every iteration.
    //    We cap the Set to the last 8 IDs to avoid unbounded memory growth
    //    (at 937 ms cadence this is ~7.5 seconds of IDs — more than enough
    //    to foil an attacker who reads the current Set snapshot in the
    //    brief window between when a new ID is generated and added).
    (function _stLoop() {
        _tick();
        const id = _N._setTimeout.call(window, _stLoop, 937);
        _watchdogIds.add(id);
        if (_watchdogIds.size > 16) {
            const iter = _watchdogIds.values();
            // keep the first entry (setInterval ID) + trim oldest setTimeout IDs
            iter.next(); // skip _ivId
            const oldest = iter.next().value;
            _watchdogIds.delete(oldest);
        }
    })();

    // ── Mechanism 3: requestAnimationFrame chain ───────────────
    //    rAF cannot be killed via clearInterval/clearTimeout.
    //    Throttled to ~1 s cadence to avoid burning CPU.
    //    _rafId is tracked so the cancelAnimationFrame guard (E4)
    //    can silently ignore attempts to kill this specific chain.
    let _lastRafTick = 0, _rafId = null;
    function _rafLoop(ts) {
        if (ts - _lastRafTick >= 980) { _lastRafTick = ts; _tick(); }
        _rafId = _N._requestAnimationFrame.call(window, _rafLoop);
    }
    _rafId = _N._requestAnimationFrame.call(window, _rafLoop);

    // ── B2: Guard clearInterval / clearTimeout ─────────────────
    //    If external code tries to clear our watchdog timer IDs,
    //    silently ignore the call. Legitimate code never targets
    //    foreign timer IDs.
    window.clearInterval = function snvClearInterval(id) {
        if (_watchdogIds.has(id) || _trapIds.has(id)) return; // protect watchdog + trap
        return _N._clearInterval.call(window, id);
    };
    window.clearTimeout = function snvClearTimeout(id) {
        if (_watchdogIds.has(id)) return;
        return _N._clearTimeout.call(window, id);
    };

    // ── E4: Guard cancelAnimationFrame ─────────────────────────
    //    Silently ignore attempts to cancel our rAF chain ID.
    if (_N._cancelAnimationFrame) {
        window.cancelAnimationFrame = function snvCancelAnimationFrame(id) {
            if (_rafId !== null && id === _rafId) return;
            return _N._cancelAnimationFrame.call(window, id);
        };
    }

    // ── E6: WebSocket hook ──────────────────────────────
    //    SafeNova makes no WebSocket connections.
    //    Any attempt to open a WebSocket to an external host
    //    is blocked and triggers a threat alert.
    const _NativeWebSocket = window.WebSocket;
    if (_NativeWebSocket && _isNative(_NativeWebSocket)) {
        window.WebSocket = function snvWebSocket(url) {
            const urlStr = String(url ?? '');
            const isSameOrigin = (function () {
                try {
                    // WebSocket URLs must be absolute: ws:// or wss://
                    const m = urlStr.match(/^wss?:\/\/([^/:?#]+)/i);
                    if (!m) return false; // malformed or non-ws URL — block
                    return m[1].toLowerCase() === window.location.hostname;
                } catch { return false; }
            }());
            if (!isSameOrigin) {
                _triggerAlert('WebSocket to external host blocked \u2192 ' + urlStr);
                throw new Error('[SafeNova Proactive] External WebSocket blocked');
            }
            return arguments.length >= 2
                ? new _NativeWebSocket(arguments[0], arguments[1])
                : new _NativeWebSocket(arguments[0]);
        };
        try { window.WebSocket.prototype = _NativeWebSocket.prototype; } catch { }
    }

    // ── D1: Visibility-change fast check ───────────────────────
    //    When the tab becomes visible again, run an immediate full
    //    tick so an attacker cannot exploit the ~1 s gap.
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') _tick();
    });

})();
