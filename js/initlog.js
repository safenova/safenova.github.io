'use strict';

/* ============================================================
   INITLOG  —  Initialization stage console logger

   Usage:
     InitLog.start()            — open grouped output, start timer
     InitLog.step('label')      — mark stage start (prints offset from boot)
     InitLog.done('label', d?)  — mark stage done  (prints elapsed for stage)
     InitLog.error('label', err)— mark stage failed
     InitLog.finish()           — close group, print total boot time
   ============================================================ */
const InitLog = (() => {
    let _t0 = null;
    const _timers = {};

    const _S = {
        badge: 'font-size:11px;font-weight:700;color:#1e1e1e;background:#0078d4;padding:1px 6px;border-radius:2px;font-family:Consolas,monospace',
        title: 'font-size:11px;font-weight:700;color:#0078d4;font-family:Consolas,monospace',
        step: 'font-size:11px;color:#4ec9b0;font-family:Consolas,monospace',
        lbl: 'font-size:11px;color:#d4d4d4;font-family:Consolas,monospace',
        done: 'font-size:11px;color:#89d185;font-family:Consolas,monospace',
        err: 'font-size:11px;font-weight:700;color:#f44747;font-family:Consolas,monospace',
        dim: 'font-size:11px;color:#858585;font-family:Consolas,monospace',
        time: 'font-size:11px;color:#ce9178;font-family:Consolas,monospace',
    };

    function _ts() { return _t0 != null ? '+' + (performance.now() - _t0).toFixed(1) + 'ms' : ''; }
    function _elapsed(label) { const t = _timers[label]; return t != null ? (performance.now() - t).toFixed(1) + 'ms' : ''; }

    function start() {
        _t0 = performance.now();
        console.groupCollapsed('%c SNV %c Initialization', _S.badge, _S.title);
    }

    function step(label) {
        _timers[label] = performance.now();
        console.log('%c ▶ %c' + label + ' %c' + _ts(), _S.step, _S.lbl, _S.dim);
    }

    function done(label, detail) {
        const elapsed = _elapsed(label);
        const suffix = detail ? '  · ' + detail : '';
        console.log('%c ✓ %c' + label + suffix + ' %c' + elapsed, _S.done, _S.lbl, _S.time);
    }

    function error(label, err) {
        const msg = err instanceof Error ? err.message : String(err ?? '');
        console.log('%c ✗ %c' + label + ' %c' + msg, _S.err, _S.lbl, _S.err);
    }

    function finish() {
        const total = _t0 != null ? (performance.now() - _t0).toFixed(1) : '?';
        console.log('%c ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', _S.dim);
        console.log('%c ✔ %cReady  %c' + total + 'ms', _S.done, _S.lbl, _S.time);
        console.groupEnd();
    }

    return { start, step, done, error, finish };
})();
