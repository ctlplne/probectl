/*!
 * probectl-rum.js — the probectl real-user-monitoring beacon (S47b, F20).
 *
 * Privacy by construction (the SDK side of a contract the SERVER re-enforces):
 *   - Sends NOTHING until your consent callback fires (window.probectlRUM.consent()).
 *   - Respects Do-Not-Track / Global Privacy Control: never arms when set.
 *   - Sends the page PATH only — query strings and fragments never leave the
 *     browser; the server re-redacts and collapses volatile segments anyway.
 *   - No cookies, no storage, no fingerprinting, no user identifiers, no IP
 *     handling (and the server refuses payloads carrying unknown fields).
 *
 * Performance: passive PerformanceObservers + one navigator.sendBeacon on
 * pagehide. No synchronous XHR, no long tasks, < 2 KiB minified.
 *
 * Embed (see docs/rum.md):
 *   <script src="https://probectl.example/probectl-rum.js"
 *           data-key="pk_your_app_key"
 *           data-endpoint="https://probectl.example/ingest/rum" defer></script>
 *   then, AFTER your consent banner accepts: window.probectlRUM.consent()
 */
(function () {
  'use strict';
  var script = document.currentScript;
  if (!script) return;
  var key = script.getAttribute('data-key');
  var endpoint = script.getAttribute('data-endpoint');
  if (!key || !endpoint) return;

  // DNT / GPC: never arm. (The server cannot see these signals — honoring
  // them is the SDK's job.)
  if (navigator.doNotTrack === '1' || window.globalPrivacyControl) return;

  var consented = false;
  var sent = false;
  var vitals = {};
  var errors = 0;
  var failed = 0;

  // Web vitals via passive observers (buffered: late registration still sees
  // earlier entries).
  function observe(type, fn) {
    try {
      new PerformanceObserver(fn).observe({ type: type, buffered: true });
    } catch (e) { /* older browsers: vitals stay absent — absence is honest */ }
  }
  observe('largest-contentful-paint', function (l) {
    var es = l.getEntries();
    if (es.length) vitals.lcp_ms = Math.round(es[es.length - 1].startTime);
  });
  observe('paint', function (l) {
    l.getEntries().forEach(function (e) {
      if (e.name === 'first-contentful-paint') vitals.fcp_ms = Math.round(e.startTime);
    });
  });
  observe('layout-shift', function (l) {
    l.getEntries().forEach(function (e) {
      if (!e.hadRecentInput) vitals.cls = Math.round(((vitals.cls || 0) + e.value) * 1000) / 1000;
    });
  });
  observe('event', function (l) {
    l.getEntries().forEach(function (e) {
      var d = Math.round(e.duration);
      if (!vitals.inp_ms || d > vitals.inp_ms) vitals.inp_ms = d;
    });
  });

  window.addEventListener('error', function () { errors++; }, { passive: true });
  window.addEventListener('unhandledrejection', function () { errors++; }, { passive: true });

  function navTimings() {
    var nav = performance.getEntriesByType && performance.getEntriesByType('navigation')[0];
    if (!nav) return;
    if (nav.responseStart > 0) vitals.ttfb_ms = Math.round(nav.responseStart);
    if (nav.loadEventEnd > 0) vitals.load_ms = Math.round(nav.loadEventEnd);
    if (nav.responseStatus && nav.responseStatus >= 400) failed++;
  }

  function send() {
    if (sent || !consented) return;
    sent = true;
    navTimings();
    var beacon = {
      v: 1,
      key: key,
      consent: true,
      host: location.hostname.toLowerCase(),
      page: location.pathname, // PATH ONLY — query/fragment never leave the page
      browser: browserFamily(),
      vitals: vitals,
      errors: errors,
      failed_requests: failed,
      sdk: '0.1.0'
    };
    try {
      // text/plain avoids a CORS preflight; the server parses JSON regardless.
      navigator.sendBeacon(endpoint, new Blob([JSON.stringify(beacon)], { type: 'text/plain' }));
    } catch (e) { /* never break the page for telemetry */ }
  }

  function browserFamily() {
    var ua = navigator.userAgent; // inspected locally; NEVER transmitted
    if (/Edg\//.test(ua)) return 'edge';
    if (/Firefox\//.test(ua)) return 'firefox';
    if (/Chrome\//.test(ua)) return 'chrome';
    if (/Safari\//.test(ua)) return 'safari';
    return 'other';
  }

  // One beacon per page view, at pagehide (covers tab close + navigation).
  window.addEventListener('pagehide', send, { passive: true });
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') send();
  }, { passive: true });

  // The consent gate: nothing is ever sent before this is called.
  window.probectlRUM = {
    consent: function () { consented = true; },
    revoke: function () { consented = false; }
  };
})();
