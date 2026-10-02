// Modest, same-origin UI helpers: local-time rendering and queue count polling. No external resources.
(function () {
  var tzEl = document.getElementById('tz');
  if (tzEl) { try { tzEl.textContent = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { tzEl.textContent = 'local'; } }
  function fmt(iso, rel) {
    if (!iso || iso === 'None') return '';
    var d = new Date(iso); if (isNaN(d.getTime())) return iso;
    if (rel) { var s = Math.round((Date.now() - d.getTime()) / 1000); if (s < 60) return s + 's ago'; if (s < 3600) return Math.round(s / 60) + 'm ago'; if (s < 86400) return Math.round(s / 3600) + 'h ago'; }
    return d.toLocaleString(undefined, { hour12: false, timeZoneName: 'short' });
  }
  function renderTimes() { var els = document.querySelectorAll('time[data-ts]'); for (var i = 0; i < els.length; i++) { var e = els[i]; e.title = e.getAttribute('data-ts'); e.textContent = fmt(e.getAttribute('data-ts'), e.getAttribute('data-rel') === '1'); } }
  renderTimes();
  var count = document.getElementById('queue-count');
  function poll() {
    fetch('/api/ui/queue', { credentials: 'same-origin' }).then(function (r) { return r.ok ? r.json() : null; }).then(function (j) {
      if (!j || !count) return; var n = (j.pending_requests || 0) + (j.pending_responses || 0); count.textContent = n ? String(n) : ''; count.style.display = n ? 'inline-block' : 'none';
      if (document.body.getAttribute('data-autorefresh') === '1') { location.reload(); }
    }).catch(function () {});
  }
  if (count) { poll(); setInterval(poll, 5000); }
})();
