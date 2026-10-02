// Modest, same-origin UI helpers: local-time rendering, pending-decision polling with auto-refresh, and
// form posts that replace the current history entry. No external resources.
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

  // Form posts go through fetch so the redirect target replaces this history entry: Back returns to the
  // page you came from instead of the pre-submit copy of this one. Without JS the forms post normally.
  document.addEventListener('submit', function (ev) {
    var form = ev.target;
    if (!form || (form.method || '').toLowerCase() !== 'post' || form.hasAttribute('data-native') || ev.defaultPrevented) return;
    ev.preventDefault();
    var buttons = form.querySelectorAll('button'); for (var i = 0; i < buttons.length; i++) buttons[i].disabled = true;
    fetch(form.action, { method: 'POST', body: new URLSearchParams(new FormData(form)), credentials: 'same-origin' }).then(function (r) {
      if (r.redirected) { location.replace(r.url); return null; }
      return r.text().then(function (html) { document.open(); document.write(html); document.close(); });
    }).catch(function () { for (var i = 0; i < buttons.length; i++) buttons[i].disabled = false; });
  });

  // Typing or a changed field means the reviewer is mid-decision; never reload under them.
  function busy() {
    var a = document.activeElement;
    if (a && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName) && a.type !== 'hidden' && a.type !== 'submit') return true;
    var fields = document.querySelectorAll('main input:not([type=hidden]), main textarea');
    for (var i = 0; i < fields.length; i++) { var f = fields[i]; if (f.type === 'checkbox' || f.type === 'radio' ? f.checked !== f.defaultChecked : f.value !== f.defaultValue) return true; }
    return false;
  }
  function setPill(id, n) { var el = document.getElementById(id); if (!el) return; el.textContent = n ? String(n) : ''; el.style.display = n ? 'inline-block' : 'none'; }
  var autorefresh = document.body.getAttribute('data-autorefresh') === '1';
  var seen = null, stale = false;
  function poll() {
    fetch('/api/ui/queue', { credentials: 'same-origin' }).then(function (r) { return r.ok ? r.json() : null; }).then(function (j) {
      if (!j) return;
      var openProposals = (j.pending_proposals || 0) + (j.stale_proposals || 0);
      setPill('queue-count', (j.pending_requests || 0) + (j.pending_responses || 0));
      setPill('proposals-count', openProposals);
      var counts = { pending_requests: j.pending_requests || 0, pending_responses: j.pending_responses || 0, open_proposals: openProposals };
      var banner = document.getElementById('pending-banner');
      if (banner) {
        var spans = banner.querySelectorAll('[data-count]'); for (var i = 0; i < spans.length; i++) spans[i].textContent = String(counts[spans[i].getAttribute('data-count')]);
        banner.hidden = !(counts.pending_requests || counts.pending_responses || counts.open_proposals);
      }
      if (seen === null) { seen = j.fingerprint; return; }
      if (j.fingerprint !== seen && autorefresh) {
        if (busy()) { stale = true; var n = document.getElementById('update-notice'); if (n) n.hidden = false; }
        else { location.reload(); }
      }
    }).catch(function () {});
  }
  if (document.getElementById('queue-count')) { poll(); setInterval(poll, 5000); }
  document.addEventListener('focusout', function () { if (stale && !busy()) { setTimeout(function () { if (!busy()) location.reload(); }, 300); } });
})();
