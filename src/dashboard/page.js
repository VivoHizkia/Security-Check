// The dashboard is one self-contained page: no build step, no CDN, nothing fetched but /api.
// Everything that comes from a scan (titles, code snippets, paths) is untrusted and goes through esc().

const STYLE = `
:root{--bg:#f6f7f9;--panel:#fff;--panel2:#f0f2f5;--line:#e2e5ea;--text:#16191f;--muted:#5d6675;--accent:#2f6fde;--accent-ink:#fff;
--critical:#b4232a;--high:#d4542b;--medium:#b7791f;--low:#3d7bb8;--info:#6b7280;--ok:#2f855a;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--panel:#171a21;--panel2:#1e222b;--line:#2a2f3a;--text:#e7e9ee;--muted:#9aa3b2;--accent:#5b8ff0;
--critical:#f0646b;--high:#f28a5b;--medium:#e6b450;--low:#6aa7e6;--info:#9aa3b2;--ok:#5fc48c;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
code,.mono{font-family:ui-monospace,"Cascadia Code",Consolas,monospace;font-size:12.5px}
header{display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--line);background:var(--panel)}
header h1{font-size:16px;margin:0;letter-spacing:.2px}header .tag{color:var(--muted);font-size:12.5px}
.layout{display:grid;grid-template-columns:290px 1fr;min-height:calc(100vh - 51px)}
aside{border-right:1px solid var(--line);background:var(--panel);padding:14px;display:flex;flex-direction:column;gap:12px}
main{padding:22px 26px;min-width:0}
.plist{display:flex;flex-direction:column;gap:4px}
.pitem{display:grid;grid-template-columns:1fr auto;gap:2px 8px;padding:9px 10px;border-radius:8px;cursor:pointer;border:1px solid transparent;background:none;color:inherit;text-align:left;font:inherit}
.pitem:hover{background:var(--panel2)}.pitem[aria-current=true]{background:var(--panel2);border-color:var(--line)}
.pitem .grade{justify-self:end}.tablewrap{overflow-x:auto;border-radius:10px}
.pitem .n{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.pitem .s{color:var(--muted);font-size:12px}
.grade{display:inline-grid;place-items:center;min-width:26px;height:22px;padding:0 6px;border-radius:6px;font-weight:700;font-size:12.5px;color:#fff}
.gA{background:var(--ok)}.gB{background:#4f8a3a}.gC{background:var(--medium)}.gD{background:var(--high)}.gF{background:var(--critical)}.g-{background:var(--info)}
form.add{display:flex;flex-direction:column;gap:6px;border-top:1px solid var(--line);padding-top:12px;margin-top:auto}
input[type=text],select{width:100%;padding:7px 9px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--text);font:inherit}
button{font:inherit;cursor:pointer;border-radius:7px;border:1px solid var(--line);background:var(--panel2);color:var(--text);padding:7px 12px}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink);font-weight:600}
button:disabled{opacity:.55;cursor:progress}button.link{border:none;background:none;color:var(--muted);padding:4px}
button.danger{color:var(--critical)}
.muted{color:var(--muted)}.small{font-size:12.5px}
.top{display:flex;flex-wrap:wrap;align-items:flex-start;gap:16px;justify-content:space-between}
.top h2{margin:0 0 2px;font-size:20px}.actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:18px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}.card .v{font-size:26px;font-weight:700;margin-top:2px}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.chip{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line)}
.dot{width:8px;height:8px;border-radius:50%}
.sev{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11.5px;font-weight:700;text-transform:uppercase;color:#fff;letter-spacing:.3px}
.s-critical{background:var(--critical)}.s-high{background:var(--high)}.s-medium{background:var(--medium)}.s-low{background:var(--low)}.s-info{background:var(--info)}
.d-critical{background:var(--critical)}.d-high{background:var(--high)}.d-medium{background:var(--medium)}.d-low{background:var(--low)}.d-info{background:var(--info)}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin:22px 0 14px}
.tabs button{border:none;background:none;border-bottom:2px solid transparent;border-radius:0;padding:8px 12px;color:var(--muted)}
.tabs button[aria-selected=true]{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
.finding{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-bottom:8px}
.finding .h{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}.finding .t{font-weight:600}
.finding .loc{color:var(--muted)}.finding .det{margin:6px 0 0;color:var(--muted);word-break:break-word}.finding .fix{margin:6px 0 0}
.filters{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}.filters select{width:auto}.filters input{max-width:280px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--muted);font-weight:600;background:var(--panel2)}
tr:last-child td{border-bottom:none}tr.click{cursor:pointer}tr.click:hover td{background:var(--panel2)}
.auth{font-size:12px;font-weight:600;white-space:nowrap}td.mono{white-space:nowrap}.a-required{color:var(--ok)}.a-likely{color:var(--ok)}.a-none{color:var(--critical)}.a-unknown{color:var(--medium)}
.diff{display:grid;grid-template-columns:1fr 1fr;gap:12px}.diff ul{margin:6px 0 0;padding-left:18px}.diff li{margin:3px 0}
.chart{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.chart svg{display:block;width:100%;height:auto;max-height:160px}
.empty{text-align:center;padding:60px 20px;color:var(--muted)}.empty h2{color:var(--text)}
.err{color:var(--critical);font-size:13px;min-height:1em}
.banner{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin-top:12px;font-size:13px}
.mb12{margin-bottom:12px}.mt12{margin-top:12px}.mt6{margin-top:6px}.pad12{padding:12px}.okc{color:var(--ok)}.card .v.v15{font-size:15px;font-weight:600;margin-top:6px}
input.w320{width:320px;max-width:100%}tr[aria-current=true] td{font-weight:600}
@media (max-width:800px){.layout{grid-template-columns:1fr}aside{border-right:none;border-bottom:1px solid var(--line)}main{padding:16px}.diff{grid-template-columns:1fr}}
`;

const SCRIPT = `
const TOKEN = document.querySelector('meta[name=tameng-token]').content;
const SEVS = ['critical','high','medium','low','info'];
const state = { projects: [], current: null, view: null, scans: [], tab: 'findings', sev: 'all', q: '', busy: false, offline: false };
const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));

async function api(method, url, body) {
  const res = await fetch(url, { method, headers: { 'x-tameng-token': TOKEN, ...(body && { 'content-type': 'application/json' }) }, body: body && JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Request failed (' + res.status + ')');
  return data;
}

const when = (iso) => iso ? new Date(iso).toLocaleString() : '';
const grade = (g) => '<span class="grade g' + esc(g || '-') + '">' + esc(g || '–') + '</span>';

function spark(points, w = 70, h = 22) {
  if (points.length < 2) return '';
  const xs = points.map((_, i) => (i / (points.length - 1)) * w);
  const ys = points.map((p) => h - 2 - (p.score / 100) * (h - 4));
  return '<svg width="' + w + '" height="' + h + '" aria-hidden="true"><polyline fill="none" stroke="currentColor" stroke-width="1.5" points="' + xs.map((x, i) => x.toFixed(1) + ',' + ys[i].toFixed(1)).join(' ') + '"/></svg>';
}

function renderList() {
  // Every interpolated value below goes through esc().
  $('#plist').innerHTML = state.projects.length ? state.projects.map((p) => // tameng-ignore
    '<button class="pitem" data-id="' + esc(p.id) + '" aria-current="' + (p.id === state.current) + '">' +
      '<span class="n">' + esc(p.name) + '</span>' + grade(p.last?.grade) +
      '<span class="s">' + (p.last ? esc(p.last.score) + '/100 · ' + esc(p.last.total) + (p.last.total === 1 ? ' finding' : ' findings') : 'not scanned yet') + '</span>' +
      '<span class="s muted">' + spark(p.trend) + '</span>' +
    '</button>').join('') : '<p class="muted small">No projects yet. Add a folder below.</p>';
}

function chart(scans) {
  if (scans.length < 2) return '<p class="muted small">The trend appears after the second scan.</p>';
  const pts = scans.slice(-30), W = 600, H = 120, P = 8;
  const x = (i) => P + (i / (pts.length - 1)) * (W - 2 * P), y = (s) => H - P - (s / 100) * (H - 2 * P);
  const line = pts.map((s, i) => x(i).toFixed(1) + ',' + y(s.score).toFixed(1)).join(' ');
  const dots = pts.map((s, i) => '<circle cx="' + x(i).toFixed(1) + '" cy="' + y(s.score).toFixed(1) + '" r="3" fill="var(--accent)"><title>' + esc(when(s.startedAt) + ' — ' + s.score + '/100') + '</title></circle>').join('');
  const grid = [100, 75, 50].map((v) => '<line x1="0" x2="' + W + '" y1="' + y(v) + '" y2="' + y(v) + '" stroke="var(--line)"/><text x="' + (W - 2) + '" y="' + (y(v) - 3) + '" text-anchor="end" font-size="10" fill="var(--muted)">' + v + '</text>').join('');
  return '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Score over time">' + grid + '<polyline fill="none" stroke="var(--accent)" stroke-width="2" points="' + line + '"/>' + dots + '</svg>';
}

function findingCard(f) {
  return '<div class="finding"><div class="h"><span class="sev s-' + esc(f.severity) + '">' + esc(f.severity) + '</span>' +
    '<span class="t">' + esc(f.title) + '</span><span class="loc mono">' + esc(f.location) + '</span><span class="muted small">' + esc(f.scanner) + '</span></div>' +
    (f.detail ? '<p class="det mono">' + esc(f.detail) + '</p>' : '') + (f.fix ? '<p class="fix">→ ' + esc(f.fix) + '</p>' : '') + '</div>';
}

function tabFindings(r) {
  const list = r.findings.filter((f) => (state.sev === 'all' || f.severity === state.sev) &&
    (!state.q || (f.title + ' ' + f.location + ' ' + f.id).toLowerCase().includes(state.q.toLowerCase())));
  return '<div class="filters"><select id="sev" aria-label="Severity"><option value="all">All severities</option>' +
    SEVS.map((s) => '<option value="' + s + '"' + (state.sev === s ? ' selected' : '') + '>' + s + ' (' + r.summary.counts[s] + ')</option>').join('') +
    '</select><input type="text" id="q" placeholder="Filter by text, file or rule" value="' + esc(state.q) + '"></div>' +
    (list.length ? list.map(findingCard).join('') : '<p class="muted">' + (r.findings.length ? 'Nothing matches the filter.' : 'No findings. Nice.') + '</p>');
}

function tabSurface(r) {
  const s = r.surface;
  if (!s || !s.endpoints.length) return '<p class="muted">No endpoints found (supports Laravel routes, Next.js route handlers, pages/api, Server Actions and Express).</p>';
  const count = (a) => s.endpoints.filter((e) => e.auth === a).length;
  const label = { required: 'auth required', likely: 'auth check found', none: 'no auth', unknown: 'no auth check found' };
  return '<div class="chips mb12">' +
    ['none', 'unknown', 'likely', 'required'].filter(count).map((a) => '<span class="chip"><span class="auth a-' + a + '">' + count(a) + '</span> ' + label[a] + '</span>').join('') +
    '</div>' + s.notes.map((n) => '<p class="banner">' + esc(n) + '</p>').join('') +
    '<div class="tablewrap"><table><thead><tr><th>Method</th><th>Endpoint</th><th>Protection</th><th>Source</th></tr></thead><tbody>' +
    s.endpoints.map((e) => '<tr><td class="mono">' + esc(e.method) + '</td><td class="mono">' + esc(e.path) + (e.admin ? ' <span class="chip">admin</span>' : '') +
      '</td><td><span class="auth a-' + esc(e.auth) + '">' + esc(label[e.auth]) + '</span></td><td class="mono muted">' + esc(e.file + ':' + e.line) + '</td></tr>').join('') +
    '</tbody></table></div><p class="muted small">"No auth check found" means the handler itself does not call an auth helper. It may still be guarded by middleware, so treat it as a list to review, not a verdict.</p>';
}

function tabHistory() {
  if (!state.scans.length) return '<p class="muted">No scans yet.</p>';
  return '<div class="tablewrap"><table><thead><tr><th>When</th><th>Score</th><th>Findings</th><th>Duration</th></tr></thead><tbody>' +
    state.scans.slice().reverse().map((s) => '<tr class="click" data-scan="' + esc(s.scanId) + '"' + (state.view?.scanId === s.scanId ? ' aria-current="true"' : '') + '><td>' + esc(when(s.startedAt)) +
      '</td><td>' + grade(s.grade) + ' ' + esc(s.score) + '</td><td>' + SEVS.filter((v) => s.counts[v]).map((v) => '<span class="chip"><span class="dot d-' + v + '"></span>' + s.counts[v] + ' ' + v + '</span>').join(' ') +
      '</td><td class="muted">' + esc((s.durationMs / 1000).toFixed(1)) + 's</td></tr>').join('') + '</tbody></table></div>';
}

function diffBlock(d) {
  if (!d || d.firstScan) return '';
  const names = { deps: 'dependency check', headers: 'live-site check', secrets: 'secrets', config: 'config', code: 'code', laravel: 'Laravel' };
  const caveat = d.notCompared?.length
    ? '<p class="banner">Not compared: ' + esc(d.notCompared.map((s) => names[s] || s).join(', ')) + ' (it did not run in both scans, so its findings are neither new nor fixed).</p>'
    : '';
  if (!d.added.length && !d.fixed.length) return '<p class="banner">No changes since the previous scan.</p>' + caveat;
  const li = (f) => '<li><span class="sev s-' + esc(f.severity) + '">' + esc(f.severity) + '</span> ' + esc(f.title) + ' <span class="mono muted">' + esc(f.location) + '</span></li>';
  return '<div class="diff"><div class="card"><div class="k">New since previous scan</div><div class="v">' + d.added.length + '</div>' +
    (d.added.length ? '<ul>' + d.added.slice(0, 8).map(li).join('') + '</ul>' : '') + '</div>' +
    '<div class="card"><div class="k">Fixed since previous scan</div><div class="v okc">' + d.fixed.length + '</div>' +
    (d.fixed.length ? '<ul>' + d.fixed.slice(0, 8).map(li).join('') + '</ul>' : '') + '</div></div>' + caveat;
}

function renderMain() {
  const p = state.projects.find((x) => x.id === state.current);
  if (!p) {
    $('main').innerHTML = '<div class="empty"><h2>Scan your own projects</h2><p>Add a project folder on the left, then run a scan. Every scan is kept, so you can see what got better and what got worse.</p></div>';
    return;
  }
  const v = state.view, r = v?.report;
  $('main').innerHTML =
    '<div class="top"><div><h2>' + esc(p.name) + '</h2><div class="mono muted">' + esc(p.path) + '</div>' +
      '<div class="actions small mt6"><input type="text" id="purl" class="w320" aria-label="Deployed URL" placeholder="https://your-site.com (optional, a site you own)" value="' + esc(p.url || '') + '">' +
      '<button id="saveurl">Save URL</button></div></div>' +
    '<div class="actions"><label class="small"><input type="checkbox" id="offline"' + (state.offline ? ' checked' : '') + '> Skip dependency lookup</label>' +
      '<button class="primary" id="scan"' + (state.busy ? ' disabled' : '') + '>' + (state.busy ? 'Scanning…' : 'Scan now') + '</button>' +
      '<button class="link danger" id="remove" title="Remove project and its history">Remove</button></div></div>' +
    '<div class="err" id="err"></div>' +
    (r ? '<div class="cards"><div class="card"><div class="k">Score</div><div class="v">' + grade(r.summary.grade) + ' ' + esc(r.summary.score) + '<span class="muted small">/100</span></div></div>' +
      '<div class="card"><div class="k">Findings</div><div class="v">' + esc(r.summary.total) + '</div><div class="chips">' +
        SEVS.filter((s) => r.summary.counts[s]).map((s) => '<span class="chip"><span class="dot d-' + s + '"></span>' + r.summary.counts[s] + ' ' + s + '</span>').join('') + '</div></div>' +
      '<div class="card"><div class="k">Endpoints</div><div class="v">' + esc(r.surface?.endpoints.length ?? 0) + '</div><div class="muted small">' + esc(r.meta.filesScanned) + ' files scanned</div></div>' +
      '<div class="card"><div class="k">Scanned</div><div class="v v15">' + esc(when(r.meta.startedAt)) + '</div><div class="muted small">' + (r.meta.url ? 'incl. ' + esc(r.meta.url) : 'code only') + '</div></div></div>' +
      '<div class="chart">' + chart(state.scans) + '</div>' + '<div class="mt12">' + diffBlock(v.diff) + '</div>' +
      '<div class="tabs" role="tablist">' + [['findings', 'Findings'], ['surface', 'Attack surface'], ['history', 'History']].map(([k, l]) =>
        '<button role="tab" data-tab="' + k + '" aria-selected="' + (state.tab === k) + '">' + l + '</button>').join('') + '</div>' +
      '<div id="tab">' + (state.tab === 'findings' ? tabFindings(r) : state.tab === 'surface' ? tabSurface(r) : tabHistory()) + '</div>'
    : '<div class="empty"><h2>Not scanned yet</h2><p>Run the first scan to see findings and the attack surface.</p></div>');
}

const render = () => { renderList(); renderMain(); };
const showError = (e) => { const el = $('#err') || $('#adderr'); if (el) el.textContent = e.message; };

async function loadProjects() { state.projects = (await api('GET', '/api/projects')).projects; }

async function select(id, scanId) {
  state.current = id; state.view = null; state.scans = [];
  if (id) {
    state.scans = (await api('GET', '/api/projects/' + id + '/scans')).scans;
    const target = scanId || state.scans.at(-1)?.scanId;
    if (target) state.view = await api('GET', '/api/projects/' + id + '/scans/' + target);
  }
  try { localStorage.setItem('tameng.project', id || ''); } catch {}
  render();
}

document.addEventListener('click', async (ev) => {
  const t = ev.target.closest('button, tr[data-scan]');
  if (!t) return;
  try {
    if (t.dataset.id) await select(t.dataset.id);
    else if (t.dataset.tab) { state.tab = t.dataset.tab; renderMain(); }
    else if (t.dataset.scan) await select(state.current, t.dataset.scan);
    else if (t.id === 'scan') {
      state.busy = true; renderMain();
      try {
        const v = await api('POST', '/api/projects/' + state.current + '/scan', { offline: state.offline });
        await loadProjects();
        state.scans = (await api('GET', '/api/projects/' + state.current + '/scans')).scans;
        state.view = v;
      } finally { state.busy = false; }
      render();
    } else if (t.id === 'saveurl') {
      await api('PATCH', '/api/projects/' + state.current, { url: $('#purl').value.trim() || null });
      await loadProjects(); render();
    } else if (t.id === 'remove') {
      const p = state.projects.find((x) => x.id === state.current);
      if (!confirm('Remove "' + p.name + '" and all of its scan history? The project folder itself is not touched.')) return;
      await api('DELETE', '/api/projects/' + state.current);
      await loadProjects(); await select(null);
    }
  } catch (e) { showError(e); }
});

document.addEventListener('input', (ev) => {
  if (ev.target.id === 'q') { state.q = ev.target.value; const pos = ev.target.selectionStart; renderMain(); const q = $('#q'); q.focus(); q.setSelectionRange(pos, pos); }
});
document.addEventListener('change', (ev) => {
  if (ev.target.id === 'sev') { state.sev = ev.target.value; renderMain(); }
  if (ev.target.id === 'offline') state.offline = ev.target.checked; // kept in state: re-renders rebuild the checkbox
});

$('#add').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  $('#adderr').textContent = '';
  try {
    const { project } = await api('POST', '/api/projects', { path: $('#apath').value.trim(), url: $('#aurl').value.trim() || null });
    ev.target.reset();
    await loadProjects(); await select(project.id);
  } catch (e) { $('#adderr').textContent = e.message; }
});

(async () => {
  try {
    await loadProjects();
    let saved = ''; try { saved = localStorage.getItem('tameng.project') || ''; } catch {}
    await select(state.projects.some((p) => p.id === saved) ? saved : state.projects[0]?.id ?? null);
  } catch (e) { document.body.insertAdjacentHTML('afterbegin', '<p class="err pad12">' + esc(e.message) + '</p>'); }
})();
`;

export function renderPage({ token, nonce }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="tameng-token" content="${token}">
<title>tameng dashboard</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z' fill='%232f6fde'/%3E%3C/svg%3E">
<style nonce="${nonce}">${STYLE}</style>
</head>
<body>
<header><h1>tameng</h1><span class="tag">security self-scan · only scan systems you own</span></header>
<div class="layout">
  <aside>
    <div class="plist" id="plist"></div>
    <form class="add" id="add">
      <strong class="small">Add project</strong>
      <input type="text" id="apath" placeholder="C:\\code\\my-app or ~/code/my-app" required aria-label="Project folder">
      <input type="text" id="aurl" placeholder="https://my-app.com (optional)" aria-label="Deployed URL">
      <button class="primary" type="submit">Add</button>
      <div class="err" id="adderr"></div>
    </form>
  </aside>
  <main></main>
</div>
<script nonce="${nonce}">${SCRIPT}</script>
</body>
</html>`;
}
