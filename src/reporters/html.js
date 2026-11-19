import { SEVERITIES } from '../findings.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);

const linkify = (s) => esc(s).replace(/https:\/\/osv\.dev\/vulnerability\/[\w.-]+/g, (u) => `<a href="${u}" target="_blank" rel="noopener">${u.replace('https://', '')}</a>`);

export function renderHtml({ meta, summary, findings }) {
  const ringColor = { A: 'var(--ok)', B: 'var(--ok)', C: 'var(--medium)', D: 'var(--high)', F: 'var(--critical)' }[summary.grade];
  const circumference = 2 * Math.PI * 52;
  const dash = (summary.score / 100) * circumference;
  const target = [meta.path, meta.url].filter(Boolean).join(' · ');
  const date = new Date(meta.startedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });

  const chips = SEVERITIES.map((s) => `
      <button class="chip" data-sev="${s}" aria-pressed="true"><span class="dot ${s}"></span>${summary.counts[s]} ${s}</button>`).join('');

  const cards = findings.map((f) => `
    <article class="card" data-sev="${f.severity}" data-text="${esc(`${f.title} ${f.location} ${f.detail} ${f.scanner}`.toLowerCase())}">
      <div class="stripe ${f.severity}"></div>
      <div class="body">
        <header>
          <span class="badge ${f.severity}">${f.severity}</span>
          <h3>${esc(f.title)}</h3>
          <span class="scanner">${esc(f.scanner)}</span>
        </header>
        ${f.location ? `<code class="loc">${esc(f.location)}</code>` : ''}
        ${f.detail ? `<p class="detail">${linkify(f.detail)}</p>` : ''}
        ${f.fix ? `<p class="fix"><b>Fix</b> ${esc(f.fix)}</p>` : ''}
      </div>
    </article>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tameng report · ${summary.grade} ${summary.score}/100</title>
<style>
  :root {
    --bg: #f6f7f9; --panel: #fff; --text: #14171c; --muted: #5d6673; --line: #e3e6eb; --code: #f0f2f5;
    --critical: #c81e3a; --high: #e2541c; --medium: #c98a00; --low: #1f7fbf; --info: #7b8494; --ok: #1c9a5a;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #0e1116; --panel: #161a21; --text: #e8ebf0; --muted: #98a1ae; --line: #262c36; --code: #1d222b;
      --critical: #ff5470; --high: #ff7a45; --medium: #f2b632; --low: #4fb3ff; --info: #8b94a3; --ok: #3ccf87; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  .wrap { max-width: 960px; margin: 0 auto; padding: 40px 20px 80px; }
  .top { display: flex; gap: 28px; align-items: center; background: var(--panel); border: 1px solid var(--line); border-radius: 16px; padding: 24px 28px; }
  .ring { flex: none; position: relative; width: 128px; height: 128px; }
  .ring svg { transform: rotate(-90deg); }
  .ring .num { position: absolute; inset: 0; display: grid; place-content: center; text-align: center; }
  .ring .num b { font-size: 34px; line-height: 1; }
  .ring .num span { color: var(--muted); font-size: 13px; }
  h1 { margin: 0 0 4px; font-size: 22px; letter-spacing: -.01em; }
  .meta { color: var(--muted); font-size: 13.5px; word-break: break-all; }
  .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
  .chip { display: inline-flex; align-items: center; gap: 7px; border: 1px solid var(--line); background: transparent; color: var(--text);
    padding: 5px 12px; border-radius: 999px; font: inherit; font-size: 13px; cursor: pointer; text-transform: capitalize; }
  .chip[aria-pressed="false"] { opacity: .4; }
  .chip:focus-visible, input:focus-visible { outline: 2px solid var(--low); outline-offset: 2px; }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--info); }
  .tools { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin: 28px 0 12px; }
  .tools h2 { margin: 0; font-size: 16px; }
  input[type=search] { width: min(320px, 100%); padding: 8px 12px; border-radius: 10px; border: 1px solid var(--line); background: var(--panel); color: var(--text); font: inherit; }
  .card { display: flex; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; margin-bottom: 10px; }
  .card[hidden] { display: none; }
  .stripe { width: 4px; flex: none; }
  .body { padding: 14px 18px; min-width: 0; flex: 1; }
  .card header { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
  .card h3 { margin: 0; font-size: 15px; font-weight: 600; flex: 1; min-width: 200px; }
  .badge { font-size: 11px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; padding: 2px 8px; border-radius: 6px; color: #fff; }
  .scanner { color: var(--muted); font-size: 12px; }
  .loc { display: inline-block; margin-top: 8px; background: var(--code); padding: 2px 8px; border-radius: 6px; font: 12.5px ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
  .detail { margin: 8px 0 0; color: var(--muted); font-size: 13.5px; word-break: break-word; }
  .detail a { color: var(--low); }
  .fix { margin: 8px 0 0; font-size: 13.5px; }
  .fix b { color: var(--ok); margin-right: 6px; }
  .empty { text-align: center; color: var(--muted); padding: 40px; }
  footer { margin-top: 40px; color: var(--muted); font-size: 12.5px; text-align: center; }
  ${SEVERITIES.map((s) => `.${s}.dot, .stripe.${s}, .badge.${s} { background: var(--${s}); }`).join('\n  ')}
  @media (max-width: 600px) { .top { flex-direction: column; text-align: center; } .chips { justify-content: center; } .tools { flex-direction: column; align-items: stretch; } }
</style>
</head>
<body>
<main class="wrap">
  <section class="top">
    <div class="ring" role="img" aria-label="Score ${summary.score} out of 100, grade ${summary.grade}">
      <svg width="128" height="128" viewBox="0 0 128 128">
        <circle cx="64" cy="64" r="52" fill="none" stroke="var(--line)" stroke-width="12"/>
        ${summary.score > 0 ? `<circle cx="64" cy="64" r="52" fill="none" stroke="${ringColor}" stroke-width="12" stroke-linecap="round"
          stroke-dasharray="${dash.toFixed(1)} ${circumference.toFixed(1)}"/>` : ''}
      </svg>
      <div class="num"><b>${summary.score}</b><span>grade ${summary.grade}</span></div>
    </div>
    <div>
      <h1>Security report</h1>
      <div class="meta">${esc(target)}</div>
      <div class="meta">${esc(date)} · ${meta.filesScanned} files · ${summary.total} findings</div>
      <div class="chips">${chips}
      </div>
    </div>
  </section>

  <div class="tools">
    <h2>Findings</h2>
    <input type="search" id="q" placeholder="Filter by file, title, CVE…" aria-label="Filter findings">
  </div>
  <section id="list">${cards || '<p class="empty">No findings. Nice.</p>'}
  </section>
  <p class="empty" id="none" hidden>No findings match the current filter.</p>
  <footer>Generated by tameng v${esc(meta.version)} · findings are leads to review, not proof of exploitability.</footer>
</main>
<script>
  const active = new Set(${JSON.stringify(SEVERITIES)});
  const cards = [...document.querySelectorAll('.card')];
  const q = document.getElementById('q');
  function apply() {
    const term = q.value.trim().toLowerCase();
    let shown = 0;
    for (const card of cards) {
      const ok = active.has(card.dataset.sev) && (!term || card.dataset.text.includes(term));
      card.hidden = !ok;
      if (ok) shown++;
    }
    document.getElementById('none').hidden = shown > 0 || cards.length === 0;
  }
  document.querySelectorAll('.chip').forEach((chip) => chip.addEventListener('click', () => {
    const sev = chip.dataset.sev;
    active.has(sev) ? active.delete(sev) : active.add(sev);
    chip.setAttribute('aria-pressed', active.has(sev));
    apply();
  }));
  q.addEventListener('input', apply);
</script>
</body>
</html>
`;
}
