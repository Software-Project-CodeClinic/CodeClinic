// ── State ──────────────────────────────────────────────────────
let currentPage    = 0;
const PAGE_SIZE    = 20;
let totalElements  = 0;
let selectedId     = null;
let selectedVerdict = null;
let autoRefreshTimer = null;
let activePreset   = null;  // 1 | 24 | 168 | null

// ── CWE 메타 ────────────────────────────────────────────────────
const CWE_META = {
  'NORMAL': { cls: '',       barColor: 'bg-emerald-500' },
  'CWE-89': { cls: 'cwe-89', barColor: 'bg-violet-500' },
  'CWE-79': { cls: 'cwe-79', barColor: 'bg-pink-500'   },
  'CWE-78': { cls: 'cwe-78', barColor: 'bg-orange-500' },
  'CWE-22': { cls: 'cwe-22', barColor: 'bg-cyan-500'   },
};

// ── Helpers ─────────────────────────────────────────────────────
function cweBadge(cwe) {
  if (!cwe || cwe === 'NORMAL') return '<span class="text-slate-500 text-xs">—</span>';
  const cls = CWE_META[cwe]?.cls ?? '';
  return `<span class="cwe-badge ${cls}">${cwe}</span>`;
}

function verdictBadge(v) {
  if (!v) return '<span class="text-slate-500 text-xs">—</span>';
  const cls = v === 'BLOCK'
    ? 'bg-red-600'
    : v === 'MONITOR' ? 'bg-amber-500' : 'bg-emerald-600';
  return `<span class="inline-block px-2 py-0.5 text-xs font-bold text-white rounded ${cls}">${v}</span>`;
}

function scoreClass(s) {
  return s >= 0.8 ? 'text-red-400' : s >= 0.5 ? 'text-amber-400' : 'text-emerald-400';
}

function fmtTime(iso) {
  if (!iso) return '—';
  const d  = new Date(iso);
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  const HH = String(d.getHours()).padStart(2, '0');
  const MM = String(d.getMinutes()).padStart(2, '0');
  const SS = String(d.getSeconds()).padStart(2, '0');
  return `${mm}-${dd} ${HH}:${MM}:${SS}`;
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function buildQuery() {
  const p = new URLSearchParams({ page: currentPage, size: PAGE_SIZE });
  const cwe     = document.getElementById('filterCwe').value;
  const verdict = document.getElementById('filterVerdict').value;
  const from    = document.getElementById('filterFrom').value;
  const to      = document.getElementById('filterTo').value;
  if (cwe)     p.set('cweLabel', cwe);
  if (verdict) p.set('verdict', verdict);
  if (from)    p.set('from', new Date(from).toISOString());
  if (to)      p.set('to', new Date(to).toISOString());
  return p.toString();
}

// ── 시간 프리셋 ─────────────────────────────────────────────────
function setPreset(hours) {
  activePreset = hours;

  // 프리셋 버튼 하이라이트
  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.classList.remove('ring-2', 'ring-blue-500', 'bg-blue-600', 'text-white', 'border-blue-500');
    btn.classList.add('bg-slate-800', 'text-slate-300', 'border-slate-600');
  });

  const idMap = { 1: 'preset1h', 24: 'preset24h', 168: 'preset7d', null: 'presetAll' };
  const activeBtn = document.getElementById(idMap[hours]);
  if (activeBtn) {
    activeBtn.classList.remove('bg-slate-800', 'text-slate-300', 'border-slate-600');
    activeBtn.classList.add('ring-2', 'ring-blue-500', 'bg-blue-600', 'text-white', 'border-blue-500');
  }

  if (hours == null) {
    document.getElementById('filterFrom').value = '';
    document.getElementById('filterTo').value   = '';
  } else {
    const now  = new Date();
    const from = new Date(now - hours * 3600 * 1000);
    // datetime-local 값 형식: yyyy-MM-ddTHH:mm
    document.getElementById('filterFrom').value = toDatetimeLocal(from);
    document.getElementById('filterTo').value   = toDatetimeLocal(now);
  }

  applyFilter();
}

function clearPreset() {
  activePreset = null;
  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.classList.remove('ring-2', 'ring-blue-500', 'bg-blue-600', 'text-white', 'border-blue-500');
    btn.classList.add('bg-slate-800', 'text-slate-300', 'border-slate-600');
  });
}

function toDatetimeLocal(date) {
  const pad = n => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

// ── Stats & CWE 분포 ────────────────────────────────────────────
async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const s = await res.json();

    document.getElementById('statBlock').textContent   = s.totalBlock   ?? 0;
    document.getElementById('statMonitor').textContent = s.totalMonitor ?? 0;
    document.getElementById('statNormal').textContent  = s.byLabel?.['NORMAL'] ?? 0;
    document.getElementById('statCwe89').textContent   = s.byLabel?.['CWE-89'] ?? 0;
    document.getElementById('statCwe79').textContent   = s.byLabel?.['CWE-79'] ?? 0;
    document.getElementById('statCwe78').textContent   = s.byLabel?.['CWE-78'] ?? 0;
    document.getElementById('statCwe22').textContent   = s.byLabel?.['CWE-22'] ?? 0;

    renderDistribution(s.byLabel ?? {}, s.totalBlock ?? 0, s.totalMonitor ?? 0);
  } catch { /* silently ignore */ }
}

function renderDistribution(byLabel, totalBlock, totalMonitor) {
  const section = document.getElementById('distSection');
  const verdictTotal = totalBlock + totalMonitor;
  const labelOrder   = ['NORMAL', 'CWE-89', 'CWE-79', 'CWE-78', 'CWE-22'];
  const labelTotal   = labelOrder.reduce((sum, k) => sum + (byLabel[k] ?? 0), 0);

  if (verdictTotal === 0 && labelTotal === 0) { section.classList.add('hidden'); return; }
  section.classList.remove('hidden');

  // Verdict 차트
  document.getElementById('verdictChart').innerHTML = [
    { label: 'BLOCK',   count: totalBlock,   color: 'bg-red-500'   },
    { label: 'MONITOR', count: totalMonitor, color: 'bg-amber-500' },
  ].map(({ label, count, color }) => {
    const pct = verdictTotal > 0 ? (count / verdictTotal * 100).toFixed(1) : '0.0';
    return `
      <div class="flex items-center gap-2 text-xs">
        <span class="w-16 text-right text-slate-400 shrink-0 font-mono">${label}</span>
        <div class="flex-1 bg-slate-800 rounded-full h-2 overflow-hidden">
          <div class="h-full ${color} rounded-full transition-all duration-500" style="width:${pct}%"></div>
        </div>
        <span class="w-24 text-slate-400 shrink-0 text-right">${pct}% (${count})</span>
      </div>`;
  }).join('');

  // Label 차트
  document.getElementById('distChart').innerHTML = labelOrder.map(cwe => {
    const count = byLabel[cwe] ?? 0;
    const pct   = labelTotal > 0 ? (count / labelTotal * 100).toFixed(1) : '0.0';
    const bar   = CWE_META[cwe]?.barColor ?? 'bg-slate-500';
    return `
      <div class="flex items-center gap-2 text-xs">
        <span class="w-16 text-right text-slate-400 shrink-0 font-mono">${cwe}</span>
        <div class="flex-1 bg-slate-800 rounded-full h-2 overflow-hidden">
          <div class="h-full ${bar} rounded-full transition-all duration-500" style="width:${pct}%"></div>
        </div>
        <span class="w-24 text-slate-400 shrink-0 text-right">${pct}% (${count})</span>
      </div>`;
  }).join('');
}

// ── 공격 테이블 ─────────────────────────────────────────────────
async function loadAttacks() {
  const tbody = document.getElementById('attackTable');
  tbody.innerHTML = '<tr><td colspan="5" class="px-4 py-10 text-center text-slate-500 text-sm">Loading…</td></tr>';
  try {
    const res  = await fetch('/api/attacks?' + buildQuery());
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    totalElements = data.totalElements ?? 0;
    document.getElementById('totalCount').textContent = `${totalElements} total`;
    syncPagination();

    if (!data.content?.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="px-4 py-10 text-center text-slate-500 text-sm">No attacks found.</td></tr>';
      return;
    }

    tbody.innerHTML = data.content.map(row => `
      <tr class="border-b border-slate-800 hover:bg-slate-800/70 cursor-pointer transition-colors ${selectedId === row.id ? 'row-selected' : ''}"
          onclick="selectAttack('${row.id}', this)" data-id="${row.id}" tabindex="0"
          onkeydown="if(event.key==='Enter')selectAttack('${row.id}',this)"
          role="button" aria-pressed="${selectedId === row.id}">
        <td class="px-4 py-2 text-xs text-slate-400 whitespace-nowrap font-mono">${fmtTime(row.timestamp)}</td>
        <td class="px-4 py-2">${cweBadge(row.cweType)}</td>
        <td class="px-4 py-2">${verdictBadge(row.verdict)}</td>
        <td class="px-4 py-2 text-xs font-mono font-semibold ${scoreClass(row.score)}">${row.score != null ? row.score.toFixed(2) : '—'}</td>
        <td class="px-4 py-2 text-xs text-slate-300 font-mono max-w-xs truncate" title="${esc(row.uri)}">${esc(row.uri) || '—'}</td>
      </tr>
    `).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-8 text-center text-red-400 text-sm">Error: ${esc(e.message)}</td></tr>`;
  }
}

function syncPagination() {
  const total = Math.max(1, Math.ceil(totalElements / PAGE_SIZE));
  document.getElementById('pageInfo').textContent = `Page ${currentPage + 1} / ${total}`;
  document.getElementById('btnPrev').disabled = currentPage === 0;
  document.getElementById('btnNext').disabled = (currentPage + 1) * PAGE_SIZE >= totalElements;
}

function changePage(delta) {
  currentPage = Math.max(0, currentPage + delta);
  loadAttacks();
}

// ── 상세 패널 ───────────────────────────────────────────────────
async function selectAttack(id, rowEl) {
  if (selectedId === id) { closeDetail(); return; }

  document.querySelectorAll('#attackTable tr').forEach(r => {
    r.classList.remove('row-selected');
    r.setAttribute('aria-pressed', 'false');
  });
  rowEl.classList.add('row-selected');
  rowEl.setAttribute('aria-pressed', 'true');
  selectedId = id;

  const panel = document.getElementById('detailPanel');
  panel.classList.remove('hidden');
  document.getElementById('detailMeta').innerHTML  = '<div class="col-span-4 text-slate-500 text-xs">Loading…</div>';
  document.getElementById('detailRaw').textContent = 'Loading…';
  document.getElementById('detailRecs').innerHTML  = '<p class="text-slate-500 text-xs italic">Loading recommendations…</p>';

  try {
    const [dRes, rRes] = await Promise.all([
      fetch(`/api/attacks/${id}`),
      fetch(`/api/recommendations?attackLogId=${id}`)
    ]);
    const detail = await dRes.json();
    const recs   = await rRes.json();
    selectedVerdict = detail.verdict;

    // 메타 카드
    document.getElementById('detailMeta').innerHTML = `
      <div class="bg-slate-800 border border-slate-700/60 rounded-lg px-3 py-2">
        <p class="text-slate-500 text-xs mb-1">⚠️ CWE Type</p>
        ${cweBadge(detail.cweType)}
      </div>
      <div class="bg-slate-800 border border-slate-700/60 rounded-lg px-3 py-2">
        <p class="text-slate-500 text-xs mb-1">⛔ Verdict</p>
        ${verdictBadge(detail.verdict)}
      </div>
      <div class="bg-slate-800 border border-slate-700/60 rounded-lg px-3 py-2">
        <p class="text-slate-500 text-xs mb-1">📊 Score</p>
        <p class="text-sm font-mono font-bold ${scoreClass(detail.classificationScore)}">${detail.classificationScore?.toFixed(4) ?? '—'}</p>
      </div>
      <div class="bg-slate-800 border border-slate-700/60 rounded-lg px-3 py-2">
        <p class="text-slate-500 text-xs mb-1">🌐 Source IP</p>
        <p class="text-sm font-mono text-slate-300">${esc(detail.sourceIp) || '—'}</p>
      </div>
    `;

    // Raw payload
    document.getElementById('detailRaw').textContent = detail.rawPayload || '(empty)';

    // 추천 카드
    document.getElementById('detailRecs').innerHTML = renderRecommendations(recs, detail.verdict);

    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (e) {
    document.getElementById('detailRecs').innerHTML =
      `<p class="text-red-400 text-xs">Failed to load detail: ${esc(e.message)}</p>`;
  }
}

function renderRecommendations(recs, verdict) {
  if (!recs?.length) {
    return '<p class="text-slate-500 text-xs italic">No Semgrep recommendations found. ' +
           'The Feedback Bridge may still be processing, or no matching patterns were detected.</p>';
  }

  const severity      = verdict === 'BLOCK' ? 'HIGH' : 'MEDIUM';
  const severityClass = verdict === 'BLOCK'
    ? 'bg-red-600 text-white'
    : 'bg-amber-500 text-white';

  return recs.map(rec => `
    <div class="bg-slate-800 border border-slate-700/60 rounded-lg p-4">
      <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
        <div class="flex items-center gap-2 flex-wrap">
          ${cweBadge(rec.cweType)}
          <span class="text-xs text-slate-300 font-mono font-medium">${esc(rec.pattern)}</span>
        </div>
        <span class="text-xs font-bold rounded px-2 py-0.5 ${severityClass}">${severity}</span>
      </div>
      ${rec.filePath
        ? `<p class="text-xs font-mono text-blue-400 mb-3">📄 ${esc(rec.filePath)}${rec.lineNumber != null ? ':' + rec.lineNumber : ''}</p>`
        : ''}
      <pre class="suggestion bg-slate-950 border border-slate-700/40 rounded-md p-3 text-slate-200 overflow-x-auto">${esc(rec.suggestion)}</pre>
    </div>
  `).join('');
}

function closeDetail() {
  selectedId      = null;
  selectedVerdict = null;
  document.querySelectorAll('#attackTable tr').forEach(r => {
    r.classList.remove('row-selected');
    r.setAttribute('aria-pressed', 'false');
  });
  document.getElementById('detailPanel').classList.add('hidden');
}

// ── 필터 액션 ───────────────────────────────────────────────────
function applyFilter() {
  currentPage = 0;
  closeDetail();
  loadAttacks();
}

function resetFilter() {
  ['filterCwe', 'filterVerdict'].forEach(id => document.getElementById(id).value = '');
  ['filterFrom', 'filterTo'].forEach(id => document.getElementById(id).value = '');
  clearPreset();
  currentPage = 0;
  closeDetail();
  loadAll();
}

// ── Auto-refresh ────────────────────────────────────────────────
function toggleAutoRefresh() {
  if (document.getElementById('autoRefresh').checked) {
    autoRefreshTimer = setInterval(loadAll, 30000);
  } else {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
}

// ── 전체 로드 ───────────────────────────────────────────────────
async function loadAll() {
  await Promise.all([loadStats(), loadAttacks()]);
  document.getElementById('lastUpdated').textContent =
    new Date().toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

loadAll();
