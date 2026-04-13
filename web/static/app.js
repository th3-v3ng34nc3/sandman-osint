/**
 * sandman osint — Frontend
 * States: IDLE → SEARCHING → STREAMING → DONE | ERROR
 */
'use strict';

// ─── Constants ────────────────────────────────────────────────────────────────
const HISTORY_KEY = 'sandman_history';
const STARRED_KEY = 'sandman_starred';
const THEME_KEY   = 'sandman_theme';
const MAX_HISTORY = 20;

// ─── State ────────────────────────────────────────────────────────────────────
const state = {
  status:       'IDLE',
  queryID:      null,
  findings:     [],
  sources:      {},
  eventSource:  null,
  aiAnalysis:   null,
  totalSources: 0,
  doneSources:  0,
  activeFilter: 'all',   // stat pill
  starFilter:   false,
};

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const dom = {
  form:           $('searchForm'),
  input:          $('searchInput'),
  typeSelect:     $('typeSelect'),
  torToggle:      $('torToggle'),
  searchBtn:      $('searchBtn'),
  btnLabel:       $('btnLabel'),
  btnSpinner:     $('btnSpinner'),
  headerStatus:   $('headerStatus'),

  themeToggle:    $('themeToggle'),

  heroSection:    $('heroSection'),
  statsBar:       $('statsBar'),
  widgetStrip:    $('widgetStrip'),
  resultsGrid:    $('resultsGrid'),

  nCritical: $('nCritical'), sCritical: $('sCritical'),
  nHigh:     $('nHigh'),     sHigh:     $('sHigh'),
  nMedium:   $('nMedium'),   sMedium:   $('sMedium'),
  nLow:      $('nLow'),      sLow:      $('sLow'),
  sAll:      $('sAll'),
  progressInfo: $('progressInfo'),

  // widgets
  wgTotal:   $('wgTotal'),
  wgThreat:  $('wgThreat'),
  wgSources: $('wgSources'),
  wgTimer:   $('wgTimer'),

  sourcesList:   $('sourcesList'),
  recentBlock:   $('recentBlock'),
  recentList:    $('recentList'),

  findingsList:  $('findingsList'),
  findingsCount: $('findingsCount'),
  findingSearch: $('findingSearch'),
  sourceFilter:  $('sourceFilter'),
  severityFilter:$('severityFilter'),
  typeFilter:    $('typeFilter'),
  sourceGroupFilter: $('sourceGroupFilter'),
  starFilterBtn: $('starFilterBtn'),
  exportBtn:     $('exportBtn'),
  emptyState:    $('emptyState'),
  emptyMsg:      $('emptyMsg'),

  aiPanel:         $('aiPanel'),
  aiToggle:        $('aiToggle'),
  aiChevron:       $('aiChevron'),
  aiBody:          $('aiBody'),
  aiProviderBadge: $('aiProviderBadge'),
  aiRiskLabel:     $('aiRiskLabel'),
  aiSummary:       $('aiSummary'),
  riskFill:        $('riskFill'),
  riskScore:       $('riskScore'),
  keyFindingsList: $('keyFindingsList'),
  connectionsList: $('connectionsList'),

  errorBanner:  $('errorBanner'),
  errorMsg:     $('errorMsg'),
  dismissError: $('dismissError'),

  historyBtn:      $('historyBtn'),
  historyDropdown: $('historyDropdown'),
  historyList:     $('historyList'),
  historyEmpty:    $('historyEmpty'),
  clearHistoryBtn: $('clearHistoryBtn'),
};

// ─── Theme ────────────────────────────────────────────────────────────────────
function initTheme() {
  const saved = localStorage.getItem(THEME_KEY) || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeIcon(saved);
}

function updateThemeIcon(theme) {
  if (dom.themeToggle) dom.themeToggle.textContent = theme === 'dark' ? '☀' : '◑';
}

dom.themeToggle?.addEventListener('click', () => {
  const cur  = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem(THEME_KEY, next);
  updateThemeIcon(next);
});

initTheme();

// ─── Scan timer ───────────────────────────────────────────────────────────────
let _timerInterval = null;
let _searchStart   = null;

function startTimer() {
  _searchStart = Date.now();
  _timerInterval = setInterval(() => {
    const s = Math.floor((Date.now() - _searchStart) / 1000);
    const label = s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
    if (dom.wgTimer) dom.wgTimer.textContent = label;
  }, 1000);
}

function stopTimer() {
  if (_timerInterval) { clearInterval(_timerInterval); _timerInterval = null; }
}

// ─── Widget updates ───────────────────────────────────────────────────────────
function updateWidgets() {
  const total  = state.findings.length;
  const threat = state.findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
  if (dom.wgTotal)   dom.wgTotal.textContent   = total;
  if (dom.wgThreat)  dom.wgThreat.textContent  = threat;
  const src = state.totalSources > 0
    ? `${state.doneSources}/${state.totalSources}`
    : state.doneSources;
  if (dom.wgSources) dom.wgSources.textContent = src;
}

// ─── History ──────────────────────────────────────────────────────────────────
function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
  catch { return []; }
}

function saveHistory(h) {
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(h)); } catch {}
}

function pushHistory(raw, type) {
  const h = loadHistory().filter(e => !(e.raw === raw && e.type === type));
  h.unshift({ raw, type, ts: Date.now() });
  saveHistory(h.slice(0, MAX_HISTORY));
  renderHistory();
  renderRecentSidebar();
}

function renderHistory() {
  const h = loadHistory();
  if (h.length === 0) {
    dom.historyList.innerHTML = '';
    dom.historyEmpty.classList.remove('hidden');
    return;
  }
  dom.historyEmpty.classList.add('hidden');
  dom.historyList.innerHTML = h.map(e => `
    <div class="hd-item" data-raw="${escAttr(e.raw)}" data-type="${escAttr(e.type)}">
      <span class="hd-query">${escHtml(e.raw)}</span>
      <span class="hd-type">${escHtml(e.type)}</span>
      <span class="hd-time">${timeAgo(e.ts)}</span>
    </div>`).join('');

  dom.historyList.querySelectorAll('.hd-item').forEach(item => {
    item.addEventListener('click', () => {
      dom.input.value = item.dataset.raw;
      dom.typeSelect.value = item.dataset.type;
      closeHistory();
      dom.form.requestSubmit();
    });
  });
}

function renderRecentSidebar() {
  const h = loadHistory().slice(0, 5);
  if (h.length === 0) { dom.recentBlock.style.display = 'none'; return; }
  dom.recentBlock.style.display = '';
  dom.recentList.innerHTML = h.map(e => `
    <div class="recent-item" data-raw="${escAttr(e.raw)}" data-type="${escAttr(e.type)}">
      <span class="ri-query">${escHtml(e.raw)}</span>
      <span class="ri-type">${escHtml(e.type)}</span>
    </div>`).join('');

  dom.recentList.querySelectorAll('.recent-item').forEach(item => {
    item.addEventListener('click', () => {
      dom.input.value = item.dataset.raw;
      dom.typeSelect.value = item.dataset.type;
      dom.form.requestSubmit();
    });
  });
}

function closeHistory() { dom.historyDropdown.classList.add('hidden'); }

dom.historyBtn.addEventListener('click', e => {
  e.stopPropagation();
  renderHistory();
  dom.historyDropdown.classList.toggle('hidden');
});
dom.clearHistoryBtn.addEventListener('click', e => {
  e.stopPropagation();
  saveHistory([]);
  renderHistory();
  renderRecentSidebar();
});
document.addEventListener('click', e => {
  if (!dom.historyDropdown.contains(e.target) && e.target !== dom.historyBtn) closeHistory();
});

// ─── Starred findings ─────────────────────────────────────────────────────────
function loadStarred() {
  try { return new Set(JSON.parse(localStorage.getItem(STARRED_KEY)) || []); }
  catch { return new Set(); }
}

function toggleStar(id) {
  const s = loadStarred();
  if (s.has(id)) s.delete(id); else s.add(id);
  try { localStorage.setItem(STARRED_KEY, JSON.stringify([...s])); } catch {}
  return s.has(id);
}

function isStarred(id) { return loadStarred().has(id); }

// Star filter toggle
dom.starFilterBtn?.addEventListener('click', () => {
  state.starFilter = !state.starFilter;
  dom.starFilterBtn.classList.toggle('active', state.starFilter);
  dom.starFilterBtn.textContent = state.starFilter ? '★' : '☆';
  dom.starFilterBtn.title = state.starFilter ? 'Show all' : 'Show starred only';
  reRenderFindings();
});

// ─── State transitions ────────────────────────────────────────────────────────
function transitionTo(newStatus) {
  state.status = newStatus;

  switch (newStatus) {
    case 'IDLE':
      setHeaderStatus('');
      dom.searchBtn.disabled  = false;
      dom.btnLabel.textContent = 'SEARCH';
      dom.btnSpinner.classList.add('hidden');
      dom.exportBtn.disabled  = true;
      stopTimer();
      break;

    case 'SEARCHING':
      setHeaderStatus('⟳ Initialising…');
      dom.searchBtn.disabled  = true;
      dom.btnLabel.textContent = 'SEARCHING';
      dom.btnSpinner.classList.remove('hidden');
      dom.exportBtn.disabled  = true;
      dom.errorBanner.classList.add('hidden');

      dom.heroSection.classList.add('hidden');
      dom.statsBar.classList.remove('hidden');
      dom.widgetStrip.classList.remove('hidden');
      dom.resultsGrid.classList.remove('hidden');

      dom.findingsList.innerHTML  = '';
      dom.sourcesList.innerHTML   = '';
      dom.aiPanel.classList.add('hidden');
      dom.aiBody.classList.add('hidden');
      dom.findingsCount.textContent = '0';
      dom.emptyState.classList.remove('hidden');
      dom.emptyMsg.textContent = 'Searching…';

      resetPills();
      updatePillCounts();
      dom.progressInfo.textContent = '0 / 0 sources';
      dom.sourceFilter.innerHTML = '<option value="all">All Sources</option>';

      if (dom.wgTotal)   dom.wgTotal.textContent   = '0';
      if (dom.wgThreat)  dom.wgThreat.textContent  = '0';
      if (dom.wgSources) dom.wgSources.textContent = '0/0';
      if (dom.wgTimer)   dom.wgTimer.textContent   = '0s';

      state.findings     = [];
      state.sources      = {};
      state.aiAnalysis   = null;
      state.activeFilter = 'all';
      state.totalSources = 0;
      state.doneSources  = 0;
      state.starFilter   = false;
      if (dom.starFilterBtn)      { dom.starFilterBtn.classList.remove('active'); dom.starFilterBtn.textContent = '☆'; }
      if (dom.sourceGroupFilter)  dom.sourceGroupFilter.value = 'all';

      startTimer();
      break;

    case 'STREAMING':
      setHeaderStatus('◈ Scanning…');
      dom.emptyState.classList.add('hidden');
      break;

    case 'DONE': {
      stopTimer();
      const n = state.findings.length;
      setHeaderStatus(`✓ Complete — ${n} finding${n !== 1 ? 's' : ''}`);
      dom.searchBtn.disabled  = false;
      dom.btnLabel.textContent = 'SEARCH';
      dom.btnSpinner.classList.add('hidden');
      dom.exportBtn.disabled  = false;
      if (n === 0) {
        dom.emptyState.classList.remove('hidden');
        dom.emptyMsg.textContent = 'No findings for this target.';
      }
      break;
    }

    case 'ERROR':
      stopTimer();
      setHeaderStatus('⚠ Error');
      dom.searchBtn.disabled  = false;
      dom.btnLabel.textContent = 'SEARCH';
      dom.btnSpinner.classList.add('hidden');
      break;
  }
}

// ─── Search submission ────────────────────────────────────────────────────────
dom.form.addEventListener('submit', async e => {
  e.preventDefault();
  const raw = dom.input.value.trim();
  if (!raw) return;

  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }

  transitionTo('SEARCHING');
  pushHistory(raw, dom.typeSelect.value);

  try {
    const resp = await fetch('/api/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw, type: dom.typeSelect.value, use_tor: dom.torToggle.checked }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(err.error || `HTTP ${resp.status}`);
    }
    const { query_id } = await resp.json();
    state.queryID = query_id;
    window.location.hash = query_id;
    openStream(query_id);
  } catch (err) {
    showError(err.message);
    transitionTo('ERROR');
  }
});

// ─── SSE stream ───────────────────────────────────────────────────────────────
function openStream(queryID) {
  const es = new EventSource(`/api/stream?id=${queryID}`);
  state.eventSource = es;

  es.addEventListener('search_meta', e => {
    const d = JSON.parse(e.data);
    state.totalSources = d.total_sources || 0;
    updateProgress();
    updateWidgets();
  });

  es.addEventListener('source_update', e => {
    const sm = JSON.parse(e.data);
    // Count terminal states once
    const terminal = ['done', 'error', 'timeout', 'skipped'];
    const wasTerminal = state.sources[sm.name] && terminal.includes(state.sources[sm.name].status);
    state.sources[sm.name] = sm;
    if (terminal.includes(sm.status) && !wasTerminal) {
      state.doneSources++;
      updateProgress();
      updateWidgets();
    }
    renderSourceRow(sm);
  });

  es.addEventListener('finding', e => {
    if (state.status === 'SEARCHING') transitionTo('STREAMING');
    const f = JSON.parse(e.data);
    state.findings.push(f);
    dom.findingsCount.textContent = state.findings.length;
    updatePillCounts();
    updateWidgets();
    addSourceFilterOption(f.source);
    if (passesFilters(f)) dom.findingsList.prepend(buildFindingCard(f));
  });

  es.addEventListener('ai_analysis', e => {
    state.aiAnalysis = JSON.parse(e.data);
    renderAIAnalysis(state.aiAnalysis);
  });

  es.addEventListener('done', () => {
    es.close(); state.eventSource = null;
    transitionTo('DONE');
  });

  es.addEventListener('error', e => {
    try {
      const d = JSON.parse(e.data);
      showError(d.message || 'Stream error');
    } catch {
      if (state.status !== 'DONE') {
        showError('Connection lost. Results so far are preserved.');
        transitionTo('ERROR');
      }
    }
    es.close(); state.eventSource = null;
  });

  es.onerror = () => {
    if (state.status !== 'DONE' && state.status !== 'ERROR') {
      showError('Stream connection failed.');
      transitionTo('ERROR');
      es.close();
    }
  };
}

// ─── Progress ─────────────────────────────────────────────────────────────────
function updateProgress() {
  const total = state.totalSources || 0;
  const done  = Math.min(state.doneSources, total);
  dom.progressInfo.textContent = total > 0 ? `${done} / ${total} sources` : `${done} sources`;
}

// ─── Source rows ──────────────────────────────────────────────────────────────
function renderSourceRow(sm) {
  let row = dom.sourcesList.querySelector(`.src-row[data-name="${CSS.escape(sm.name)}"]`);
  if (!row) {
    row = document.createElement('div');
    row.className = 'src-row pending';
    row.dataset.name = sm.name;
    row.innerHTML = `
      <span class="src-dot"></span>
      <span class="src-name">${escHtml(sm.name)}</span>
      <span class="src-count"></span>
      <span class="src-dur"></span>`;
    dom.sourcesList.appendChild(row);
  }
  row.className = `src-row ${sm.status || 'pending'}`;
  row.querySelector('.src-count').textContent = sm.count > 0 ? sm.count : '';
  const durEl = row.querySelector('.src-dur');
  if (sm.duration_ms > 0) {
    durEl.textContent = sm.duration_ms < 1000 ? `${sm.duration_ms}ms` : `${(sm.duration_ms / 1000).toFixed(1)}s`;
  }
  if (sm.error) row.title = sm.error;
}

// ─── Finding cards ────────────────────────────────────────────────────────────
function buildFindingCard(f) {
  const card = document.createElement('div');
  card.className = 'finding-card';
  card.dataset.sev    = f.severity || 'info';
  card.dataset.type   = f.type     || '';
  card.dataset.source = f.source   || '';
  card.dataset.region = (f.raw && f.raw.region) || 'global';
  card.dataset.id     = f.id;

  const sev     = (f.severity || 'info').toUpperCase();
  const starred = isStarred(f.id);
  const rawJson = f.raw ? JSON.stringify(f.raw, null, 2) : null;
  const tsMs    = f.found_at ? new Date(f.found_at).getTime() : Date.now();

  card.innerHTML = `
    <div class="card-header">
      <div class="card-left">
        <span class="card-title">${escHtml(f.title)}</span>
        <span class="card-time">${timeAgo(tsMs)}</span>
      </div>
      <div class="card-badges">
        <span class="badge b-src">${escHtml(f.source)}</span>
        <span class="badge b-type">${escHtml(f.type || '')}</span>
        <span class="badge b-sev b-sev-${f.severity || 'info'}">${sev}</span>
      </div>
    </div>
    ${f.summary ? `<p class="card-summary">${escHtml(f.summary)}</p>` : ''}
    ${f.url     ? `<a class="card-url" href="${escAttr(f.url)}" target="_blank" rel="noopener noreferrer">${escHtml(truncate(f.url, 88))}</a>` : ''}
    <div class="card-actions">
      ${f.url ? `<button class="ca-btn copy-btn" data-url="${escAttr(f.url)}">⎘ Copy</button>` : ''}
      <button class="ca-btn star-btn ${starred ? 'starred' : ''}" data-id="${escAttr(f.id)}">${starred ? '★' : '☆'}</button>
      ${rawJson ? `<button class="ca-btn raw-btn">{ } Raw</button>` : ''}
    </div>
    ${rawJson ? `<pre class="card-raw hidden">${escHtml(rawJson)}</pre>` : ''}`;

  // Copy
  card.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      navigator.clipboard.writeText(btn.dataset.url).then(() => {
        btn.textContent = '✓ Copied';
        setTimeout(() => { btn.textContent = '⎘ Copy'; }, 1500);
      }).catch(() => {
        btn.textContent = '✗ Failed';
        setTimeout(() => { btn.textContent = '⎘ Copy'; }, 1500);
      });
    });
  });

  // Star
  card.querySelectorAll('.star-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const now = toggleStar(f.id);
      btn.textContent = now ? '★' : '☆';
      btn.classList.toggle('starred', now);
    });
  });

  // Raw toggle
  card.querySelectorAll('.raw-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const pre = card.querySelector('.card-raw');
      if (!pre) return;
      pre.classList.toggle('hidden');
      btn.textContent = pre.classList.contains('hidden') ? '{ } Raw' : '{ } Hide';
    });
  });

  return card;
}

// ─── Source filter option ─────────────────────────────────────────────────────
function addSourceFilterOption(source) {
  if (!source) return;
  if (!dom.sourceFilter.querySelector(`option[value="${CSS.escape(source)}"]`)) {
    const opt = document.createElement('option');
    opt.value = source; opt.textContent = source;
    dom.sourceFilter.appendChild(opt);
  }
}

// ─── Source groups ────────────────────────────────────────────────────────────
const SOURCE_GROUPS = {
  breach:  ['hibp', 'emailrep', 'hunter'],
  social:  ['username', 'india'],
  search:  ['duckduckgo', 'googledork'],
  infra:   ['shodan', 'crtsh', 'wayback', 'github'],
  india:   ['india'],
  darkweb: ['tor'],
};

// Returns true if a finding belongs to the selected source group.
function inGroup(f, group) {
  if (group === 'all') return true;
  const groupSources = SOURCE_GROUPS[group] || [];
  // Direct source name match
  if (groupSources.includes(f.source)) return true;
  // For india group: also match findings where raw.region === 'india'
  if (group === 'india' && f.raw && f.raw.region === 'india') return true;
  return false;
}

// ─── Filters ──────────────────────────────────────────────────────────────────
function passesFilters(f) {
  const sev    = dom.severityFilter.value;
  const type   = dom.typeFilter.value;
  const source = dom.sourceFilter.value;
  const group  = dom.sourceGroupFilter?.value || 'all';
  const text   = dom.findingSearch.value.trim().toLowerCase();
  const pill   = state.activeFilter;

  if (pill   !== 'all' && f.severity !== pill)   return false;
  if (sev    !== 'all' && f.severity !== sev)     return false;
  if (type   !== 'all' && f.type     !== type)    return false;
  if (source !== 'all' && f.source   !== source)  return false;
  if (!inGroup(f, group))                          return false;
  if (state.starFilter && !isStarred(f.id))        return false;
  if (text) {
    const hay = `${f.title} ${f.summary} ${f.url} ${f.source}`.toLowerCase();
    if (!hay.includes(text)) return false;
  }
  return true;
}

function reRenderFindings() {
  dom.findingsList.innerHTML = '';
  let shown = 0;
  for (let i = state.findings.length - 1; i >= 0; i--) {
    if (passesFilters(state.findings[i])) {
      dom.findingsList.appendChild(buildFindingCard(state.findings[i]));
      shown++;
    }
  }
  dom.findingsCount.textContent = shown;
  if (shown === 0 && state.status === 'DONE') {
    dom.emptyState.classList.remove('hidden');
    dom.emptyMsg.textContent = 'No findings match the current filters.';
  } else {
    dom.emptyState.classList.add('hidden');
  }
}

[dom.severityFilter, dom.typeFilter, dom.sourceFilter].forEach(el => {
  el?.addEventListener('change', reRenderFindings);
});
// Source group filter — re-render + sync accent color via attribute
dom.sourceGroupFilter?.addEventListener('change', () => {
  dom.sourceGroupFilter.setAttribute('value', dom.sourceGroupFilter.value);
  reRenderFindings();
});
dom.findingSearch.addEventListener('input', reRenderFindings);

// ─── Stat pills ───────────────────────────────────────────────────────────────
function updatePillCounts() {
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  state.findings.forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; });
  dom.nCritical.textContent = c.critical;
  dom.nHigh.textContent     = c.high;
  dom.nMedium.textContent   = c.medium;
  dom.nLow.textContent      = c.low;
}

function resetPills() {
  [dom.sCritical, dom.sHigh, dom.sMedium, dom.sLow].forEach(p => p.classList.remove('active'));
  dom.sAll.classList.add('active');
  state.activeFilter = 'all';
}

(function setupPillListeners() {
  const pills = [
    { el: dom.sCritical, val: 'critical' },
    { el: dom.sHigh,     val: 'high'     },
    { el: dom.sMedium,   val: 'medium'   },
    { el: dom.sLow,      val: 'low'      },
    { el: dom.sAll,      val: 'all'      },
  ];
  pills.forEach(({ el, val }) => {
    el.addEventListener('click', () => {
      pills.forEach(p => p.el.classList.remove('active'));
      el.classList.add('active');
      state.activeFilter = val;
      reRenderFindings();
    });
  });
})();

// ─── AI Analysis ──────────────────────────────────────────────────────────────
function renderAIAnalysis(ai) {
  dom.aiPanel.classList.remove('hidden');

  const score = ai.risk_score || 0;
  dom.riskScore.textContent = `${score}/100`;
  dom.riskFill.style.width  = `${score}%`;
  dom.riskFill.style.background =
    score >= 75 ? 'var(--sc)' :
    score >= 50 ? 'var(--sh)' :
    score >= 25 ? 'var(--sm)' : 'var(--sl)';

  const riskLabel = score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low';
  dom.aiRiskLabel.textContent = `Risk: ${riskLabel.toUpperCase()}`;
  dom.aiRiskLabel.className   = `ai-risk-label risk-${riskLabel}`;

  if (ai.provider) {
    dom.aiProviderBadge.textContent = ai.provider;
    dom.aiProviderBadge.style.display = '';
  }

  dom.aiSummary.textContent = ai.summary || '';
  dom.keyFindingsList.innerHTML = (ai.key_findings || []).map(kf => `<li>${escHtml(kf)}</li>`).join('');
  dom.connectionsList.innerHTML = (ai.connections  || []).map(c  => `<li>${escHtml(c)}</li>`).join('');

  dom.aiBody.classList.remove('hidden');
  dom.aiChevron.textContent = '▲';
}

dom.aiToggle.addEventListener('click', () => {
  const hidden = dom.aiBody.classList.toggle('hidden');
  dom.aiChevron.textContent = hidden ? '▼' : '▲';
});

// ─── Export ───────────────────────────────────────────────────────────────────
dom.exportBtn.addEventListener('click', () => {
  if (state.queryID) window.location.href = `/api/export?id=${state.queryID}`;
});

// ─── Error banner ─────────────────────────────────────────────────────────────
dom.dismissError.addEventListener('click', () => { dom.errorBanner.classList.add('hidden'); });

function showError(msg) {
  dom.errorMsg.textContent = msg;
  dom.errorBanner.classList.remove('hidden');
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function escHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function escAttr(s) {
  if (s == null) return '';
  return String(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function truncate(s, max) {
  s = String(s || '');
  return s.length <= max ? s : s.slice(0, max) + '…';
}
function setHeaderStatus(msg) { dom.headerStatus.textContent = msg; }

function timeAgo(tsOrMs) {
  if (!tsOrMs) return '';
  const ms   = typeof tsOrMs === 'number' ? tsOrMs : new Date(tsOrMs).getTime();
  const diff = Math.floor((Date.now() - ms) / 1000);
  if (diff <  5)    return 'just now';
  if (diff <  60)   return `${diff}s ago`;
  if (diff <  3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff <  86400)return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

// ─── Page-load recovery ───────────────────────────────────────────────────────
(async function recoverFromHash() {
  renderHistory();
  renderRecentSidebar();

  const hash = window.location.hash.slice(1);
  if (!hash || hash.length < 8) return;

  try {
    const resp = await fetch(`/api/status?id=${hash}`);
    if (!resp.ok) return;
    const data = await resp.json();
    if (data.status !== 'done' && data.status !== 'error') return;

    state.queryID = hash;
    transitionTo('SEARCHING');
    openStream(hash);
  } catch { /* ignore */ }
})();
