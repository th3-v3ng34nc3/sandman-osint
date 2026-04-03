/**
 * Sandman OSINT — Frontend State Machine
 *
 * States: IDLE → SEARCHING → STREAMING → DONE
 *                          ↘ ERROR
 * DONE / ERROR → IDLE (new search resets state)
 */

'use strict';

// ─── State ───────────────────────────────────────────────────────────────────
const state = {
  status: 'IDLE',        // IDLE | SEARCHING | STREAMING | DONE | ERROR
  queryID: null,
  findings: [],
  sources: {},
  eventSource: null,
  aiAnalysis: null,
};

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const dom = {
  form:          $('searchForm'),
  input:         $('searchInput'),
  typeSelect:    $('typeSelect'),
  torToggle:     $('torToggle'),
  searchBtn:     $('searchBtn'),
  searchBtnText: $('searchBtnText'),
  searchBtnSpinner: $('searchBtnSpinner'),
  headerStatus:  $('headerStatus'),
  resultsSection:$('resultsSection'),
  sourcesGrid:   $('sourcesGrid'),
  findingsList:  $('findingsList'),
  findingsCount: $('findingsCount'),
  noFindings:    $('noFindings'),
  severityFilter:$('severityFilter'),
  typeFilter:    $('typeFilter'),
  exportBtn:     $('exportBtn'),
  aiPanel:       $('aiPanel'),
  aiToggle:      $('aiToggle'),
  aiChevron:     $('aiChevron'),
  aiBody:        $('aiBody'),
  aiRiskBadge:   $('aiRiskBadge'),
  aiSummary:     $('aiSummary'),
  riskFill:      $('riskFill'),
  riskScore:     $('riskScore'),
  keyFindingsList: $('keyFindingsList'),
  connectionsList: $('connectionsList'),
  errorBanner:   $('errorBanner'),
  errorMessage:  $('errorMessage'),
};

// ─── Transitions ──────────────────────────────────────────────────────────────
function transitionTo(newStatus) {
  state.status = newStatus;

  switch (newStatus) {
    case 'IDLE':
      setHeaderStatus('');
      dom.searchBtn.disabled = false;
      dom.searchBtnText.textContent = 'SEARCH';
      dom.searchBtnSpinner.classList.add('hidden');
      dom.exportBtn.disabled = true;
      break;

    case 'SEARCHING':
      setHeaderStatus('⟳ Initialising…');
      dom.searchBtn.disabled = true;
      dom.searchBtnText.textContent = 'SEARCHING';
      dom.searchBtnSpinner.classList.remove('hidden');
      dom.resultsSection.classList.remove('hidden');
      dom.errorBanner.classList.add('hidden');
      dom.noFindings.classList.remove('hidden');
      dom.findingsList.innerHTML = '';
      dom.sourcesGrid.innerHTML = '';
      dom.aiPanel.classList.add('hidden');
      dom.findingsCount.textContent = '0';
      dom.exportBtn.disabled = true;
      state.findings = [];
      state.sources = {};
      state.aiAnalysis = null;
      break;

    case 'STREAMING':
      setHeaderStatus('◈ Scanning…');
      dom.noFindings.classList.add('hidden');
      break;

    case 'DONE':
      setHeaderStatus(`✓ Complete — ${state.findings.length} finding${state.findings.length !== 1 ? 's' : ''}`);
      dom.searchBtn.disabled = false;
      dom.searchBtnText.textContent = 'SEARCH';
      dom.searchBtnSpinner.classList.add('hidden');
      dom.exportBtn.disabled = false;
      if (state.findings.length === 0) {
        dom.noFindings.classList.remove('hidden');
        dom.noFindings.querySelector('p').textContent = 'No findings found for this target.';
      }
      break;

    case 'ERROR':
      setHeaderStatus('⚠ Error');
      dom.searchBtn.disabled = false;
      dom.searchBtnText.textContent = 'SEARCH';
      dom.searchBtnSpinner.classList.add('hidden');
      break;
  }
}

// ─── Search submission ────────────────────────────────────────────────────────
dom.form.addEventListener('submit', async e => {
  e.preventDefault();

  const raw = dom.input.value.trim();
  if (!raw) return;

  // Close any existing EventSource
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }

  transitionTo('SEARCHING');

  try {
    const resp = await fetch('/api/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        raw,
        type: dom.typeSelect.value,
        use_tor: dom.torToggle.checked,
      }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(err.error || `HTTP ${resp.status}`);
    }

    const { query_id } = await resp.json();
    state.queryID = query_id;

    // Update URL hash for page-reload recovery
    window.location.hash = query_id;

    openStream(query_id);
  } catch (err) {
    showError(err.message);
    transitionTo('ERROR');
  }
});

// ─── SSE Stream ───────────────────────────────────────────────────────────────
function openStream(queryID) {
  const es = new EventSource(`/api/stream?id=${queryID}`);
  state.eventSource = es;

  es.addEventListener('source_update', e => {
    const sm = JSON.parse(e.data);
    state.sources[sm.name] = sm;
    renderSourceCell(sm);
  });

  es.addEventListener('finding', e => {
    if (state.status === 'SEARCHING') transitionTo('STREAMING');
    const f = JSON.parse(e.data);
    state.findings.push(f);
    dom.findingsCount.textContent = state.findings.length;
    prependFindingCard(f);
  });

  es.addEventListener('ai_analysis', e => {
    const ai = JSON.parse(e.data);
    state.aiAnalysis = ai;
    renderAIAnalysis(ai);
  });

  es.addEventListener('done', () => {
    es.close();
    state.eventSource = null;
    transitionTo('DONE');
  });

  es.addEventListener('error', e => {
    // SSE error event from our server
    try {
      const data = JSON.parse(e.data);
      showError(data.message || 'Stream error');
    } catch {
      // Connection error (network / server closed)
      if (state.status !== 'DONE') {
        showError('Connection lost. Results so far are preserved.');
        transitionTo('ERROR');
      }
    }
    es.close();
    state.eventSource = null;
  });

  // Generic onerror (network failure)
  es.onerror = () => {
    if (state.status !== 'DONE' && state.status !== 'ERROR') {
      showError('Stream connection failed.');
      transitionTo('ERROR');
      es.close();
    }
  };
}

// ─── Source Grid ──────────────────────────────────────────────────────────────
function renderSourceCell(sm) {
  let cell = document.querySelector(`.source-cell[data-name="${sm.name}"]`);
  if (!cell) {
    cell = document.createElement('div');
    cell.className = 'source-cell pending';
    cell.dataset.name = sm.name;
    cell.innerHTML = `
      <span class="source-dot"></span>
      <span class="source-name">${escHtml(sm.name)}</span>
      <span class="source-count"></span>
    `;
    dom.sourcesGrid.appendChild(cell);
  }

  // Update classes
  cell.className = `source-cell ${sm.status || 'pending'}`;

  const countEl = cell.querySelector('.source-count');
  if (sm.count > 0) countEl.textContent = sm.count;

  if (sm.duration_ms > 0) {
    let durEl = cell.querySelector('.source-duration');
    if (!durEl) {
      durEl = document.createElement('span');
      durEl.className = 'source-duration';
      cell.appendChild(durEl);
    }
    durEl.textContent = sm.duration_ms < 1000
      ? `${sm.duration_ms}ms`
      : `${(sm.duration_ms / 1000).toFixed(1)}s`;
  }
}

// ─── Finding Cards ────────────────────────────────────────────────────────────
function prependFindingCard(f) {
  if (!passesFilters(f)) return;
  const card = buildFindingCard(f);
  dom.findingsList.prepend(card);
}

function buildFindingCard(f) {
  const card = document.createElement('div');
  card.className = 'finding-card';
  card.dataset.sev = f.severity || 'info';
  card.dataset.type = f.type || '';
  card.dataset.id = f.id;

  const sevLabel = (f.severity || 'info').toUpperCase();

  card.innerHTML = `
    <div class="finding-top">
      <span class="finding-title">${escHtml(f.title)}</span>
      <div class="finding-badges">
        <span class="badge badge-source">${escHtml(f.source)}</span>
        <span class="badge badge-type">${escHtml(f.type)}</span>
        <span class="badge badge-sev-${f.severity || 'info'}">${sevLabel}</span>
      </div>
    </div>
    ${f.summary ? `<p class="finding-summary">${escHtml(f.summary)}</p>` : ''}
    ${f.url ? `<a class="finding-url" href="${escHtml(f.url)}" target="_blank" rel="noopener">${escHtml(truncateURL(f.url, 80))}</a>` : ''}
    ${f.raw ? `<pre class="finding-raw">${escHtml(JSON.stringify(f.raw, null, 2))}</pre>` : ''}
  `;

  // Toggle raw data on click
  card.addEventListener('click', e => {
    if (e.target.tagName === 'A') return; // don't intercept link clicks
    card.classList.toggle('expanded');
  });

  return card;
}

function passesFilters(f) {
  const sev  = dom.severityFilter.value;
  const type = dom.typeFilter.value;
  if (sev  !== 'all' && f.severity !== sev)  return false;
  if (type !== 'all' && f.type     !== type) return false;
  return true;
}

// Re-render all findings when filters change
[dom.severityFilter, dom.typeFilter].forEach(el => {
  el.addEventListener('change', () => {
    dom.findingsList.innerHTML = '';
    [...state.findings].reverse().forEach(f => {
      if (passesFilters(f)) dom.findingsList.appendChild(buildFindingCard(f));
    });
  });
});

// ─── AI Analysis ──────────────────────────────────────────────────────────────
function renderAIAnalysis(ai) {
  dom.aiPanel.classList.remove('hidden');

  // Risk score
  const score = ai.risk_score || 0;
  dom.riskScore.textContent = `${score}/100`;

  const fill = dom.riskFill;
  fill.style.width = `${score}%`;
  if (score >= 75)      fill.style.background = 'var(--sev-critical)';
  else if (score >= 50) fill.style.background = 'var(--sev-high)';
  else if (score >= 25) fill.style.background = 'var(--sev-medium)';
  else                  fill.style.background = 'var(--sev-low)';

  const riskLabel = score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW';
  dom.aiRiskBadge.textContent = `Risk: ${riskLabel}`;
  dom.aiRiskBadge.style.background = `var(--sev-${riskLabel.toLowerCase()}, var(--sev-info))`;
  dom.aiRiskBadge.style.color = '#0d1117';

  if (ai.summary) {
    dom.aiSummary.textContent = ai.summary;
  }

  if (ai.key_findings && ai.key_findings.length > 0) {
    dom.keyFindingsList.innerHTML = ai.key_findings
      .map(kf => `<li>${escHtml(kf)}</li>`)
      .join('');
    $('keyFindingsSection').style.display = '';
  } else {
    $('keyFindingsSection').style.display = 'none';
  }

  if (ai.connections && ai.connections.length > 0) {
    dom.connectionsList.innerHTML = ai.connections
      .map(c => `<li>${escHtml(c)}</li>`)
      .join('');
    $('connectionsSection').style.display = '';
  } else {
    $('connectionsSection').style.display = 'none';
  }

  // Auto-expand AI panel
  dom.aiPanel.classList.add('open');
  dom.aiBody.classList.remove('hidden');
}

// AI panel toggle
dom.aiToggle.addEventListener('click', () => {
  dom.aiPanel.classList.toggle('open');
  dom.aiBody.classList.toggle('hidden');
});

// ─── Export ───────────────────────────────────────────────────────────────────
dom.exportBtn.addEventListener('click', () => {
  if (!state.queryID) return;
  window.location.href = `/api/export?id=${state.queryID}`;
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function truncateURL(url, max) {
  if (url.length <= max) return url;
  return url.slice(0, max) + '…';
}

function setHeaderStatus(msg) {
  dom.headerStatus.textContent = msg;
}

function showError(msg) {
  dom.errorMessage.textContent = msg;
  dom.errorBanner.classList.remove('hidden');
}

// ─── Page-load recovery ───────────────────────────────────────────────────────
(async function recoverFromHash() {
  const hash = window.location.hash.slice(1);
  if (!hash || hash.length < 8) return;

  try {
    const resp = await fetch(`/api/status?id=${hash}`);
    if (!resp.ok) return;
    const data = await resp.json();
    if (data.status !== 'done' && data.status !== 'error') return;

    // Re-stream cached results
    state.queryID = hash;
    transitionTo('SEARCHING');
    openStream(hash);
  } catch {
    // ignore recovery errors
  }
})();
