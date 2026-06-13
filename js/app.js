// js/app.js — SOC Dashboard Main Application Controller

import { Simulator, ATTACK_CAMPAIGNS, generateAlert } from './simulator.js';
import { initEPSChart, updateEPSChart, initCategoryChart, updateCategoryChart, initSeverityChart, updateSeverityChart, updateChartsTheme } from './charts.js';
import { PLAYBOOKS, runPlaybook } from './playbooks.js';
import { lookupIOC, renderIOCResult, renderThreatFeed, renderCVEList, renderMITREGrid, updateMITREFromAlerts } from './threatIntel.js';

// ── Application State ──────────────────────────────────────────
const state = {
  alerts: [],       // circular buffer (max 500)
  resolved: 0,
  selectedAlert: null,
  currentView: 'dashboard',
  epsHistory: [],
  categoryCounts: { Malware: 0, Intrusion: 0, DDoS: 0, Phishing: 0, Exfiltration: 0, Ransomware: 0 },
  sevCounts: { Critical: 0, High: 0, Medium: 0, Low: 0 },
  simulator: null,
  charts: {},
  filterSeverity: '',
  filterStatus: '',
  filterCategory: '',
  filterSearch: '',
  activeIOCType: 'ip',
};

const MAX_ALERTS = 500;
const MAX_STREAM_LINES = 120;

// ── Init ───────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initNavigation();
  initCharts();
  initSimulator();
  initAlertFilters();
  initPlaybooksView();
  initThreatIntelView();
  initSimulatorView();
  initThemeToggle();
  updateKPIs();
  updateThreatLevel();
});

// ── Clock ──────────────────────────────────────────────────────
function initClock() {
  const el = document.getElementById('topbar-clock');
  function tick() {
    el.textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
  }
  tick();
  setInterval(tick, 1000);
}

// ── Navigation ─────────────────────────────────────────────────
function initNavigation() {
  const sidebar = document.getElementById('sidebar');
  const navItems = document.querySelectorAll('.nav-item[data-view]');
  navItems.forEach(item => {
    item.addEventListener('click', e => {
      e.preventDefault();
      switchView(item.dataset.view);
      sidebar.classList.remove('open');
    });
  });

  // View link buttons (e.g. "View All →")
  document.querySelectorAll('[data-view-link]').forEach(btn => {
    btn.addEventListener('click', () => {
      switchView(btn.dataset.viewLink);
      sidebar.classList.remove('open');
    });
  });

  // Sidebar toggle (mobile)
  document.getElementById('sidebarToggle').addEventListener('click', (e) => {
    e.stopPropagation();
    sidebar.classList.toggle('open');
  });

  // Sidebar close button (mobile)
  const closeBtn = document.getElementById('sidebarClose');
  if (closeBtn) {
    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      sidebar.classList.remove('open');
    });
  }

  // Click outside sidebar to close it on mobile
  document.addEventListener('click', (e) => {
    if (sidebar.classList.contains('open')) {
      const isClickInside = sidebar.contains(e.target) || 
                           document.getElementById('sidebarToggle').contains(e.target) ||
                           (closeBtn && closeBtn.contains(e.target));
      if (!isClickInside) {
        sidebar.classList.remove('open');
      }
    }
  });
}

function switchView(viewId) {
  // Deactivate all
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

  // Activate selected
  const navEl = document.getElementById('nav-' + viewId);
  if (navEl) navEl.classList.add('active');
  const viewEl = document.getElementById('view-' + viewId);
  if (viewEl) viewEl.classList.add('active');

  // Update page title
  const titles = {
    dashboard: 'Dashboard Overview',
    alerts: 'Alert Triage Center',
    intel: 'Threat Intelligence',
    playbooks: 'SOAR Playbooks',
    simulator: 'SIEM Simulator',
  };
  document.getElementById('page-title').textContent = titles[viewId] || viewId;
  state.currentView = viewId;

  // Reset scroll position to prevent view scroll bleed
  const contentArea = document.getElementById('content-area');
  if (contentArea) contentArea.scrollTop = 0;

  // Refresh alert table on switch
  if (viewId === 'alerts') renderAlertTable();
  if (viewId === 'intel') updateMITREFromAlerts(document.getElementById('mitre-grid'), state.alerts);
}

// ── Charts ─────────────────────────────────────────────────────
function initCharts() {
  state.charts.eps = initEPSChart('epsChart');
  state.charts.category = initCategoryChart('categoryChart');
  state.charts.severity = initSeverityChart('severityChart');
}

// ── Simulator ─────────────────────────────────────────────────
function initSimulator() {
  state.simulator = new Simulator(onNewAlert, onStreamLine);

  document.getElementById('sim-start').addEventListener('click', () => {
    state.simulator.start();
    document.getElementById('sim-start').disabled = true;
    document.getElementById('sim-stop').disabled = false;
    document.getElementById('sim-status-dot').style.background = '#10b981';
    document.getElementById('sim-status-dot').style.boxShadow = '0 0 6px rgba(16,185,129,0.6)';
    document.getElementById('sim-status-text').textContent = 'Running';
    document.getElementById('live-badge').style.display = 'block';
    document.querySelector('.stream-empty')?.remove();
  });

  document.getElementById('sim-stop').addEventListener('click', () => {
    state.simulator.stop();
    document.getElementById('sim-start').disabled = false;
    document.getElementById('sim-stop').disabled = true;
    document.getElementById('sim-status-dot').style.background = '#94a3b8';
    document.getElementById('sim-status-dot').style.boxShadow = 'none';
    document.getElementById('sim-status-text').textContent = 'Paused';
  });

  document.getElementById('sim-clear').addEventListener('click', () => {
    state.alerts = [];
    state.categoryCounts = { Malware: 0, Intrusion: 0, DDoS: 0, Phishing: 0, Exfiltration: 0, Ransomware: 0 };
    state.sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    state.resolved = 0;
    document.getElementById('event-stream').innerHTML = '<div class="stream-empty">Start the simulator to begin ingesting events...</div>';
    document.getElementById('recent-alerts-list').innerHTML = '<div class="empty-state">No alerts yet. Start the simulator →</div>';
    document.getElementById('alert-table-body').innerHTML = '<tr><td colspan="8" class="empty-cell">No alerts yet. Start the simulator.</td></tr>';
    updateKPIs();
    updateCharts(0);
    updateThreatLevel();
    document.getElementById('nav-alert-count').textContent = '0';
  });

  // EPS slider
  const slider = document.getElementById('eps-slider');
  const sliderVal = document.getElementById('eps-slider-val');
  slider.addEventListener('input', () => {
    sliderVal.textContent = slider.value;
    state.simulator.setEPS(parseInt(slider.value));
  });

  // EPS chart ticker
  setInterval(() => {
    if (state.simulator.running) {
      const eps = parseInt(document.getElementById('eps-slider').value) + Math.floor(Math.random() * 5) - 2;
      updateEPSChart(state.charts.eps, Math.max(0, eps));
      document.getElementById('eps-display').textContent = Math.max(0, eps) + ' EPS';
      document.getElementById('kpi-eps').textContent = Math.max(0, eps);
    }
  }, 1200);
}

function onNewAlert(alert) {
  // Add to buffer
  state.alerts.unshift(alert);
  if (state.alerts.length > MAX_ALERTS) state.alerts.pop();

  // Update counts
  state.categoryCounts[alert.category] = (state.categoryCounts[alert.category] || 0) + 1;
  state.sevCounts[alert.severity] = (state.sevCounts[alert.severity] || 0) + 1;

  updateKPIs();
  updateCharts(parseInt(document.getElementById('eps-slider').value));
  updateRecentAlerts();
  updateThreatLevel();

  // Update alert table if visible
  if (state.currentView === 'alerts') renderAlertTable();

  // Update badge
  const openCount = state.alerts.filter(a => a.status === 'Open').length;
  document.getElementById('nav-alert-count').textContent = openCount > 99 ? '99+' : openCount;
}

function onStreamLine(line) {
  const container = document.getElementById('event-stream');
  const el = document.createElement('div');
  el.className = 'stream-line';
  el.innerHTML = `<span class="ts">[${line.ts}]</span> <span class="sev ${line.sev}">[${line.sev.toUpperCase()}]</span> <span class="msg">${line.msg}</span>`;
  container.prepend(el);

  // Trim
  const lines = container.querySelectorAll('.stream-line');
  if (lines.length > MAX_STREAM_LINES) {
    lines[lines.length - 1].remove();
  }
}

// ── KPIs ───────────────────────────────────────────────────────
function updateKPIs() {
  document.getElementById('kpi-critical').textContent = state.sevCounts['Critical'] || 0;
  document.getElementById('kpi-active').textContent = state.alerts.filter(a => a.status === 'Open').length;
  document.getElementById('kpi-resolved').textContent = state.resolved;
}

// ── Charts Update ──────────────────────────────────────────────
function updateCharts(eps) {
  updateCategoryChart(state.charts.category, state.categoryCounts);
  updateSeverityChart(state.charts.severity, state.sevCounts);
}

// ── Threat Level ───────────────────────────────────────────────
function updateThreatLevel() {
  const pill = document.getElementById('threat-level-pill');
  const label = document.getElementById('threat-level-label');
  const critical = state.sevCounts['Critical'] || 0;
  const high = state.sevCounts['High'] || 0;

  pill.className = 'threat-level-pill';
  if (critical >= 5) {
    pill.classList.add('critical');
    label.textContent = 'CRITICAL RISK';
  } else if (critical >= 1 || high >= 8) {
    pill.classList.add('high');
    label.textContent = 'HIGH RISK';
  } else if (high >= 3) {
    label.textContent = 'MEDIUM RISK';
  } else {
    pill.classList.add('low');
    label.textContent = 'LOW RISK';
  }
}

// ── Recent Alerts (Dashboard) ──────────────────────────────────
function updateRecentAlerts() {
  const container = document.getElementById('recent-alerts-list');
  const recent = state.alerts.slice(0, 8);
  const sevColors = { Critical: '#ef4444', High: '#f97316', Medium: '#3b82f6', Low: '#10b981' };

  container.innerHTML = recent.map(a => `
    <div class="alert-mini" data-id="${a.id}">
      <div class="alert-mini-sev" style="background:${sevColors[a.severity]}"></div>
      <div class="alert-mini-name">${a.name}</div>
      <div class="alert-mini-time">${a.timeLabel}</div>
    </div>
  `).join('');

  container.querySelectorAll('.alert-mini').forEach(el => {
    el.addEventListener('click', () => {
      const alert = state.alerts.find(a => a.id === el.dataset.id);
      if (alert) {
        switchView('alerts');
        setTimeout(() => selectAlert(alert), 100);
      }
    });
  });
}

// ── Alert Table ────────────────────────────────────────────────
function initAlertFilters() {
  document.getElementById('filter-severity').addEventListener('change', e => { state.filterSeverity = e.target.value; renderAlertTable(); });
  document.getElementById('filter-status').addEventListener('change', e => { state.filterStatus = e.target.value; renderAlertTable(); });
  document.getElementById('filter-category').addEventListener('change', e => { state.filterCategory = e.target.value; renderAlertTable(); });
  document.getElementById('alert-search').addEventListener('input', e => { state.filterSearch = e.target.value.toLowerCase(); renderAlertTable(); });
}

function getFilteredAlerts() {
  return state.alerts.filter(a => {
    if (state.filterSeverity && a.severity !== state.filterSeverity) return false;
    if (state.filterStatus && a.status !== state.filterStatus) return false;
    if (state.filterCategory && a.category !== state.filterCategory) return false;
    if (state.filterSearch) {
      const q = state.filterSearch;
      if (![a.name || '', a.sourceIP || '', a.hostname || '', a.category || ''].some(f => f.toLowerCase().includes(q))) return false;
    }
    return true;
  });
}

function renderAlertTable() {
  const tbody = document.getElementById('alert-table-body');
  const filtered = getFilteredAlerts();

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-cell">No matching alerts found.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.slice(0, 100).map(a => `
    <tr data-id="${a.id}" class="${state.selectedAlert?.id === a.id ? 'selected' : ''}">
      <td><span class="sev-badge ${a.severity}"><span class="sev-dot"></span>${a.severity}</span></td>
      <td style="font-weight:500;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${a.name}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px">${a.sourceIP}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px">${a.hostname}</td>
      <td>${a.category}</td>
      <td style="font-size:12px;white-space:nowrap">${a.timeLabel}</td>
      <td><span class="status-badge ${a.status}">${a.status}</span></td>
      <td><button class="btn-inspect" data-id="${a.id}">Inspect</button></td>
    </tr>
  `).join('');

  tbody.querySelectorAll('tr[data-id]').forEach(row => {
    row.addEventListener('click', () => {
      const alert = state.alerts.find(a => a.id === row.dataset.id);
      if (alert) selectAlert(alert);
    });
  });

  tbody.querySelectorAll('.btn-inspect').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const alert = state.alerts.find(a => a.id === btn.dataset.id);
      if (alert) selectAlert(alert);
    });
  });
}

function selectAlert(alert) {
  state.selectedAlert = alert;
  renderAlertDetail(alert);
  // Reset details panel scroll position to the top
  const panel = document.getElementById('alert-detail-panel');
  if (panel) panel.scrollTop = 0;
  // Highlight row
  document.querySelectorAll('#alert-table-body tr').forEach(r => r.classList.remove('selected'));
  const row = document.querySelector(`#alert-table-body tr[data-id="${alert.id}"]`);
  if (row) row.classList.add('selected');
}

function renderAlertDetail(alert) {
  const panel = document.getElementById('alert-detail-panel');
  const mitreTags = (alert.mitre || []).map(t => `<span class="mitre-tag">${t}</span>`).join('');
  const sevColors = { Critical: '#ef4444', High: '#f97316', Medium: '#3b82f6', Low: '#10b981' };

  panel.innerHTML = `
    <div class="detail-section">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
        <span class="sev-badge ${alert.severity}" style="font-size:12px;padding:4px 12px">
          <span class="sev-dot"></span>${alert.severity}
        </span>
        <span class="status-badge ${alert.status}">${alert.status}</span>
      </div>
      <div style="font-size:15px;font-weight:700;color:var(--text-primary);margin-bottom:4px">${alert.name}</div>
      <div style="font-size:12px;color:var(--text-secondary);line-height:1.6">${alert.description}</div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Incident Details</div>
      <div class="detail-field"><div class="detail-field-label">Alert ID</div><div class="detail-field-value" style="font-family:'JetBrains Mono',monospace">${alert.id}</div></div>
      <div class="detail-field"><div class="detail-field-label">Source IP</div><div class="detail-field-value" style="font-family:'JetBrains Mono',monospace">${alert.sourceIP}</div></div>
      <div class="detail-field"><div class="detail-field-label">Destination IP</div><div class="detail-field-value" style="font-family:'JetBrains Mono',monospace">${alert.destIP}</div></div>
      <div class="detail-field"><div class="detail-field-label">Hostname</div><div class="detail-field-value">${alert.hostname}</div></div>
      <div class="detail-field"><div class="detail-field-label">Category</div><div class="detail-field-value">${alert.category}</div></div>
      <div class="detail-field"><div class="detail-field-label">Timestamp</div><div class="detail-field-value">${new Date(alert.timestamp).toLocaleString()}</div></div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">MITRE ATT&CK</div>
      <div>${mitreTags || '<span style="color:var(--text-muted);font-size:12px">No mapping available</span>'}</div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Raw Log</div>
      <div class="json-log">${alert.rawLog}</div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Response Actions</div>
      <div class="action-buttons" id="action-buttons">
        ${alert.status === 'Remediated' ? `
          <div style="text-align:center;padding:16px;color:var(--green);font-weight:600;font-size:13px">
            ✓ Alert has been remediated
          </div>
        ` : `
          <button class="btn-action danger" id="act-isolate">
            🛡 Isolate Endpoint
          </button>
          <button class="btn-action warning" id="act-block-ip">
            🚫 Block IP on Firewall
          </button>
          <button class="btn-action info" id="act-disable-user">
            👤 Disable User Session
          </button>
          <button class="btn-action info" id="act-enrich" style="border-color:rgba(139,92,246,0.3);background:rgba(139,92,246,0.08);color:#8b5cf6">
            🔍 Enrich & Triage
          </button>
        `}
      </div>
      <div class="inline-progress-bar-wrap" id="inline-pb-progress-wrap">
        <div class="inline-progress-bar" id="inline-pb-progress"></div>
      </div>
      <div class="inline-playbook-console" id="inline-pb-console" style="display:none;"></div>
    </div>
  `;

  // Bind action buttons
  if (alert.status !== 'Remediated') {
    const actions = [
      { id: 'act-isolate', playbook: 'isolate-endpoint' },
      { id: 'act-block-ip', playbook: 'block-ip' },
      { id: 'act-disable-user', playbook: 'disable-user' },
      { id: 'act-enrich', playbook: 'enrich-alert' },
    ];
    for (const { id, playbook } of actions) {
      const btn = document.getElementById(id);
      if (btn) {
        btn.addEventListener('click', () => {
          executeActionFromDetail(alert, playbook);
        });
      }
    }
  }
}

function executeActionFromDetail(alert, playbookId) {
  const actionButtons = document.getElementById('action-buttons');
  const progressWrap = document.getElementById('inline-pb-progress-wrap');
  const progressBar = document.getElementById('inline-pb-progress');
  const consoleEl = document.getElementById('inline-pb-console');

  // Disable all action buttons
  const buttons = actionButtons.querySelectorAll('.btn-action');
  buttons.forEach(btn => btn.disabled = true);

  // Show inline console and progress bar
  consoleEl.style.display = 'flex';
  progressWrap.style.display = 'block';

  // Get playbook total duration
  const pb = PLAYBOOKS.find(p => p.id === playbookId);
  const totalTime = pb ? Math.max(...pb.steps.map(s => s.delay)) + 1200 : 3000;

  // Trigger progress bar transition
  progressBar.style.transition = 'none';
  progressBar.style.width = '0%';
  progressBar.offsetHeight; // force reflow
  progressBar.style.transition = `width ${totalTime}ms linear`;
  progressBar.style.width = '100%';

  // Run the playbook on the inline console element
  runPlaybook(playbookId, consoleEl, (completedPb) => {
    // Mark alert as remediated
    alert.status = 'Remediated';
    state.resolved++;
    updateKPIs();
    logExecution(completedPb, true);
    updateThreatLevel();

    // Re-render Alert Table to show checkmarks/remediated statuses
    renderAlertTable();

    // Hide progress bar and update action buttons to remediated state
    progressWrap.style.display = 'none';
    actionButtons.innerHTML = `
      <div style="text-align:center;padding:16px;color:var(--green);font-weight:600;font-size:13px;animation:fadeIn 0.3s ease;">
        ✓ Alert has been remediated
      </div>
    `;

    // Re-render full detail panel to update header badges
    renderAlertDetail(alert);

    // Update alert counts in sidebar badge
    const openCount = state.alerts.filter(a => a.status === 'Open').length;
    document.getElementById('nav-alert-count').textContent = openCount > 99 ? '99+' : openCount;
  });
}

// ── Playbooks View ─────────────────────────────────────────────
function initPlaybooksView() {
  const container = document.getElementById('playbook-items');
  container.innerHTML = PLAYBOOKS.map(pb => `
    <div class="playbook-item" data-id="${pb.id}">
      <div class="playbook-name">${pb.name}</div>
      <div class="playbook-desc">${pb.desc}</div>
      <div class="playbook-meta">
        <span class="playbook-trigger">${pb.trigger}</span>
        <button class="playbook-run-btn" data-id="${pb.id}">▶ Execute</button>
      </div>
    </div>
  `).join('');

  container.querySelectorAll('.playbook-run-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const pbId = btn.dataset.id;
      const terminal = document.getElementById('playbook-terminal');
      document.querySelectorAll('.playbook-item').forEach(el => el.classList.remove('running'));
      btn.closest('.playbook-item').classList.add('running');

      runPlaybook(pbId, terminal, (pb) => {
        btn.closest('.playbook-item').classList.remove('running');
        logExecution(pb, true);
        state.resolved++;
        updateKPIs();
      });
    });
  });

  document.getElementById('clear-terminal').addEventListener('click', () => {
    document.getElementById('playbook-terminal').innerHTML = '<div class="terminal-prompt">$ Select a playbook to execute...</div>';
  });
}

function logExecution(pb, success) {
  const logContainer = document.getElementById('execution-log');
  const empty = logContainer.querySelector('.empty-state');
  if (empty) empty.remove();

  const entry = document.createElement('div');
  entry.className = `exec-item ${success ? 'success' : 'fail'}`;
  entry.innerHTML = `
    <span>${success ? '✓' : '✗'}</span>
    <span style="flex:1;font-weight:600">${pb.name}</span>
    <span style="color:var(--text-muted)">${new Date().toLocaleTimeString()}</span>
  `;
  logContainer.prepend(entry);
}

// ── Threat Intel View ──────────────────────────────────────────
function initThreatIntelView() {
  renderThreatFeed(document.getElementById('threat-feed'));
  renderCVEList(document.getElementById('vuln-list'));
  renderMITREGrid(document.getElementById('mitre-grid'));

  // IOC type tabs
  document.querySelectorAll('.ioc-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.ioc-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      state.activeIOCType = tab.dataset.ioc;
      const placeholders = { ip: '45.141.152.18', hash: 'e3b0c44298fc1c14', domain: 'evil-update-server.ru' };
      document.getElementById('ioc-input').placeholder = `Enter ${tab.dataset.ioc}... (try: ${placeholders[tab.dataset.ioc]})`;
      document.getElementById('ioc-result').innerHTML = '<div class="ioc-empty">Enter an indicator to analyze threat context.</div>';
    });
  });

  // Set initial placeholder
  document.getElementById('ioc-input').placeholder = 'Enter IP... (try: 45.141.152.18 or 185.220.101.3)';

  document.getElementById('ioc-lookup-btn').addEventListener('click', doIOCLookup);
  document.getElementById('ioc-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') doIOCLookup();
  });

  // Refresh feed every 30s
  setInterval(() => {
    renderThreatFeed(document.getElementById('threat-feed'));
  }, 30000);
}

function isValidIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    const num = Number(p);
    return !isNaN(num) && num >= 0 && num <= 255 && p === String(num);
  });
}

function isValidHash(hash) {
  return /^[a-fA-F0-9]{16}$/.test(hash) || /^[a-fA-F0-9]{32}$/.test(hash) || /^[a-fA-F0-9]{40}$/.test(hash) || /^[a-fA-F0-9]{64}$/.test(hash);
}

function isValidDomain(domain) {
  return /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/.test(domain);
}

function showIOCError(msg) {
  const container = document.getElementById('ioc-result');
  container.innerHTML = `<div class="ioc-empty" style="color:var(--red); font-weight: 600;">⚠️ ${msg}</div>`;
}

function doIOCLookup() {
  const value = document.getElementById('ioc-input').value.trim();
  if (!value) {
    showIOCError('Please enter an indicator.');
    return;
  }

  // Format validations
  if (state.activeIOCType === 'ip' && !isValidIPv4(value)) {
    showIOCError('Invalid IPv4 address format. Expected: e.g. 192.168.1.1');
    return;
  }
  if (state.activeIOCType === 'hash' && !isValidHash(value)) {
    showIOCError('Invalid file hash format. Expected: 32-char MD5, 40-char SHA1, or 64-char SHA256.');
    return;
  }
  if (state.activeIOCType === 'domain' && !isValidDomain(value)) {
    showIOCError('Invalid domain format. Expected: e.g. example.com');
    return;
  }

  const result = lookupIOC(state.activeIOCType, value);
  const container = document.getElementById('ioc-result');
  if (result) {
    renderIOCResult(container, result, state.activeIOCType);
  } else {
    container.innerHTML = '<div class="ioc-empty" style="color:var(--red)">No results found for this indicator.</div>';
  }
}

// ── Simulator View (Attack Campaigns) ─────────────────────────
function initSimulatorView() {
  const container = document.getElementById('attack-cards');
  container.innerHTML = ATTACK_CAMPAIGNS.map(c => `
    <div class="attack-card" data-id="${c.id}">
      <div class="attack-card-icon">${c.icon}</div>
      <div class="attack-card-name">${c.name}</div>
      <div class="attack-card-desc">${c.desc}</div>
      <button class="attack-card-btn" data-id="${c.id}">⚡ Launch Campaign</button>
    </div>
  `).join('');

  container.querySelectorAll('.attack-card-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const campaign = ATTACK_CAMPAIGNS.find(c => c.id === btn.dataset.id);
      if (campaign) {
        // Ensure simulator is running
        if (!state.simulator.running) {
          state.simulator.start();
          document.getElementById('sim-start').disabled = true;
          document.getElementById('sim-stop').disabled = false;
          document.getElementById('sim-status-dot').style.background = '#10b981';
          document.getElementById('sim-status-dot').style.boxShadow = '0 0 6px rgba(16,185,129,0.6)';
          document.getElementById('sim-status-text').textContent = 'Running';
          document.querySelector('.stream-empty')?.remove();
        }
        state.simulator.injectCampaign(campaign);
        // Visual feedback
        btn.textContent = '✓ Launched!';
        btn.style.background = '#10b981';
        setTimeout(() => { btn.textContent = '⚡ Launch Campaign'; btn.style.background = ''; }, 3000);
      }
    });
  });
}

// ── Theme Toggle ───────────────────────────────────────────────
function initThemeToggle() {
  const toggleBtn = document.getElementById('themeToggle');
  if (!toggleBtn) return;
  
  // Check localStorage or system preference
  const savedTheme = localStorage.getItem('soc-theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const isDark = savedTheme === 'dark' || (!savedTheme && prefersDark);
  
  // Set initial state
  document.body.classList.toggle('dark-theme', isDark);
  
  toggleBtn.addEventListener('click', () => {
    const isNowDark = !document.body.classList.contains('dark-theme');
    document.body.classList.toggle('dark-theme', isNowDark);
    localStorage.setItem('soc-theme', isNowDark ? 'dark' : 'light');
    
    // Update charts theme
    updateChartsTheme(state.charts, isNowDark);
  });

  // Call it initially to set correct colors for charts on load
  setTimeout(() => {
    updateChartsTheme(state.charts, isDark);
  }, 100);
}
