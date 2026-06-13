// js/threatIntel.js — Threat Intelligence Module

// ── IOC Lookup Database (mock) ─────────────────────────────────

const IOC_DB = {
  ip: {
    '45.141.152.18': { risk: 'High', score: 91, country: 'Russia', asn: 'AS208091', tags: ['Scanning', 'C2', 'Botnet'], last_seen: '2026-06-12' },
    '103.25.8.55':   { risk: 'High', score: 85, country: 'China',  asn: 'AS137697', tags: ['DDoS', 'Brute Force'],     last_seen: '2026-06-11' },
    '185.220.101.3': { risk: 'High', score: 98, country: 'Germany', asn: 'AS209650 (Tor Exit)', tags: ['Tor Exit', 'Proxy', 'Malware'], last_seen: '2026-06-13' },
    '8.8.8.8':       { risk: 'Low',  score: 0,  country: 'USA',    asn: 'AS15169 (Google)',    tags: ['Trusted DNS'], last_seen: 'N/A' },
  },
  hash: {
    'd41d8cd98f00b204e9800998ecf8427e': { risk: 'Low',      score: 0,  type: 'MD5', malware: 'N/A (empty file)', vt_detections: '0/72', first_seen: 'N/A' },
    '4a5a8c5d3f2e1b0a':                 { risk: 'High',     score: 90, type: 'SHA1', malware: 'LockBit 3.0 Ransomware', vt_detections: '67/72', first_seen: '2026-01-08' },
    'e3b0c44298fc1c14':                 { risk: 'Critical', score: 99, type: 'SHA256', malware: 'Cobalt Strike Beacon', vt_detections: '71/72', first_seen: '2025-09-14' },
  },
  domain: {
    'evil-update-server.ru':     { risk: 'Critical', score: 99, registrar: 'NameCheap', created: '2026-05-01', tags: ['Phishing', 'Malware Distribution', 'NRD'], ip: '185.220.101.3' },
    'totally-legit-bank.info':   { risk: 'High',     score: 88, registrar: 'GoDaddy',  created: '2026-06-01', tags: ['Phishing', 'Banking Fraud', 'NRD'],           ip: '103.25.8.55' },
    'google.com':                { risk: 'Low',      score: 0,  registrar: 'MarkMonitor', created: '1997-09-15', tags: ['Trusted'],                                  ip: '142.250.80.46' },
  }
};

export function lookupIOC(type, value) {
  const db = IOC_DB[type];
  if (!db) return null;
  const key = Object.keys(db).find(k => k.toLowerCase() === value.toLowerCase());
  if (!key) {
    // Generate a plausible result for unknown values
    return generateFallbackIOC(type, value);
  }
  return { value: key, ...db[key] };
}

function generateFallbackIOC(type, value) {
  const score = Math.floor(Math.random() * 60);
  const risk = score > 50 ? 'Medium' : score > 20 ? 'Low' : 'Low';
  if (type === 'ip') {
    return { value, risk, score, country: 'Unknown', asn: 'AS' + Math.floor(Math.random() * 99999), tags: ['Unclassified'], last_seen: 'N/A' };
  } else if (type === 'hash') {
    return { value, risk, score, type: 'SHA256', malware: 'Unclassified', vt_detections: `${score > 30 ? score : 0}/72`, first_seen: 'N/A' };
  } else {
    return { value, risk, score, registrar: 'Unknown', created: 'Unknown', tags: ['Unclassified'], ip: 'N/A' };
  }
}

export function renderIOCResult(container, ioc, type) {
  const riskClass = ioc.risk === 'Critical' || ioc.risk === 'High' ? 'high' : ioc.risk === 'Medium' ? 'medium' : 'low';

  let metaHtml = '';
  if (type === 'ip') {
    metaHtml = `
      <div class="ioc-meta-item"><div class="ioc-meta-label">Country</div><div class="ioc-meta-value">${ioc.country}</div></div>
      <div class="ioc-meta-item"><div class="ioc-meta-label">ASN</div><div class="ioc-meta-value">${ioc.asn}</div></div>
      <div class="ioc-meta-item"><div class="ioc-meta-label">Last Seen</div><div class="ioc-meta-value">${ioc.last_seen}</div></div>
      <div class="ioc-meta-item"><div class="ioc-meta-label">Tags</div><div class="ioc-meta-value">${ioc.tags.map(t => `<span class="mitre-tag">${t}</span>`).join('')}</div></div>
    `;
  } else if (type === 'hash') {
    metaHtml = `
      <div class="ioc-meta-item"><div class="ioc-meta-label">Hash Type</div><div class="ioc-meta-value">${ioc.type}</div></div>
      <div class="ioc-meta-item"><div class="ioc-meta-label">Malware Family</div><div class="ioc-meta-value">${ioc.malware}</div></div>
      <div class="ioc-meta-item"><div class="ioc-meta-label">VT Detections</div><div class="ioc-meta-value">${ioc.vt_detections}</div></div>
      <div class="ioc-meta-item"><div class="ioc-meta-label">First Seen</div><div class="ioc-meta-value">${ioc.first_seen}</div></div>
    `;
  } else {
    metaHtml = `
      <div class="ioc-meta-item"><div class="ioc-meta-label">Registrar</div><div class="ioc-meta-value">${ioc.registrar}</div></div>
      <div class="ioc-meta-item"><div class="ioc-meta-label">Created</div><div class="ioc-meta-value">${ioc.created}</div></div>
      <div class="ioc-meta-item"><div class="ioc-meta-label">Resolved IP</div><div class="ioc-meta-value">${ioc.ip || 'N/A'}</div></div>
      <div class="ioc-meta-item"><div class="ioc-meta-label">Tags</div><div class="ioc-meta-value">${ioc.tags.map(t => `<span class="mitre-tag">${t}</span>`).join('')}</div></div>
    `;
  }

  container.innerHTML = `
    <div class="ioc-result-card">
      <div class="ioc-result-header">
        <span class="ioc-result-value">${ioc.value}</span>
        <span class="risk-score ${riskClass}">Risk: ${ioc.score}/100 — ${ioc.risk}</span>
      </div>
      <div class="ioc-meta-grid">${metaHtml}</div>
    </div>
  `;
}

// ── Threat Feed ────────────────────────────────────────────────

const FEED_ITEMS = [
  { title: 'New LockBit 4.0 variant targeting healthcare sector', source: 'CISA Advisory', sev: 'Critical', time: '2m ago' },
  { title: 'Zero-day in Ivanti Connect Secure — patch immediately', source: 'Vendor Advisory', sev: 'Critical', time: '8m ago' },
  { title: 'Mass exploitation of CVE-2026-1234 observed in the wild', source: 'Threat Intel Feed', sev: 'High', time: '15m ago' },
  { title: 'BlackCat ransomware group resurfaces with updated TTPs', source: 'Dark Web Monitor', sev: 'High', time: '31m ago' },
  { title: 'Large-scale phishing campaign impersonating Microsoft Teams', source: 'Email Gateway', sev: 'High', time: '45m ago' },
  { title: 'Tor exit node IPs added to threat block-list (1,247 IPs)', source: 'Threat Intel Feed', sev: 'Medium', time: '1h ago' },
  { title: 'Suspicious activity from AS208091 — monitor closely', source: 'ISP Alert', sev: 'Medium', time: '2h ago' },
  { title: 'NIST NVD: 14 new critical CVEs published today', source: 'NIST NVD', sev: 'Low', time: '3h ago' },
];

export function renderThreatFeed(container) {
  const colors = { Critical: '#ef4444', High: '#f97316', Medium: '#3b82f6', Low: '#10b981' };
  container.innerHTML = FEED_ITEMS.map(item => `
    <div class="feed-item">
      <div class="feed-dot" style="background:${colors[item.sev]}"></div>
      <div class="feed-content">
        <div class="feed-title">${item.title}</div>
        <div class="feed-meta">${item.source} · ${item.time}</div>
      </div>
    </div>
  `).join('');
}

// ── CVE Watchlist ──────────────────────────────────────────────

const CVE_LIST = [
  { cve: 'CVE-2026-1234', name: 'Apache Log4j RCE (2026 variant)', cvss: 10.0, severity: 'critical' },
  { cve: 'CVE-2026-0891', name: 'Windows LDAP Remote Code Execution', cvss: 9.8, severity: 'critical' },
  { cve: 'CVE-2025-4421', name: 'Ivanti Connect Secure Auth Bypass', cvss: 9.1, severity: 'critical' },
  { cve: 'CVE-2025-3307', name: 'Confluence Data Center RCE', cvss: 8.8, severity: 'high' },
  { cve: 'CVE-2025-2916', name: 'FortiGate SSL VPN Path Traversal', cvss: 8.6, severity: 'high' },
  { cve: 'CVE-2025-1188', name: 'VMware ESXi Privilege Escalation', cvss: 8.1, severity: 'high' },
];

export function renderCVEList(container) {
  container.innerHTML = CVE_LIST.map(item => `
    <div class="vuln-item">
      <div class="vuln-cve">${item.cve}</div>
      <div class="vuln-name">${item.name}</div>
      <div class="cvss-badge ${item.severity}">CVSS ${item.cvss}</div>
    </div>
  `).join('');
}

// ── MITRE ATT&CK Grid ─────────────────────────────────────────

const MITRE_TACTICS = [
  { id: 'TA0001', name: 'Reconnaissance', count: 3 },
  { id: 'TA0002', name: 'Resource Dev.', count: 1 },
  { id: 'TA0003', name: 'Initial Access', count: 7 },
  { id: 'TA0004', name: 'Execution', count: 5 },
  { id: 'TA0005', name: 'Persistence', count: 4 },
  { id: 'TA0006', name: 'Priv. Escalation', count: 6 },
  { id: 'TA0007', name: 'Defense Evasion', count: 3 },
  { id: 'TA0008', name: 'Credential Access', count: 8 },
  { id: 'TA0009', name: 'Discovery', count: 2 },
  { id: 'TA0010', name: 'Lateral Movement', count: 5 },
  { id: 'TA0011', name: 'Collection', count: 2 },
  { id: 'TA0012', name: 'C2', count: 4 },
  { id: 'TA0013', name: 'Exfiltration', count: 3 },
  { id: 'TA0040', name: 'Impact', count: 2 },
];

export function renderMITREGrid(container) {
  container.innerHTML = MITRE_TACTICS.map(t => `
    <div class="mitre-tactic ${t.count > 0 ? 'active' : ''}">
      <div class="mitre-tactic-name">${t.name}</div>
      <div class="mitre-tactic-count">${t.count}</div>
      <div class="mitre-tactic-label">techniques</div>
    </div>
  `).join('');
}

export function updateMITREFromAlerts(container, alerts) {
  const tacticAlertMap = {
    'Malware': ['TA0004', 'TA0007'],
    'Intrusion': ['TA0003', 'TA0006', 'TA0010'],
    'DDoS': ['TA0040'],
    'Phishing': ['TA0003'],
    'Exfiltration': ['TA0013', 'TA0011'],
    'Ransomware': ['TA0040', 'TA0006'],
  };

  const counts = {};
  for (const alert of alerts) {
    const tactics = tacticAlertMap[alert.category] || [];
    for (const tid of tactics) {
      counts[tid] = (counts[tid] || 0) + 1;
    }
  }

  container.innerHTML = MITRE_TACTICS.map(t => {
    const c = (t.count + (counts[t.id] || 0));
    return `
      <div class="mitre-tactic ${c > 0 ? 'active' : ''}">
        <div class="mitre-tactic-name">${t.name}</div>
        <div class="mitre-tactic-count">${c}</div>
        <div class="mitre-tactic-label">techniques</div>
      </div>
    `;
  }).join('');
}
