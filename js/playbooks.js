// js/playbooks.js — SOAR Automated Response Playbooks

export const PLAYBOOKS = [
  {
    id: 'isolate-endpoint',
    name: 'Isolate Endpoint',
    desc: 'Immediately quarantines an endpoint from the network via EDR agent.',
    trigger: 'Malware / Ransomware',
    steps: [
      { text: 'Connecting to EDR management console...', type: 'info', delay: 400 },
      { text: 'Authenticating via service account [svc-soar]...', type: 'info', delay: 700 },
      { text: 'Retrieving agent ID for target host...', type: 'info', delay: 900 },
      { text: 'Issuing ISOLATE command to endpoint agent...', type: 'warn', delay: 1300 },
      { text: 'Verifying network isolation status...', type: 'info', delay: 1700 },
      { text: '✓ Endpoint successfully isolated from network.', type: 'success', delay: 2200 },
      { text: '✓ Isolation event logged to case management [CASE-' + rndId() + ']', type: 'success', delay: 2500 },
      { text: '✓ Notification sent to incident response team.', type: 'success', delay: 2800 },
    ]
  },
  {
    id: 'block-ip',
    name: 'Block IP on Firewall',
    desc: 'Pushes a block rule to perimeter and internal firewalls for a malicious IP address.',
    trigger: 'Intrusion / DDoS',
    steps: [
      { text: 'Resolving target IP threat classification...', type: 'info', delay: 300 },
      { text: 'Connecting to firewall management API (Palo Alto)...', type: 'info', delay: 600 },
      { text: 'Authenticating with API key...', type: 'info', delay: 800 },
      { text: 'Pushing deny rule to PERIMETER-FW-01...', type: 'warn', delay: 1200 },
      { text: 'Pushing deny rule to INTERNAL-FW-02...', type: 'warn', delay: 1500 },
      { text: 'Verifying rule propagation across policy...', type: 'info', delay: 1900 },
      { text: '✓ IP blocked on all firewall tiers.', type: 'success', delay: 2400 },
      { text: '✓ Block rule expiry set to 72 hours.', type: 'success', delay: 2600 },
      { text: '✓ Indicator added to threat intelligence block-list.', type: 'success', delay: 2900 },
    ]
  },
  {
    id: 'disable-user',
    name: 'Disable User Account',
    desc: 'Disables a compromised user account in Active Directory and revokes all sessions.',
    trigger: 'Phishing / Credential Compromise',
    steps: [
      { text: 'Connecting to Active Directory domain controller...', type: 'info', delay: 400 },
      { text: 'Locating target user account in LDAP...', type: 'info', delay: 700 },
      { text: 'Disabling account in Active Directory...', type: 'warn', delay: 1100 },
      { text: 'Revoking Azure AD / Entra ID session tokens...', type: 'warn', delay: 1500 },
      { text: 'Forcing sign-out from all active sessions...', type: 'warn', delay: 1900 },
      { text: 'Resetting account password to random value...', type: 'info', delay: 2300 },
      { text: '✓ Account disabled and all sessions revoked.', type: 'success', delay: 2700 },
      { text: '✓ Manager and HR notified via ServiceNow ticket.', type: 'success', delay: 3000 },
    ]
  },
  {
    id: 'hash-block',
    name: 'Block Malicious Hash',
    desc: 'Adds a file hash to EDR and email gateway deny-lists to prevent execution.',
    trigger: 'Malware Detection',
    steps: [
      { text: 'Submitting hash to threat intelligence enrichment...', type: 'info', delay: 400 },
      { text: 'VirusTotal: 62/71 engines flagged — MALICIOUS.', type: 'error', delay: 900 },
      { text: 'Adding hash to EDR Custom IOC blocklist...', type: 'warn', delay: 1300 },
      { text: 'Adding hash to email attachment filter...', type: 'warn', delay: 1700 },
      { text: 'Scanning endpoints for existing instances of file...', type: 'info', delay: 2100 },
      { text: '3 instances found on LINUX-WEB01, WIN-WS-043, WIN-WS-107', type: 'error', delay: 2500 },
      { text: 'Quarantining detected file instances...', type: 'warn', delay: 2900 },
      { text: '✓ Hash blocked across all enforcement points.', type: 'success', delay: 3300 },
      { text: '✓ Affected hosts queued for forensic analysis.', type: 'success', delay: 3600 },
    ]
  },
  {
    id: 'enrich-alert',
    name: 'Enrich & Triage Alert',
    desc: 'Automatically correlates and enriches an alert with threat intel and CMDB context.',
    trigger: 'Any Alert',
    steps: [
      { text: 'Fetching asset details from CMDB...', type: 'info', delay: 300 },
      { text: 'Looking up source IP in threat intelligence feeds...', type: 'info', delay: 600 },
      { text: 'AbuseIPDB: High confidence threat [Score: 97/100]', type: 'error', delay: 1000 },
      { text: 'Pulling historical events for this host (last 30 days)...', type: 'info', delay: 1300 },
      { text: 'Correlating with open incidents in SIEM...', type: 'info', delay: 1700 },
      { text: 'MITRE ATT&CK mapping complete.', type: 'success', delay: 2000 },
      { text: '✓ Alert enrichment complete. Priority: HIGH', type: 'success', delay: 2400 },
      { text: '✓ Assigned to on-call Analyst: J. Smith', type: 'success', delay: 2700 },
    ]
  },
  {
    id: 'ransomware-response',
    name: 'Ransomware Response',
    desc: 'Full automated containment of active ransomware: isolate, snapshot, notify, recover.',
    trigger: 'Ransomware Detection',
    steps: [
      { text: '⚠ CRITICAL: Ransomware activity confirmed!', type: 'error', delay: 200 },
      { text: 'Triggering MAJOR INCIDENT protocol...', type: 'warn', delay: 500 },
      { text: 'Isolating affected endpoint immediately...', type: 'warn', delay: 800 },
      { text: 'Blocking attacker IP on all perimeter firewalls...', type: 'warn', delay: 1100 },
      { text: 'Suspending user account associated with incident...', type: 'warn', delay: 1400 },
      { text: 'Initiating VM snapshot of affected host for forensics...', type: 'info', delay: 1800 },
      { text: 'Notifying CISO, SOC Manager, and IR team via PagerDuty...', type: 'info', delay: 2100 },
      { text: 'Creating P1 incident ticket in ServiceNow...', type: 'info', delay: 2400 },
      { text: 'Checking backup availability for recovery...', type: 'info', delay: 2800 },
      { text: '✓ Last clean backup: 4 hours ago — Recovery viable.', type: 'success', delay: 3200 },
      { text: '✓ Incident contained. Recovery process initiated.', type: 'success', delay: 3600 },
    ]
  },
];

function rndId() {
  return Math.random().toString(36).substr(2, 6).toUpperCase();
}

export function runPlaybook(playbookId, terminalEl, onComplete) {
  const pb = PLAYBOOKS.find(p => p.id === playbookId);
  if (!pb) return;

  // Clear terminal
  terminalEl.innerHTML = '';

  appendLine(terminalEl, `$ Executing: ${pb.name}`, 'info', 0);
  appendLine(terminalEl, `$ Triggered at: ${new Date().toLocaleString()}`, 'info', 100);
  appendLine(terminalEl, '─'.repeat(52), 'prompt', 200);

  for (const step of pb.steps) {
    appendLine(terminalEl, step.text, step.type, step.delay + 400);
  }

  const totalTime = Math.max(...pb.steps.map(s => s.delay)) + 1200;
  setTimeout(() => {
    appendLine(terminalEl, '─'.repeat(52), 'prompt', 0);
    appendLine(terminalEl, `$ Playbook completed successfully.`, 'success', 50);
    if (onComplete) onComplete(pb);
  }, totalTime);
}

function appendLine(terminalEl, text, type, delay) {
  setTimeout(() => {
    const line = document.createElement('div');
    line.className = `terminal-line ${type}`;
    line.textContent = text;
    if (type === 'prompt') {
      line.style.color = '#334155';
      line.style.fontSize = '10px';
    }
    terminalEl.appendChild(line);
    terminalEl.scrollTop = terminalEl.scrollHeight;
  }, delay);
}
