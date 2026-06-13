// js/simulator.js — Real-time SIEM Event Simulator

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];
const SEV_WEIGHTS = [0.10, 0.25, 0.40, 0.25];

const CATEGORIES = ['Malware', 'Intrusion', 'DDoS', 'Phishing', 'Exfiltration', 'Ransomware'];

const ALERT_TEMPLATES = [
  { name: 'Suspicious PowerShell Execution', cat: 'Malware', sev: 'Critical', mitre: ['T1059.001', 'T1086'], desc: 'Encoded PowerShell command executed via WMI subscription with LOLBAS technique.' },
  { name: 'Lateral Movement via SMB', cat: 'Intrusion', sev: 'High', mitre: ['T1021.002', 'T1550'], desc: 'Abnormal SMB traffic detected between internal hosts indicating potential lateral movement.' },
  { name: 'Ransomware Signature Detected', cat: 'Ransomware', sev: 'Critical', mitre: ['T1486', 'T1490'], desc: 'File system monitoring detected mass file rename operations with unknown extension appended. Possible ransomware encryption.' },
  { name: 'Outbound Data Exfiltration', cat: 'Exfiltration', sev: 'High', mitre: ['T1041', 'T1048'], desc: 'Anomalous outbound DNS query volume to newly registered domain detected from finance workstation.' },
  { name: 'Brute Force Login Attempt', cat: 'Intrusion', sev: 'Medium', mitre: ['T1110'], desc: 'Multiple failed login attempts detected against VPN gateway from single external IP address.' },
  { name: 'Phishing Link Clicked', cat: 'Phishing', sev: 'High', mitre: ['T1566.002', 'T1204.001'], desc: 'User clicked on known malicious URL embedded in spear-phishing email from spoofed domain.' },
  { name: 'DDoS Flood Detected', cat: 'DDoS', sev: 'High', mitre: ['T1498'], desc: 'High-rate SYN flood attack detected on public-facing web server. Packet rate exceeds 1M pps.' },
  { name: 'Privilege Escalation Attempt', cat: 'Intrusion', sev: 'Critical', mitre: ['T1068', 'T1134'], desc: 'Process attempted to abuse SeImpersonatePrivilege via PrintSpoofer technique.' },
  { name: 'Malicious File Download', cat: 'Malware', sev: 'Medium', mitre: ['T1105'], desc: 'A known-bad file hash was downloaded from the internet via browser process.' },
  { name: 'SQL Injection Detected', cat: 'Exfiltration', sev: 'High', mitre: ['T1190', 'T1059.006'], desc: "Web Application Firewall triggered on SQL UNION-based injection in application's search parameter." },
  { name: 'Rogue Admin Account Created', cat: 'Intrusion', sev: 'Critical', mitre: ['T1136.001'], desc: 'New local administrator account created outside of change management process.' },
  { name: 'C2 Beacon Detected', cat: 'Malware', sev: 'Critical', mitre: ['T1071', 'T1132'], desc: 'Regular interval HTTP beaconing to known Cobalt Strike team server detected via Zeek IDS.' },
  { name: 'Credential Dump Attempt', cat: 'Intrusion', sev: 'Critical', mitre: ['T1003.001'], desc: 'LSASS process memory access detected from non-system process, possible Mimikatz execution.' },
  { name: 'Firewall Rule Modified', cat: 'Intrusion', sev: 'Medium', mitre: ['T1562.004'], desc: 'Unauthorized change to Windows Firewall rules to allow inbound traffic on port 4444.' },
  { name: 'Anomalous User Behaviour', cat: 'Exfiltration', sev: 'Low', mitre: ['T1078'], desc: 'UEBA baseline deviation: User logged in from 3 different geographies within a 2-hour window.' },
];

const HOSTNAMES = [
  'WIN-DC01', 'WIN-FS02', 'LINUX-WEB01', 'LINUX-DB01', 'WIN-WS-043',
  'WIN-WS-107', 'MAC-DEV-22', 'WIN-ADMIN01', 'LINUX-MAIL01', 'WIN-WS-055'
];

function randomIP(internal = false) {
  if (internal) {
    return `192.168.${rand(1, 10)}.${rand(10, 250)}`;
  }
  const prefixes = ['45.', '103.', '185.', '91.', '194.', '77.', '51.', '138.'];
  return prefixes[rand(0, prefixes.length - 1)] + rand(1, 254) + '.' + rand(1, 254) + '.' + rand(1, 254);
}

function rand(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function weightedSeverity() {
  const r = Math.random();
  let acc = 0;
  for (let i = 0; i < SEVERITIES.length; i++) {
    acc += SEV_WEIGHTS[i];
    if (r < acc) return SEVERITIES[i];
  }
  return 'Low';
}

function generateAlert(overrideSev = null) {
  const template = ALERT_TEMPLATES[rand(0, ALERT_TEMPLATES.length - 1)];
  const sev = overrideSev || weightedSeverity();
  const now = new Date();
  return {
    id: 'ALT-' + Math.random().toString(36).substr(2, 8).toUpperCase(),
    name: template.name,
    category: template.cat,
    severity: sev,
    sourceIP: randomIP(false),
    destIP: randomIP(true),
    hostname: HOSTNAMES[rand(0, HOSTNAMES.length - 1)],
    timestamp: now,
    timeLabel: now.toLocaleTimeString(),
    status: 'Open',
    mitre: template.mitre,
    description: template.desc,
    rawLog: JSON.stringify({
      event_id: rand(4000, 9999),
      source_ip: randomIP(false),
      dest_ip: randomIP(true),
      protocol: ['TCP', 'UDP', 'ICMP'][rand(0, 2)],
      port: [80, 443, 445, 3389, 22, 8080, 4444][rand(0, 6)],
      bytes_sent: rand(100, 50000),
      bytes_recv: rand(100, 200000),
      action: ['ALERT', 'BLOCK', 'ALLOW'][rand(0, 2)],
      rule_name: template.name.replace(/ /g, '_').toUpperCase(),
      process: ['powershell.exe', 'cmd.exe', 'svchost.exe', 'chrome.exe', 'lsass.exe', 'wscript.exe'][rand(0, 5)],
      user: ['jsmith', 'adavis', 'rjones', 'SYSTEM', 'LOCAL\\Administrator'][rand(0, 4)]
    }, null, 2)
  };
}

function generateStreamLine(eps) {
  const sev = weightedSeverity();
  const ts = new Date().toLocaleTimeString();
  const tmpl = ALERT_TEMPLATES[rand(0, ALERT_TEMPLATES.length - 1)];
  return { ts, sev, msg: `[${randomIP(false)}] → [${randomIP(true)}] ${tmpl.name}`, raw: tmpl.name };
}

// ── Attack Campaign Presets ────────────────────────────────────

export const ATTACK_CAMPAIGNS = [
  {
    id: 'ransomware',
    name: 'Ransomware Outbreak',
    icon: '🔐',
    desc: 'Simulates a multi-stage ransomware attack with lateral movement and file encryption.',
    color: 'red',
    alerts: [
      { ...ALERT_TEMPLATES[5], severity: 'High' },   // Phishing
      { ...ALERT_TEMPLATES[1], severity: 'High' },   // Lateral
      { ...ALERT_TEMPLATES[12], severity: 'Critical' }, // Credential dump
      { ...ALERT_TEMPLATES[2], severity: 'Critical' }, // Ransomware
    ]
  },
  {
    id: 'ddos',
    name: 'DDoS Attack',
    icon: '🌊',
    desc: 'High-volume SYN flood from distributed botnet targeting your public infrastructure.',
    color: 'orange',
    alerts: Array.from({ length: 12 }, () => ({ ...ALERT_TEMPLATES[6], severity: 'High', sourceIP: randomIP(false) }))
  },
  {
    id: 'sql_injection',
    name: 'SQL Injection & Exfil',
    icon: '💉',
    desc: 'UNION-based SQL injection attack followed by mass data exfiltration over DNS tunnel.',
    color: 'blue',
    alerts: [
      { ...ALERT_TEMPLATES[9], severity: 'High' },
      { ...ALERT_TEMPLATES[3], severity: 'High' },
    ]
  },
  {
    id: 'phishing_cred',
    name: 'Phishing & Compromise',
    icon: '🎣',
    desc: 'Spear-phishing email leads to credential theft and unauthorized admin account creation.',
    color: 'purple',
    alerts: [
      { ...ALERT_TEMPLATES[5], severity: 'High' },
      { ...ALERT_TEMPLATES[11], severity: 'Critical' },
      { ...ALERT_TEMPLATES[10], severity: 'Critical' },
    ]
  },
  {
    id: 'apt',
    name: 'APT Intrusion',
    icon: '👤',
    desc: 'Simulated Advanced Persistent Threat with C2 beaconing, privilege escalation, and persistence.',
    color: 'red',
    alerts: [
      { ...ALERT_TEMPLATES[11], severity: 'Critical' },
      { ...ALERT_TEMPLATES[7], severity: 'Critical' },
      { ...ALERT_TEMPLATES[12], severity: 'Critical' },
      { ...ALERT_TEMPLATES[3], severity: 'High' },
    ]
  },
  {
    id: 'insider',
    name: 'Insider Threat',
    icon: '🕵️',
    desc: 'Anomalous user behavior: off-hours data access, geo-anomaly, and mass download.',
    color: 'green',
    alerts: [
      { ...ALERT_TEMPLATES[14], severity: 'Medium' },
      { ...ALERT_TEMPLATES[3], severity: 'High' },
    ]
  },
];

// ── Simulator Class ────────────────────────────────────────────

export class Simulator {
  constructor(onAlert, onStream) {
    this.onAlert = onAlert;
    this.onStream = onStream;
    this.eps = 10;
    this.running = false;
    this._interval = null;
  }

  setEPS(eps) {
    let val = parseInt(eps);
    if (isNaN(val) || val <= 0) {
      val = 10;
    } else if (val > 1000) {
      val = 1000;
    }
    this.eps = val;
    if (this.running) {
      this.stop();
      this.start();
    }
  }

  start() {
    if (this.running) return;
    this.running = true;
    const intervalMs = Math.max(200, Math.floor(1000 / this.eps));
    this._interval = setInterval(() => {
      const alert = generateAlert();
      this.onAlert(alert);
      this.onStream(generateStreamLine(this.eps));
    }, intervalMs);
  }

  stop() {
    this.running = false;
    clearInterval(this._interval);
    this._interval = null;
  }

  injectCampaign(campaign) {
    let delay = 0;
    for (const tmpl of campaign.alerts) {
      setTimeout(() => {
        const alert = generateAlert(tmpl.severity);
        alert.name = tmpl.name;
        alert.category = tmpl.cat;
        alert.description = tmpl.desc;
        alert.mitre = tmpl.mitre;
        this.onAlert(alert);
        this.onStream({ ts: new Date().toLocaleTimeString(), sev: alert.severity, msg: `[CAMPAIGN] ${alert.name} — ${alert.sourceIP}` });
      }, delay);
      delay += rand(300, 800);
    }
  }
}

export { generateAlert, generateStreamLine, rand };
