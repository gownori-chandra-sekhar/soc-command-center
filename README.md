# SOC Command Center

> **Industry-grade Security Operations Center monitoring dashboard** with real-time threat intelligence, SIEM alerts, automated SOAR playbook execution, and attack simulation capabilities.

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Status: Active](https://img.shields.io/badge/Status-Active-brightgreen.svg)
![Built with: JavaScript](https://img.shields.io/badge/Built%20with-JavaScript-F7DF1E.svg)

## Overview

SOC Command Center is a comprehensive security operations platform designed for security analysts, incident responders, and SOC teams. It provides a unified dashboard for monitoring threats, triaging alerts, managing threat intelligence, executing automated response playbooks, and simulating attack scenarios for training and validation purposes.

### Core Features

- **🎯 Real-time Monitoring**: Live dashboard with KPI tracking for critical alerts, active incidents, event ingestion rates, and resolution metrics
- **🚨 Alert Triage**: Advanced filtering and management of security alerts with severity classification and status tracking
- **🔍 Threat Intelligence**: IOC (Indicator of Compromise) lookup, live threat feed integration, CVE watchlist monitoring, and MITRE ATT&CK coverage mapping
- **⚙️ SOAR Integration**: Execute automated response playbooks for incident remediation and threat containment
- **🎮 Attack Simulator**: Inject synthetic threat scenarios to test detection rules, train analysts, and validate security controls
- **📊 Visualizations**: Real-time charts for event ingestion rates, incident categorization, and severity breakdown
- **🌓 Dark/Light Mode**: Professional theme toggle for extended operational periods
- **📱 Responsive Design**: Optimized for multi-monitor SOC environments and mobile access

## Quick Start

### Prerequisites
- Modern web browser (Chrome, Firefox, Safari, Edge)
- No server backend required (runs entirely in the browser)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/gownori-chandra-sekhar/soc-command-center.git
   cd soc-command-center
   ```

2. **Open in browser**:
   ```bash
   # Using Python 3
   python -m http.server 8000
   
   # Using Node.js
   npx http-server
   
   # Or simply open index.html directly in your browser
   ```

3. **Access the dashboard**:
   Open `http://localhost:8000` in your browser

## Dashboard Sections

### 1. **Dashboard Overview**
The main operational dashboard featuring:
- **KPI Cards**: Critical alerts, active incidents, events per second (EPS), and resolved cases
- **Live Event Ingestion Chart**: Real-time visualization of security event flow
- **Incident Category Distribution**: Breakdown of threats by type (Malware, Intrusion, DDoS, Phishing, etc.)
- **Severity Analysis**: Distribution of alerts across critical, high, medium, and low severity levels
- **Recent Alerts Feed**: Quick reference to the latest security events

### 2. **Alert Triage**
Comprehensive alert management interface with:
- **Advanced Filtering**: Filter by severity, status (Open/Investigating/Remediated), and incident category
- **Full-text Search**: Search across alert names, IPs, hostnames, and other indicators
- **Alert Details Panel**: Deep-dive analysis of individual alerts with context and recommendations
- **Status Management**: Track investigation progress from discovery to resolution

### 3. **Threat Intelligence**
Integrated threat analysis tools:
- **IOC Lookup**: Search IP addresses, file hashes, and domains against threat databases
- **Live Threat Feed**: Real-time feed of active threats and indicators from security sources
- **CVE Watchlist**: Monitor and track active vulnerability exploits
- **MITRE ATT&CK Coverage**: Map detected threats to the MITRE ATT&CK framework tactics and techniques

### 4. **SOAR Playbooks**
Automated incident response execution:
- **Playbook Library**: Pre-built response procedures for common threat scenarios
- **Execution Console**: Real-time terminal output for playbook execution monitoring
- **Execution History**: Complete audit trail of all automated responses

### 5. **Attack Simulator**
Training and validation platform:
- **Rate Control**: Adjust event ingestion rates (1-200 EPS) for load testing
- **Attack Campaign Launcher**: Inject pre-defined attack scenarios (malware infections, brute force attempts, DDoS attacks, etc.)
- **Live Event Stream**: Raw event stream for analyzing simulated threats
- **Simulator State Management**: Start, stop, and clear operations

## System Architecture

```
┌─────────────────────────────────────────────────┐
│     SOC Command Center (Browser-based)           │
├─────────────────────────────────────────────────┤
│                                                  │
│  ┌──────────────┐  ┌──────────────────────────┐ │
│  │  Dashboard   │  │   Alert Triage Engine    │ │
│  │  - KPIs      │  │   - Filtering & Search   │ │
│  │  - Charts    │  │   - Status Management    │ │
│  └──────────────┘  └──────────────────────────┘ │
│                                                  │
│  ┌──────────────┐  ┌──────────────────────────┐ │
│  │ Threat Intel │  │   SOAR Playbooks         │ │
│  │ - IOC Lookup │  │   - Automation Rules     │ │
│  │ - CVE List   │  │   - Execution Console    │ │
│  │ - MITRE Map  │  │   - Response History     │ │
│  └──────────────┘  └──────────────────────────┘ │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │      Attack Simulator                    │   │
│  │  - Synthetic Event Generation            │   │
│  │  - Campaign Management                   │   │
│  │  - Testing & Validation                  │   │
│  └──────────────────────────────────────────┘   │
│                                                  │
└─────────────────────────────────────────────────┘
```

## Technology Stack

- **Frontend Framework**: Vanilla JavaScript (ES6+)
- **Charting**: Chart.js 4.4.0
- **Styling**: Custom CSS with glass-morphism design
- **Typography**: Inter (UI) and JetBrains Mono (terminal output)
- **Icons**: Inline SVG assets
- **Responsive Design**: Mobile-first CSS Grid and Flexbox

## Usage Examples

### Starting the Simulator

1. Navigate to the **Simulator** section
2. Adjust the **Ingestion Rate (EPS)** slider to control event volume
3. Click **▶ Start** to begin generating synthetic security events
4. Observe real-time alert generation in the Dashboard and Alert Triage views

### Triaging an Alert

1. Go to **Alert Triage** section
2. Use filters to find relevant alerts
3. Click on any alert row to view detailed information in the side panel
4. Update status as investigation progresses
5. Assign recommended SOAR playbooks for automated response

### Performing IOC Lookup

1. Navigate to **Threat Intel**
2. Select IOC type (IP, File Hash, or Domain)
3. Enter the indicator value
4. Click **Lookup** to retrieve threat context
5. Review related CVEs and MITRE ATT&CK tactics

### Running a SOAR Playbook

1. Go to **SOAR Playbooks**
2. Select a playbook from the available list
3. Monitor execution in the Execution Console
4. Review the Execution History for audit trails

## Configuration

The dashboard uses in-memory data storage. To customize:

- **Alert Categories**: Edit categories in the filter dropdowns (see `index.html`)
- **Attack Scenarios**: Modify synthetic attack definitions in `js/app.js`
- **Playbook Definitions**: Update available playbooks and their commands
- **Theme Colors**: Adjust CSS variables in `css/styles.css`

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl/Cmd + K` | Quick command palette |
| `T` | Toggle theme (dark/light) |
| `?` | Help overlay |

## Performance Characteristics

- **Event Processing**: Handles up to 200 events per second (configurable)
- **Alert Storage**: In-memory storage optimized for typical SOC volumes
- **Rendering**: Optimized chart updates with request animation frames
- **Responsiveness**: Sub-100ms interaction latency

## Browser Support

| Browser | Version | Status |
|---------|---------|--------|
| Chrome | 90+ | ✅ Full Support |
| Firefox | 88+ | ✅ Full Support |
| Safari | 14+ | ✅ Full Support |
| Edge | 90+ | ✅ Full Support |

## Project Structure

```
soc-command-center/
├── index.html              # Main HTML structure
├── css/
│   └── styles.css         # Complete styling with dark/light themes
├── js/
│   └── app.js             # Core application logic
└── README.md              # Documentation
```

## Key Components

### Dashboard Controller
Manages KPI calculations, chart rendering, and real-time data updates.

### Alert Manager
Handles alert generation, filtering, searching, and detail panel population.

### Threat Intelligence Engine
Manages IOC lookups, threat feed integration, CVE tracking, and MITRE mapping.

### SOAR Executor
Executes playbooks, manages execution history, and provides console output.

### Event Simulator
Generates synthetic security events based on configurable attack campaigns and EPS rates.

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/gownori-chandra-sekhar/soc-command-center.git
cd soc-command-center

# Start local development server
python -m http.server 8000

# Access at http://localhost:8000
```

### Code Organization

- `index.html`: DOM structure and UI layout
- `css/styles.css`: Component styling, themes, responsive design
- `js/app.js`: Business logic, state management, event handlers

### Adding New Features

1. Add UI elements to `index.html`
2. Style components in `css/styles.css`
3. Implement logic in `js/app.js`
4. Test with the Attack Simulator

## Future Roadmap

- [ ] SIEM Integration (Splunk, ELK Stack, Azure Sentinel)
- [ ] Real-time API endpoints for live data
- [ ] User authentication and role-based access
- [ ] Persistent data storage (SQLite/PostgreSQL backend)
- [ ] Webhook integrations for external systems
- [ ] Advanced analytics and ML-based anomaly detection
- [ ] Mobile native app (React Native)
- [ ] Collaborative incident management
- [ ] Custom playbook builder
- [ ] API-first architecture for integrations

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Steps to Contribute

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style

- Use semantic HTML
- Follow CSS naming conventions (BEM when applicable)
- Use descriptive variable names in JavaScript
- Add comments for complex logic
- Test changes thoroughly in multiple browsers

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or suggestions:
- 📝 [Create an Issue](https://github.com/gownori-chandra-sekhar/soc-command-center/issues)
- 📧 Contact the maintainer
- 💬 Join discussions for feature requests

## Disclaimer

**This is a demonstration and training tool.** It is designed for educational purposes and security training environments. When deploying in production, integrate with your actual SIEM, threat intelligence platforms, and incident response systems.

## Changelog

### Version 1.0.0 (Current)
- Initial release
- Core dashboard with KPI monitoring
- Alert triage and management
- Threat intelligence integration
- SOAR playbook execution
- Attack simulation engine
- Dark/Light theme support

---

**Built with ❤️ for security teams worldwide.**

Made by [@gownori-chandra-sekhar](https://github.com/gownori-chandra-sekhar)
