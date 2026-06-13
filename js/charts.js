// js/charts.js — Chart.js Chart Initializers & Updaters

const CHART_FONT = "'Inter', system-ui, sans-serif";

const palette = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#3b82f6',
  Low: '#10b981',
  bg: 'rgba(255,255,255,0)',
};

// ── EPS Rolling Chart ─────────────────────────────────────────

export function initEPSChart(canvasId) {
  const ctx = document.getElementById(canvasId).getContext('2d');
  const labels = Array.from({ length: 30 }, (_, i) => '');
  const data = Array(30).fill(0);

  const gradient = ctx.createLinearGradient(0, 0, 0, 200);
  gradient.addColorStop(0, 'rgba(59, 130, 246, 0.22)');
  gradient.addColorStop(1, 'rgba(59, 130, 246, 0.01)');

  return new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'EPS',
        data,
        borderColor: '#3b82f6',
        borderWidth: 2.5,
        backgroundColor: gradient,
        fill: true,
        tension: 0.45,
        pointRadius: 0,
        pointHoverRadius: 5,
        pointHoverBackgroundColor: '#3b82f6',
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 300 },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(255,255,255,0.95)',
          titleColor: '#1e293b',
          bodyColor: '#64748b',
          borderColor: 'rgba(148,163,184,0.3)',
          borderWidth: 1,
          callbacks: {
            label: ctx => ` ${ctx.raw} events/sec`
          }
        }
      },
      scales: {
        x: { display: false },
        y: {
          display: true,
          min: 0,
          grid: { color: 'rgba(148,163,184,0.1)', drawBorder: false },
          ticks: {
            color: '#94a3b8', font: { size: 11, family: CHART_FONT },
            maxTicksLimit: 5,
          }
        }
      }
    }
  });
}

export function updateEPSChart(chart, newValue) {
  chart.data.datasets[0].data.push(newValue);
  chart.data.labels.push('');
  if (chart.data.datasets[0].data.length > 60) {
    chart.data.datasets[0].data.shift();
    chart.data.labels.shift();
  }
  chart.update('none');
}

// ── Category Doughnut Chart ───────────────────────────────────

export function initCategoryChart(canvasId) {
  const ctx = document.getElementById(canvasId).getContext('2d');
  return new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Malware', 'Intrusion', 'DDoS', 'Phishing', 'Exfiltration', 'Ransomware'],
      datasets: [{
        data: [0, 0, 0, 0, 0, 0],
        backgroundColor: [
          'rgba(239,68,68,0.85)',
          'rgba(249,115,22,0.85)',
          'rgba(59,130,246,0.85)',
          'rgba(16,185,129,0.85)',
          'rgba(139,92,246,0.85)',
          'rgba(236,72,153,0.85)',
        ],
        borderColor: 'rgba(255,255,255,0.9)',
        borderWidth: 2.5,
        hoverOffset: 8,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '68%',
      animation: { duration: 500 },
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#64748b',
            font: { size: 11, family: CHART_FONT },
            boxWidth: 10, boxHeight: 10,
            padding: 12,
          }
        },
        tooltip: {
          backgroundColor: 'rgba(255,255,255,0.95)',
          titleColor: '#1e293b',
          bodyColor: '#64748b',
          borderColor: 'rgba(148,163,184,0.3)',
          borderWidth: 1,
        }
      }
    }
  });
}

export function updateCategoryChart(chart, categoryCounts) {
  const labels = ['Malware', 'Intrusion', 'DDoS', 'Phishing', 'Exfiltration', 'Ransomware'];
  chart.data.datasets[0].data = labels.map(l => categoryCounts[l] || 0);
  chart.update();
}

// ── Severity Bar Chart ────────────────────────────────────────

export function initSeverityChart(canvasId) {
  const ctx = document.getElementById(canvasId).getContext('2d');
  return new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        label: 'Alerts',
        data: [0, 0, 0, 0],
        backgroundColor: [
          'rgba(239,68,68,0.80)',
          'rgba(249,115,22,0.80)',
          'rgba(59,130,246,0.80)',
          'rgba(16,185,129,0.80)',
        ],
        borderRadius: 6,
        borderSkipped: false,
        barThickness: 22,
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 400 },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(255,255,255,0.95)',
          titleColor: '#1e293b',
          bodyColor: '#64748b',
          borderColor: 'rgba(148,163,184,0.3)',
          borderWidth: 1,
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(148,163,184,0.1)', drawBorder: false },
          ticks: { color: '#94a3b8', font: { size: 11, family: CHART_FONT } }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#1e293b', font: { size: 12, family: CHART_FONT, weight: '600' } }
        }
      }
    }
  });
}

export function updateSeverityChart(chart, sevCounts) {
  chart.data.datasets[0].data = [
    sevCounts['Critical'] || 0,
    sevCounts['High'] || 0,
    sevCounts['Medium'] || 0,
    sevCounts['Low'] || 0,
  ];
  chart.update();
}

// ── Dynamic Chart Theme Swapper ───────────────────────────────
export function updateChartsTheme(charts, isDark) {
  const textColor = isDark ? '#cbd5e1' : '#1e293b';
  const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(148,163,184,0.1)';
  const axisTicksColor = isDark ? '#94a3b8' : '#64748b';

  // 1. EPS Chart
  if (charts.eps) {
    charts.eps.options.scales.y.grid.color = gridColor;
    charts.eps.options.scales.y.ticks.color = axisTicksColor;
    charts.eps.update('none');
  }

  // 2. Category Chart
  if (charts.category) {
    charts.category.options.plugins.legend.labels.color = axisTicksColor;
    charts.category.data.datasets[0].borderColor = isDark ? 'rgba(15, 23, 42, 0.95)' : 'rgba(255,255,255,0.9)';
    charts.category.update();
  }

  // 3. Severity Chart
  if (charts.severity) {
    charts.severity.options.scales.x.grid.color = gridColor;
    charts.severity.options.scales.x.ticks.color = axisTicksColor;
    charts.severity.options.scales.y.ticks.color = textColor;
    charts.severity.update();
  }
}
