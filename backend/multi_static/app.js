// --- Configuration ---
const API_BASE = "";
const PING_INTERVAL = 120; // Seconds

// --- State ---
let timeLeft = PING_INTERVAL;
let performanceChart = null;
let infraHealthChart = null;
let infraLatencyChart = null;
let analyticsDistributionChart = null;
let currentWorkspaceFilter = null; // null, 'prod', or 'staging'
let latestWorkspaceStatusResults = [];
let previousInfraSnapshot = null;
let previousAnalyticsSnapshot = null;

// --- Elements ---
let domInput, addBtn, statusTable, timerEl, historyRange, countTotal, countOnline, countOffline, valLatency, toastEl;

function authToken() { return localStorage.getItem('uptrixAccessToken') || ''; }
function authRole() { return localStorage.getItem('uptrixRole') || 'Guest'; }
function demoMode() { return !authToken() || authRole() === 'Guest'; }
function apiFetch(url, options = {}) {
    const headers = new Headers(options.headers || {});
    if (authToken()) headers.set('Authorization', `Bearer ${authToken()}`);
    return fetch(url, { ...options, headers });
}

function updateAccessUI() {
    const role = authRole();
    const demo = demoMode();
    const context = document.getElementById('accessContext');
    const button = document.getElementById('accessButton');
    const form = document.getElementById('authForm');
    if (context) context.textContent = demo ? 'Public demo · read only' : `Signed in · ${role}`;
    if (button) button.textContent = demo ? 'Sign in' : 'Sign out';
    if (form && !demo) form.classList.add('hidden');
    const canWrite = role === 'Admin' || role === 'Operator';
    const actionBar = document.querySelector('.infra-action-bar');
    if (actionBar) actionBar.style.setProperty('display', 'flex', 'important');
    const domainField = document.getElementById('domainInput');
    if (domainField) {
        domainField.disabled = !canWrite;
        domainField.placeholder = canWrite ? 'Enter domains (e.g. example.com)' : demo ? 'Sign in to add a website' : 'Read-only access';
    }
}

async function refreshSignedInRole() {
    if (!authToken()) return;
    try {
        const response = await apiFetch('/api/auth/me');
        if (!response.ok) throw new Error('Session no longer valid');
        const user = await response.json();
        localStorage.setItem('uptrixRole', user.role);
        localStorage.setItem('uptrixUsername', user.username);
    } catch (_) {
        localStorage.removeItem('uptrixAccessToken');
        localStorage.removeItem('uptrixRole');
        localStorage.removeItem('uptrixUsername');
    }
}

window.toggleAuthForm = function () {
    if (!demoMode()) {
        localStorage.removeItem('uptrixAccessToken');
        localStorage.removeItem('uptrixRole');
        localStorage.removeItem('uptrixUsername');
        updateAccessUI();
        fetchStatus(); fetchHistory();
        return;
    }
    document.getElementById('authForm')?.classList.toggle('hidden');
};

window.submitLogin = async function (event) {
    event.preventDefault();
    try {
        const response = await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: document.getElementById('authUsername').value, password: document.getElementById('authPassword').value }) });
        const data = await response.json();
        if (!response.ok) { showToast(data.detail || 'Sign in failed'); return; }
        localStorage.setItem('uptrixAccessToken', data.access_token);
        localStorage.setItem('uptrixRole', data.role);
        localStorage.setItem('uptrixUsername', data.username);
        updateAccessUI(); fetchStatus(); fetchHistory();
        showToast(`Signed in as ${data.role}`);
    } catch (_) { showToast('Sign in service unavailable'); }
};

document.addEventListener('DOMContentLoaded', () => {
    domInput = document.getElementById('domainInput');
    addBtn = document.getElementById('addBtn');
    statusTable = document.getElementById('statusTable');
    timerEl = document.getElementById('timer');
    historyRange = document.getElementById('historyRange');
    countTotal = document.getElementById('count-total');
    countOnline = document.getElementById('count-online');
    countOffline = document.getElementById('count-offline');
    valLatency = document.getElementById('val-latency');
    toastEl = document.getElementById('toast');
});

// --- Helper Functions ---
// --- Core Engine ---

async function fetchStatus() {
    try {
        const resp = await apiFetch(demoMode() ? '/api/demo/status' : '/api/status');
        if (!resp.ok) throw new Error(`Status request failed (${resp.status})`);
        const data = await resp.json();
        renderStatus(data);
        return data;
    } catch (e) {
        showToast("Backend connection failed or Unauthorized");
        return null;
    }
}

async function fetchHistory() {
    try {
        if (!historyRange) return;
        const range = historyRange.value;
        const path = demoMode() ? `/api/demo/history?range=${range}` : `/api/history?range=${range}`;
        const resp = await apiFetch(path);
        if (resp.status === 401 || resp.status === 422) return;
        const history = await resp.json();
        updateChart(history);
    } catch (e) {
        console.error("History fetch failed", e);
    }
}

function renderStatus(data) {
    const tbody = document.getElementById('statusTable');
    if (!tbody) return;
    latestWorkspaceStatusResults = Array.isArray(data.results) ? data.results : [];

    if (!data.results || data.results.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 3rem; color: #848d97;">No domains configured. Enter domains above to start monitoring.</td></tr>';
        renderOverview({ results: [], summary: { total: 0, online: 0, offline: 0, avg_latency: 0 } });
        updateInfraVisuals({ results: [], summary: { total: 0, online: 0, offline: 0, avg_latency: 0 } });
        renderWebsiteWorkspace(latestWorkspaceStatusResults);
        return;
    }
    
    tbody.innerHTML = data.results.map(res => {
        const isUp = res.status === 'UP';
        const isPending = res.status === 'PENDING';
        // Build full date+time for Last Check
        const now = new Date();
        const dateStr = now.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
        const timeStr = data.summary.last_ping || now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const timestamp = `${dateStr}, ${timeStr}`;
        // SSL expiry display
        const isHttps = res.url && res.url.startsWith('https');
        const sslDisplay = res.ssl_expiry 
            ? escapeHtml(res.ssl_expiry) 
            : (isHttps ? '<span style="color:#f59e0b;">Checking...</span>' : '<span style="color:#94a3b8;">HTTP Only</span>');
        const latencyValue = Number(res.latency || 0);
        const latencyWidth = Math.max(8, Math.min(100, Math.round((latencyValue / 800) * 100)));
        const cleanUrl = escapeHtml(res.url || '');
        const cleanStatus = escapeHtml(res.status || '');
        const cleanReason = escapeHtml(res.failure_analysis || res.reason || 'OK');
        const rootCauses = Array.isArray(res.root_causes) ? res.root_causes : [];
        const diagnosis = rootCauses.length
            ? `
                <div class="rca-summary">
                    <strong>${escapeHtml(res.failure_analysis || 'Website requires attention because:')}</strong>
                    ${rootCauses.map(cause => `
                        <span class="rca-cause" title="${escapeHtml(cause.detail || '')}">
                            ${escapeHtml(cause.label || 'Unknown cause')}
                        </span>
                    `).join('')}
                </div>
            `
            : cleanReason;
        
        const removeAction = authRole() === 'Admin'
            ? `<button onclick="removeDomain('${jsStringEscape(res.url || '')}')" style="background:#fee2e2;color:#ef4444;border:0;padding:5px 10px;border-radius:5px;font-size:.75rem;font-weight:800;cursor:pointer;">Remove</button>`
            : '<span>—</span>';
        return `
            <tr>
                <td>
                    <div style="font-weight: 800; color: #0f172a; white-space: nowrap;">${cleanUrl}</div>
                    <div style="font-size: 0.68rem; color: #94a3b8; font-weight: 600;">${escapeHtml(res.status_code || '---')}</div>
                </td>
                <td style="white-space: nowrap;">
                    <span class="status-chip ${isUp ? 'up' : isPending ? 'pending' : 'down'}">
                        <b></b>
                        ${cleanStatus}
                    </span>
                </td>
                <td style="font-weight: 800; color: #0f172a; white-space: nowrap;">
                    <span class="latency-bar">
                        ${res.latency ? res.latency + 'ms' : '--'}
                        <span class="latency-track"><span style="width:${latencyWidth}%;"></span></span>
                    </span>
                </td>
                <td style="font-weight: 700; color: #475569; white-space: nowrap;">${sslDisplay}</td>
                <td style="font-weight: 700; color: #475569;">${diagnosis}</td>
                <td style="color: #2563eb; font-weight: 800; white-space: nowrap; font-size: 0.8rem;">${timestamp}</td>
                <td>
                    ${removeAction}
                </td>
            </tr>
        `;
    }).join('');

    const countTotal = document.getElementById('count-total');
    const countOnline = document.getElementById('count-online');
    const countOffline = document.getElementById('count-offline');
    const valLatency = document.getElementById('val-latency');

    if (countTotal) countTotal.textContent = data.summary.total;
    if (countOnline) countOnline.textContent = data.summary.online;
    if (countOffline) countOffline.textContent = data.summary.offline;
    if (valLatency) valLatency.textContent = data.summary.avg_latency + 'ms';
    renderOverview(data);
    updateInfraVisuals(data);
    renderWebsiteWorkspace(latestWorkspaceStatusResults);
}

function renderOverview(data) {
    const results = Array.isArray(data.results) ? data.results : [];
    const summary = data.summary || {};
    const total = Number(summary.total ?? results.length);
    const online = Number(summary.online ?? results.filter(row => row.status === 'UP').length);
    const offline = Number(summary.offline ?? Math.max(0, total - online));
    const avgLatency = Number(summary.avg_latency || 0);
    const availability = total ? Math.round((online / total) * 100) : 0;
    const lastCheck = summary.last_ping || 'Waiting for checks';

    setText('overviewTotal', String(total));
    setText('overviewOnline', String(online));
    setText('overviewOffline', String(offline));
    setText('overviewLatency', `${Math.round(avgLatency)}ms`);
    setText('overviewLastCheck', lastCheck);
    setText('overviewAvailability', `${availability}%`);
    setText('overviewHealthyCount', String(online));
    setText('overviewOfflineLegend', String(offline));
    setText('overviewAttentionCount', String(offline));

    const healthFill = document.getElementById('overviewHealthFill');
    if (healthFill) healthFill.style.width = `${availability}%`;
    setText('overviewHealthNote', total
        ? `${online} of ${total} monitored websites are responding${offline ? `; ${offline} need attention.` : '.'}`
        : 'Add a website to start monitoring your fleet.');

    const attentionList = document.getElementById('overviewAttentionList');
    if (!attentionList) return;
    const attentionRows = results.filter(row => row.status !== 'UP');
    if (!total) {
        attentionList.innerHTML = '<div class="overview-empty"><i class="fa-solid fa-globe"></i><strong>No websites yet</strong><span>Add a website in Infrastructure Status to begin monitoring.</span></div>';
    } else if (!attentionRows.length) {
        attentionList.innerHTML = '<div class="overview-empty is-healthy"><i class="fa-solid fa-circle-check"></i><strong>All monitored websites are operational</strong><span>No services currently need attention.</span></div>';
    } else {
        attentionList.innerHTML = attentionRows.slice(0, 4).map(row => `
            <div class="overview-attention-row">
                <span class="overview-attention-icon ${row.status === 'PENDING' ? 'is-pending' : ''}"><i class="fa-solid ${row.status === 'PENDING' ? 'fa-clock' : 'fa-triangle-exclamation'}"></i></span>
                <div class="overview-attention-copy"><strong>${escapeHtml(cleanServiceName(row.url || 'Website'))}</strong><span>${escapeHtml(row.failure_analysis || row.reason || (row.status === 'PENDING' ? 'First check is in progress.' : 'Check the website connection.'))}</span></div>
                <span class="overview-status-label ${row.status === 'PENDING' ? 'is-pending' : ''}">${escapeHtml(row.status || 'DOWN')}</span>
            </div>
        `).join('');
        if (attentionRows.length > 4) {
            attentionList.insertAdjacentHTML('beforeend', `<button class="overview-link-button" type="button" onclick="showSection('infrastructure')">View ${attentionRows.length - 4} more in Infrastructure Status <i class="fa-solid fa-arrow-right"></i></button>`);
        }
    }
}

function renderWebsiteWorkspace(results = latestWorkspaceStatusResults) {
    const grid = document.getElementById('workspaceSiteGrid');
    if (!grid) return;

    if (currentWorkspaceFilter) {
        results = results.filter((site) => {
            const url = String(site.url || '').toLowerCase();
            const staging = /(staging|stage|local|localhost|127\.0\.0\.1|dev|test|qa)/.test(url);
            return currentWorkspaceFilter === 'staging' ? staging : !staging;
        });
    }

    if (!results.length) {
        grid.innerHTML = '<div class="workspace-empty">No websites are being monitored yet. Add one from Website Status to create its dashboard.</div>';
        return;
    }

    grid.innerHTML = results.map((site) => {
        const url = String(site.url || '');
        const target = /^https?:\/\//i.test(url) ? url : `https://${url}`;
        const status = String(site.status || 'PENDING').toUpperCase();
        const tone = status === 'UP' ? 'up' : status === 'PENDING' ? 'pending' : 'down';
        const latency = Number(site.latency || 0);
        return `<article class="workspace-site-card">
            <div class="workspace-site-heading">
                <div><span class="workspace-site-label">Website dashboard</span><h2>${escapeHtml(url)}</h2></div>
                <span class="status-chip ${tone}"><b></b>${escapeHtml(status)}</span>
            </div>
            <div class="workspace-site-metrics">
                <div><span>Response time</span><strong>${latency ? `${latency} ms` : status === 'PENDING' ? 'Checking' : '--'}</strong></div>
                <div><span>SSL certificate</span><strong>${escapeHtml(site.ssl_expiry || 'Checking...')}</strong></div>
                <div><span>HTTP status</span><strong>${escapeHtml(site.status_code || '---')}</strong></div>
            </div>
            <p class="workspace-site-reason">${escapeHtml(site.failure_analysis || site.reason || 'Waiting for the first check.')}</p>
            <a class="workspace-site-open" href="${escapeHtml(target)}" target="_blank" rel="noopener noreferrer">Open website <i class="fa-solid fa-arrow-up-right-from-square"></i></a>
        </article>`;
    }).join('');
}

window.showWorkspaceGroup = function (group) {
    currentWorkspaceFilter = group;
    window.showSection('workspace');
};

async function refreshNewWebsite(url, attempts = 20) {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const data = await fetchStatus();
        const result = data?.results?.find((site) => site.url === url);
        if (result && result.status !== 'PENDING') return;
    }
}


function updateMetrics(summary) { }

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function jsStringEscape(value) {
    return String(value)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r');
}

function ensureInfraCharts() {
    if (typeof Chart === 'undefined') return;

    const healthCanvas = document.getElementById('infraHealthChart');
    if (healthCanvas && !infraHealthChart) {
        infraHealthChart = new Chart(healthCanvas.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Operational', 'Offline'],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: ['#10b981', '#dc2626'],
                    borderWidth: 0,
                    hoverOffset: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            usePointStyle: true,
                            boxWidth: 8,
                            color: '#475569',
                            font: { family: 'Plus Jakarta Sans', size: 10, weight: '700' }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: context => `${context.label}: ${context.raw}`
                        }
                    }
                }
            }
        });
    }

    const latencyCanvas = document.getElementById('infraLatencyChart');
    if (latencyCanvas && !infraLatencyChart) {
        infraLatencyChart = new Chart(latencyCanvas.getContext('2d'), {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Latency ms',
                    data: [],
                    backgroundColor: '#2563eb',
                    borderRadius: 5,
                    borderSkipped: false,
                    maxBarThickness: 28
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                layout: {
                    padding: { left: 6, right: 12 }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: 'rgba(148, 163, 184, 0.18)' },
                        ticks: { color: '#64748b', font: { size: 10, weight: '700' } }
                    },
                    y: {
                        grid: { display: false },
                        ticks: {
                            autoSkip: false,
                            color: '#334155',
                            padding: 6,
                            font: { size: 10, weight: '700' },
                            callback: function(value) {
                                const label = this.getLabelForValue(value);
                                return label.length > 26 ? `${label.slice(0, 23)}...` : label;
                            }
                        }
                    }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: context => `${context.raw}ms`
                        }
                    }
                }
            }
        });
    }
}

function updateInfraVisuals(data) {
    const summary = data.summary || {};
    const results = Array.isArray(data.results) ? data.results : [];
    const total = Number(summary.total || results.length || 0);
    const online = Number(summary.online || results.filter(r => r.status === 'UP').length || 0);
    const offline = Number(summary.offline || Math.max(total - online, 0));
    const avgLatency = Number(summary.avg_latency || 0);
    const availability = total > 0 ? Math.round((online / total) * 100) : 0;
    const ringDegrees = Math.round((availability / 100) * 360);

    const availabilityScore = document.getElementById('availabilityScore');
    const heroRing = document.getElementById('heroRing');
    const heroRingValue = document.getElementById('heroRingValue');
    const slaScore = document.getElementById('slaScore');
    const slaStatus = document.getElementById('slaStatus');
    const slaMeterFill = document.getElementById('slaMeterFill');
    const topologyHealthy = document.getElementById('topologyHealthy');
    const topologyRisk = document.getElementById('topologyRisk');
    const tableSummaryBadge = document.getElementById('tableSummaryBadge');
    const latencyPosture = document.getElementById('latencyPosture');

    if (availabilityScore) availabilityScore.textContent = `${availability}%`;
    if (heroRing) heroRing.style.setProperty('--ring', `${ringDegrees}deg`);
    if (heroRingValue) heroRingValue.textContent = `${availability}%`;
    if (slaScore) slaScore.textContent = `${availability}%`;
    if (slaMeterFill) slaMeterFill.style.width = `${availability}%`;
    if (topologyHealthy) topologyHealthy.textContent = `${online} healthy`;
    if (topologyRisk) topologyRisk.textContent = `${offline} at risk`;
    if (tableSummaryBadge) tableSummaryBadge.textContent = total ? `${online}/${total} services operational` : 'No telemetry';
    if (latencyPosture) {
        latencyPosture.textContent = avgLatency > 500 ? 'High latency risk' : avgLatency > 250 ? 'Moderate latency' : avgLatency > 0 ? 'Healthy response' : 'Waiting for checks';
    }
    if (slaStatus) {
        slaStatus.textContent = availability >= 99 ? 'Enterprise target met' : availability >= 90 ? 'Stable with attention needed' : availability > 0 ? 'Incident review required' : 'Awaiting telemetry';
    }

    ensureInfraCharts();

    if (infraHealthChart) {
        infraHealthChart.data.datasets[0].data = [online, offline];
        infraHealthChart.update();
    }

    if (infraLatencyChart) {
        const latencyRows = results
            .slice()
            .sort((a, b) => Number(b.latency || 0) - Number(a.latency || 0));
        const latencyStage = document.querySelector('.mini-chart-stage');
        if (latencyStage) {
            latencyStage.style.height = `${Math.max(190, latencyRows.length * 28 + 44)}px`;
            infraLatencyChart.resize();
        }
        infraLatencyChart.data.labels = latencyRows.map(res => String(res.url || '').replace(/^https?:\/\//i, ''));
        infraLatencyChart.data.datasets[0].data = latencyRows.map(res => Number(res.latency || 0));
        infraLatencyChart.data.datasets[0].backgroundColor = latencyRows.map(res => res.status === 'UP' ? '#2563eb' : '#dc2626');
        infraLatencyChart.update();
    }

    updateInfraDecisionLayer({ results, total, online, offline, avgLatency, availability });
}

function updateInfraDecisionLayer(snapshot) {
    const { results, total, online, offline, avgLatency, availability } = snapshot;
    const previous = previousInfraSnapshot;
    const changedOffline = previous ? offline - previous.offline : 0;
    const changedLatency = previous ? avgLatency - previous.avgLatency : 0;
    const highLatencyRows = results.filter(row => Number(row.latency || 0) >= 1000 && row.status === 'UP');
    const warningCount = highLatencyRows.length + results.filter(row => /ssl|cert|timeout|error/i.test(String(row.reason || ''))).length;
    const activeIncidents = offline;
    const worst = results
        .slice()
        .sort((a, b) => {
            const aDown = a.status === 'DOWN' ? 1 : 0;
            const bDown = b.status === 'DOWN' ? 1 : 0;
            return (bDown - aDown) || (Number(b.latency || 0) - Number(a.latency || 0));
        })[0];

    const healthState = total === 0
        ? 'No telemetry'
        : offline > 0
            ? 'Degraded'
            : avgLatency >= 1000
                ? 'Latency Risk'
                : 'Healthy';
    const nextAction = offline > 0
        ? 'Triage offline services'
        : avgLatency >= 1000
            ? 'Investigate latency'
            : warningCount > 0
                ? 'Review warnings'
                : 'Monitor fleet';
    const nextContext = worst
        ? `${cleanServiceName(worst.url || '')} ${worst.status === 'DOWN' ? 'is offline' : `${Math.round(Number(worst.latency || 0))}ms`}`
        : 'No service risk detected';

    setText('systemHealthState', healthState);
    setText('systemHealthContext', total ? `${online}/${total} operational - ${availability}% availability` : 'Add monitored endpoints');
    setText('activeIncidentCount', String(activeIncidents));
    setText('activeIncidentContext', changedOffline > 0 ? `+${changedOffline} since last refresh` : activeIncidents ? 'Immediate response required' : 'No current outages');
    setText('warningCount', String(warningCount));
    setText('warningContext', changedLatency > 0 ? `Latency up ${Math.round(changedLatency)}ms` : warningCount ? 'Thresholds breached' : 'No warning thresholds breached');
    setText('nextActionText', nextAction);
    setText('nextActionContext', nextContext);

    setStatusClass('systemHealthCard', offline > 0 ? 'critical' : avgLatency >= 1000 ? 'warning' : total ? 'normal' : 'neutral');
    setStatusClass('activeIncidentCard', activeIncidents > 0 ? 'critical' : 'normal');
    setStatusClass('warningCard', warningCount > 0 ? 'warning' : 'normal');
    setStatusClass('nextActionCard', activeIncidents > 0 ? 'critical' : warningCount > 0 || avgLatency >= 1000 ? 'warning' : 'normal');

    setStatusClass('kpiTotalCard', total ? 'neutral' : 'warning');
    setStatusClass('kpiOnlineCard', offline > 0 ? 'warning' : total ? 'normal' : 'neutral');
    setStatusClass('kpiOfflineCard', offline > 0 ? 'critical' : 'normal');
    setStatusClass('kpiLatencyCard', avgLatency >= 1000 ? 'critical' : avgLatency >= 500 ? 'warning' : avgLatency > 0 ? 'normal' : 'neutral');
    setText('totalKpiContext', previous ? `${formatSigned(total - previous.total)} vs last refresh` : 'Monitored endpoints');
    setText('onlineKpiContext', previous ? `${formatSigned(online - previous.online)} healthy change` : 'Healthy services');
    setText('offlineKpiContext', offline ? `${offline} requires action` : 'No offline services');

    renderInfraIntelligence(results, { activeIncidents, warningCount, avgLatency, availability, worst, highLatencyRows });
    previousInfraSnapshot = { total, online, offline, avgLatency };
}

function renderInfraIntelligence(results, meta) {
    const grid = document.getElementById('infraIntelGrid');
    const badge = document.getElementById('intelPriorityBadge');
    if (!grid) return;

    const issues = [];
    const offlineRows = results.filter(row => row.status === 'DOWN');
    offlineRows.slice(0, 3).forEach(row => {
        issues.push({
            tone: 'critical',
            title: 'Critical issue',
            value: cleanServiceName(row.url),
                detail: row.failure_analysis || row.reason || 'Service is unreachable',
            action: 'Start incident triage'
        });
    });

    meta.highLatencyRows
        .slice()
        .sort((a, b) => Number(b.latency || 0) - Number(a.latency || 0))
        .slice(0, 2)
        .forEach(row => {
            issues.push({
                tone: 'warning',
                title: 'Latency risk',
                value: cleanServiceName(row.url),
                detail: `${Math.round(Number(row.latency || 0))}ms response time`,
                action: 'Check upstream path'
            });
        });

    if (!issues.length && results.length) {
        issues.push({
            tone: 'normal',
            title: 'Fleet posture',
            value: `${meta.availability}% available`,
            detail: meta.avgLatency ? `Average latency ${Math.round(meta.avgLatency)}ms` : 'No latency risk detected',
            action: 'Continue monitoring'
        });
    }

    if (badge) {
        badge.textContent = meta.activeIncidents ? `${meta.activeIncidents} critical` : meta.warningCount ? `${meta.warningCount} warnings` : 'No active risk';
        badge.className = `table-badge ${meta.activeIncidents ? 'badge-critical' : meta.warningCount ? 'badge-warning' : 'badge-normal'}`;
    }

    grid.innerHTML = issues.length
        ? issues.map(item => `
            <article class="intel-card ${item.tone}">
                <span>${escapeHtml(item.title)}</span>
                <strong>${escapeHtml(item.value)}</strong>
                <p>${escapeHtml(item.detail)}</p>
                <small>${escapeHtml(item.action)}</small>
            </article>
        `).join('')
        : '<div class="intel-empty">Awaiting live telemetry...</div>';
}

async function addDomains() {
    if (demoMode()) {
        document.getElementById('authForm')?.classList.remove('hidden');
        document.getElementById('authUsername')?.focus();
        showToast('Sign in with an Admin or Operator account to add websites.');
        return;
    }
    if (!['Admin', 'Operator'].includes(authRole())) { showToast('Your account has read-only access.'); return; }
    const urls = domInput.value.trim();
    if (!urls) return;

    addBtn.disabled = true;
    try {
        const existingSites = new Set(latestWorkspaceStatusResults.map((site) => site.url));
        const url = `/api/domains?urls=${encodeURIComponent(urls)}`;
        const resp = await apiFetch(url, { method: 'POST' });
        const data = await resp.json();

        if (resp.status !== 200) {
            showToast(data.detail || "Failed to add domain");
        } else {
            domInput.value = '';
            const addedSites = (data.current_list || []).filter((site) => !existingSites.has(site));
            await fetchStatus();
            fetchHistory();
            window.showSection('workspace');
            showToast('Website added. Its dashboard is ready and the first check is running.');
            addedSites.forEach((site) => refreshNewWebsite(site));
        }
    } catch (e) {
        showToast("Network Error");
    } finally {
        addBtn.disabled = false;
    }
}

async function removeDomain(url) {
    if (authRole() !== 'Admin' || demoMode()) { showToast('Only Admins can remove websites.'); return; }
    if (!confirm(`Are you sure you want to stop monitoring ${url}?`)) return;

    try {
        const fetchUrl = `/api/domains/remove?url=${encodeURIComponent(url)}`;
        const resp = await apiFetch(fetchUrl, { method: 'POST' });
        if (resp.status === 200) {
            fetchStatus();
            fetchHistory();
            showToast("Website removed successfully.");
        } else {
            const err = await resp.json();
            showToast(err.detail || "Unable to remove website.");
        }
    } catch (e) {
        showToast("Communication error with server.");
    }
}

// Register Plugins
try {
    const plugins = [];
    if (typeof ChartDataLabels !== 'undefined') plugins.push(ChartDataLabels);
    if (typeof ChartAnnotation !== 'undefined') plugins.push(ChartAnnotation);
    if (typeof ChartZoom !== 'undefined') plugins.push(ChartZoom);
    if (plugins.length > 0) Chart.register(...plugins);
} catch (e) {
    console.warn('Advanced Chart plugins registration failed:', e);
}

if (typeof Chart !== 'undefined') {
    Chart.defaults.font.family = 'Plus Jakarta Sans';
    Chart.defaults.font.size = 10;
    Chart.defaults.color = '#64748b';
}

function initChart() {
    const ctx = document.getElementById('performanceChart').getContext('2d');
    performanceChart = new Chart(ctx, {
        type: 'line',
        data: { labels: [], datasets: [] },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            layout: {
                padding: {
                    right: 112,
                    top: 8
                }
            },
            interaction: { intersect: false, mode: 'index' },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(148, 163, 184, 0.16)' },
                    ticks: { color: '#64748b', font: { size: 10, weight: '800' } },
                    title: { display: true, text: 'Latency (ms)', color: '#334155', font: { size: 10, weight: '900' } }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#64748b', font: { size: 10, weight: '800' } }
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom',
                    labels: {
                         color: '#1a2332',
                         padding: 14,
                         usePointStyle: true,
                         pointStyle: 'circle',
                         boxWidth: 10,
                         font: { family: 'Plus Jakarta Sans', size: 10, weight: '700' }
                    },
                    onClick: (e, legendItem, legend) => {
                        const index = legendItem.datasetIndex;
                        const ci = legend.chart;
                        if (e.native.shiftKey) {
                            const isSolo = ci.data.datasets.every((ds, i) => i === index || ds.hidden === true);
                            ci.data.datasets.forEach((ds, i) => {
                                ds.hidden = isSolo ? false : (i !== index);
                            });
                        } else {
                            ci.setDatasetVisibility(index, !ci.isDatasetVisible(index));
                        }
                        ci.update();
                    }
                },
                tooltip: { enabled: false },
                zoom: {
                    pan: { enabled: true, mode: 'x', threshold: 10 },
                    zoom: {
                        wheel: { enabled: true },
                        pinch: { enabled: true },
                        mode: 'x'
                    }
                },
                annotation: { annotations: {} },
                datalabels: { display: false }
            }
        },
        plugins: [ChartDataLabels, {
            id: 'rightSideLabels',
            afterDraw(chart) {
                const {ctx, data, chartArea: {right, top, bottom}} = chart;
                const LINE_HEIGHT = 15;
                const labels = [];

                data.datasets.forEach((dataset, i) => {
                    if (chart.isDatasetVisible(i)) {
                        const meta = chart.getDatasetMeta(i);
                        const lastPoint = meta.data.filter(p => !p.skip).pop();
                        if (lastPoint && lastPoint.y !== undefined) {
                            labels.push({
                                y: lastPoint.y,          // actual pixel Y of line
                                drawY: lastPoint.y,      // will be adjusted
                                text: dataset.label,
                                color: dataset.borderColor
                            });
                        }
                    }
                });

                if (labels.length === 0) return;

                // Sort by actual Y position (top to bottom)
                labels.sort((a, b) => a.y - b.y);

                // Bidirectional spread: push apart while respecting chart bounds
                let maxIterations = 50;
                while (maxIterations-- > 0) {
                    let moved = false;
                    for (let i = 1; i < labels.length; i++) {
                        if (labels[i].drawY - labels[i-1].drawY < LINE_HEIGHT) {
                            const overlap = LINE_HEIGHT - (labels[i].drawY - labels[i-1].drawY);
                            labels[i-1].drawY -= overlap / 2;
                            labels[i].drawY   += overlap / 2;
                            moved = true;
                        }
                    }
                    // Clamp all within chart area
                    labels.forEach(l => {
                        l.drawY = Math.max(top + 6, Math.min(bottom - 4, l.drawY));
                    });
                    if (!moved) break;
                }

                // Draw labels beside the graph
                ctx.save();
                ctx.font = '700 10px "Plus Jakarta Sans"';
                labels.forEach(l => {
                    ctx.fillStyle = l.color;
                    ctx.fillText(l.text, right + 8, l.drawY + 4);
                });
                ctx.restore();
            }
        }]
    });

    initAnalyticsDistributionChart();
}

function initAnalyticsDistributionChart() {
    if (typeof Chart === 'undefined' || analyticsDistributionChart) return;
    const canvas = document.getElementById('analyticsDistributionChart');
    if (!canvas) return;

    analyticsDistributionChart = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Average latency',
                data: [],
                backgroundColor: [],
                borderRadius: 5,
                borderSkipped: false,
                maxBarThickness: 26
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            scales: {
                x: {
                    beginAtZero: true,
                    grid: { color: 'rgba(148, 163, 184, 0.18)' },
                    ticks: { color: '#64748b', font: { size: 10, weight: '700' } }
                },
                y: {
                    grid: { display: false },
                    ticks: {
                        autoSkip: false,
                        color: '#334155',
                        padding: 6,
                        font: { size: 10, weight: '700' },
                        callback: function(value) {
                            const label = this.getLabelForValue(value);
                            return label.length > 28 ? `${label.slice(0, 25)}...` : label;
                        }
                    }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: context => `${Math.round(context.raw)}ms average`
                    }
                }
            }
        }
    });
}

function updateChart(history) {
    if (!history) {
        updateAnalyticsSummary({});
        return;
    }
    const domains = Object.keys(history);
    if (domains.length === 0) {
        updateAnalyticsSummary(history);
        return;
    }

    // Get union of all timestamps for labels
    const allLabels = new Set();
    domains.forEach(d => history[d].forEach(p => allLabels.add(p.time)));
    const labels = Array.from(allLabels).sort();

    const colors = ['#3b82f6', '#10b981', '#ef4444', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316', '#14b8a6', '#64748b'];

    const datasets = domains.map((domain, i) => {
        const color = colors[i % colors.length];
        const values = history[domain].map(point => Number(point.latency || 0)).filter(value => value > 0);
        const avg = values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
        return {
            label: domain,
            data: labels.map(l => {
                const point = history[domain].find(p => p.time === l);
                return point ? point.latency : null;
            }),
            borderColor: color,
            backgroundColor: color + '06',
            tension: 0.34,
            borderWidth: 2.5,
            pointRadius: labels.map(l => {
                const point = history[domain].find(p => p.time === l);
                const latency = Number(point?.latency || 0);
                return point?.status === 'DOWN' || latency >= 2500 || (avg > 0 && latency > avg * 1.8) ? 3 : 0;
            }),
            pointHoverRadius: 0,
            pointBackgroundColor: labels.map(l => {
                const point = history[domain].find(p => p.time === l);
                const latency = Number(point?.latency || 0);
                return point?.status === 'DOWN' || latency >= 2500 ? '#dc2626' : (avg > 0 && latency > avg * 1.8) ? '#f59e0b' : color;
            }),
            pointHoverBorderColor: '#fff',
            pointHoverBorderWidth: 2,
            fill: true,
            spanGaps: true // <--- THIS WILL CONNECT THE LINES ACROSS RESTART GAPS
        };
    });

    // IMPLEMENT DOWNTIME SHADING
    const annotations = {};
    labels.forEach((label, idx) => {
        // Check if any domain is down at this timestamp
        const isAnyoneDown = domains.some(d => {
            const point = history[d].find(p => p.time === label);
            return point && point.status === 'DOWN';
        });

        if (isAnyoneDown) {
            // Find or extend a "Down Zone"
            const lastAnn = Object.values(annotations).pop();
            if (lastAnn && lastAnn.xMaxIdx === idx - 1) {
                lastAnn.xMax = label;
                lastAnn.xMaxIdx = idx;
            } else {
                const id = 'down_' + idx;
                annotations[id] = {
                    type: 'box',
                    xMin: label,
                    xMax: label,
                    xMaxIdx: idx,
                    backgroundColor: 'rgba(220, 38, 38, 0.045)',
                    borderColor: 'rgba(220, 38, 38, 0.14)',
                    borderWidth: 1,
                    label: {
                        display: false,
                        content: 'Downtime Detected',
                        position: 'start'
                    }
                };
            }
        }
    });

    performanceChart.data.labels = labels;
    performanceChart.data.datasets = datasets;
    performanceChart.options.plugins.annotation.annotations = annotations;
    performanceChart.update();
    updateAnalyticsSummary(history);
}

function getRangeLabel() {
    if (!historyRange) return 'Last 1 Hour';
    const labels = {
        '5m': 'Last 5 Min',
        '30m': 'Last 30 Min',
        '1h': 'Last 1 Hour',
        '24h': 'Last 24 Hours'
    };
    return labels[historyRange.value] || historyRange.value;
}

function updateAnalyticsSummary(history) {
    const domains = Object.keys(history || {});
    const stats = domains.map(domain => {
        const points = Array.isArray(history[domain]) ? history[domain] : [];
        const latencyPoints = points
            .map(point => Number(point.latency || 0))
            .filter(value => Number.isFinite(value) && value > 0);
        const downEvents = points.filter(point => point.status === 'DOWN').length;
        const avg = latencyPoints.length
            ? latencyPoints.reduce((sum, value) => sum + value, 0) / latencyPoints.length
            : 0;
        const peak = latencyPoints.length ? Math.max(...latencyPoints) : 0;
        const midpoint = Math.floor(latencyPoints.length / 2);
        const firstHalf = midpoint ? latencyPoints.slice(0, midpoint) : [];
        const secondHalf = midpoint ? latencyPoints.slice(midpoint) : latencyPoints;
        const firstAvg = firstHalf.length ? firstHalf.reduce((sum, value) => sum + value, 0) / firstHalf.length : 0;
        const recentAvg = secondHalf.length ? secondHalf.reduce((sum, value) => sum + value, 0) / secondHalf.length : 0;
        const trendDelta = firstAvg ? recentAvg - firstAvg : 0;
        const spikes = latencyPoints.filter(value => avg > 0 && (value > avg * 1.8 || value >= 2500)).length;
        return { domain, points, avg, peak, downEvents, firstAvg, recentAvg, trendDelta, spikes };
    });

    const latencyStats = stats.filter(item => item.avg > 0);
    let latencyPointCount = 0;
    const weightedLatency = latencyStats.reduce((sum, item) => {
        const latencyPoints = item.points.map(point => Number(point.latency || 0)).filter(value => value > 0);
        latencyPointCount += latencyPoints.length;
        return sum + latencyPoints.reduce((inner, value) => inner + value, 0);
    }, 0);
    const avgLatency = latencyPointCount ? Math.round(weightedLatency / latencyPointCount) : 0;
    const peakItem = stats.reduce((max, item) => item.peak > max.peak ? item : max, { peak: 0, domain: '' });
    const downEvents = stats.reduce((sum, item) => sum + item.downEvents, 0);
    const spikes = stats.reduce((sum, item) => sum + item.spikes, 0);
    const avgTrend = previousAnalyticsSnapshot ? avgLatency - previousAnalyticsSnapshot.avgLatency : 0;

    setText('analyticsServiceCount', String(domains.length));
    setText('analyticsAvgLatency', `${avgLatency}ms`);
    setText('analyticsPeakLatency', `${Math.round(peakItem.peak)}ms`);
    setText('analyticsPeakService', peakItem.domain || 'No service selected');
    setText('analyticsDownEvents', String(downEvents));
    setText('analyticsWindowBadge', getRangeLabel());
    setText('analyticsLatencyPosture', avgLatency > 2500 ? 'Critical latency pressure' : avgLatency > 1500 ? 'Elevated response times' : avgLatency > 0 ? `${avgTrend >= 0 ? '+' : ''}${Math.round(avgTrend)}ms vs last load` : 'Awaiting data');
    setText('analyticsHealthState', downEvents ? 'Degraded' : spikes ? 'Watch' : avgLatency ? 'Stable' : 'Awaiting data');
    setText('analyticsHealthContext', avgLatency ? `${avgLatency}ms fleet avg across ${domains.length} services` : 'No comparison window loaded');
    setText('analyticsSpikeCount', String(spikes));
    setText('analyticsSpikeContext', spikes ? 'Anomalies highlighted on trend chart' : 'No spikes detected');
    setText('analyticsWorstService', peakItem.domain ? cleanServiceName(peakItem.domain) : 'None');
    setText('analyticsWorstContext', peakItem.domain ? `Peak ${Math.round(peakItem.peak)}ms in ${getRangeLabel()}` : 'No service selected');

    setStatusClass('analyticsHealthCard', downEvents ? 'critical' : spikes ? 'warning' : avgLatency ? 'normal' : 'neutral');
    setStatusClass('analyticsSpikeCard', spikes ? 'warning' : 'normal');
    setStatusClass('analyticsWorstCard', peakItem.peak >= 2500 ? 'critical' : peakItem.peak >= 1500 ? 'warning' : peakItem.peak ? 'normal' : 'neutral');
    setStatusClass('analyticsServicesCard', domains.length ? 'neutral' : 'warning');
    setStatusClass('analyticsAvgCard', avgLatency >= 2500 ? 'critical' : avgLatency >= 1500 ? 'warning' : avgLatency ? 'normal' : 'neutral');
    setStatusClass('analyticsPeakCard', peakItem.peak >= 2500 ? 'critical' : peakItem.peak >= 1500 ? 'warning' : peakItem.peak ? 'normal' : 'neutral');
    setStatusClass('analyticsDownCard', downEvents ? 'critical' : 'normal');

    updateAnalyticsDistribution(stats);
    updateAnalyticsRankList(stats);
    renderAnalyticsIntelligence(stats, { avgLatency, peakItem, downEvents, spikes });
    previousAnalyticsSnapshot = { avgLatency };
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function updateAnalyticsDistribution(stats) {
    initAnalyticsDistributionChart();
    if (!analyticsDistributionChart) return;

    const rows = stats
        .slice()
        .sort((a, b) => b.avg - a.avg);
    const distributionStage = document.querySelector('.analytics-side-chart');
    if (distributionStage) {
        distributionStage.style.height = `${Math.max(190, rows.length * 28 + 44)}px`;
        analyticsDistributionChart.resize();
    }
    analyticsDistributionChart.data.labels = rows.map(item => item.domain.replace(/^https?:\/\//i, ''));
    analyticsDistributionChart.data.datasets[0].data = rows.map(item => Math.round(item.avg));
    analyticsDistributionChart.data.datasets[0].backgroundColor = rows.map(item => {
        if (item.downEvents > 0 || item.avg > 2500) return '#dc2626';
        if (item.avg > 1800) return '#f59e0b';
        return '#2563eb';
    });
    analyticsDistributionChart.update();
}

function updateAnalyticsRankList(stats) {
    const list = document.getElementById('analyticsRankList');
    if (!list) return;

    const rows = stats
        .slice()
        .sort((a, b) => (b.downEvents - a.downEvents) || (b.avg - a.avg));
    list.style.maxHeight = `${Math.max(190, rows.length * 44)}px`;

    if (rows.length === 0) {
        list.innerHTML = '<div class="analytics-empty">Awaiting performance telemetry...</div>';
        return;
    }

    list.innerHTML = rows.map(item => {
        const highRisk = item.downEvents > 0 || item.avg > 2500;
        const warningRisk = item.spikes > 0 || item.trendDelta > 500;
        const riskText = item.downEvents > 0 ? `${item.downEvents} down events` : item.avg > 2500 ? 'Latency risk' : item.spikes ? `${item.spikes} spikes` : item.trendDelta > 0 ? `+${Math.round(item.trendDelta)}ms trend` : 'Stable trend';
        return `
            <div class="rank-row ${highRisk ? 'risk-high' : warningRisk ? 'risk-warning' : ''}">
                <div>
                    <strong>${escapeHtml(item.domain)}</strong>
                    <span>${riskText} Ãƒâ€šÃ‚Â· peak ${Math.round(item.peak)}ms</span>
                </div>
                <div class="rank-score">${Math.round(item.avg)}ms avg</div>
            </div>
        `;
    }).join('');
}

function renderAnalyticsIntelligence(stats, meta) {
    const grid = document.getElementById('analyticsIntelGrid');
    const badge = document.getElementById('analyticsInsightBadge');
    if (!grid) return;

    const rows = stats
        .slice()
        .sort((a, b) => (b.downEvents - a.downEvents) || (b.spikes - a.spikes) || (b.peak - a.peak))
        .filter(item => item.downEvents || item.spikes || item.avg >= 1500 || item.trendDelta > 350)
        .slice(0, 4);

    if (badge) {
        badge.textContent = meta.downEvents ? `${meta.downEvents} down events` : meta.spikes ? `${meta.spikes} anomalies` : meta.avgLatency ? 'No active risk' : 'No telemetry';
        badge.className = `table-badge ${meta.downEvents ? 'badge-critical' : meta.spikes ? 'badge-warning' : 'badge-normal'}`;
    }

    if (!rows.length) {
        grid.innerHTML = meta.avgLatency
            ? `<article class="intel-card normal"><span>Performance posture</span><strong>Stable trend</strong><p>Average latency ${meta.avgLatency}ms with no active anomalies.</p><small>Continue monitoring</small></article>`
            : '<div class="intel-empty">Awaiting performance telemetry...</div>';
        return;
    }

    grid.innerHTML = rows.map(item => {
        const tone = item.downEvents || item.peak >= 2500 ? 'critical' : 'warning';
        const detail = item.downEvents
            ? `${item.downEvents} down events in ${getRangeLabel()}`
            : item.spikes
                ? `${item.spikes} latency spikes, peak ${Math.round(item.peak)}ms`
                : `${Math.round(item.trendDelta)}ms recent regression`;
        return `
            <article class="intel-card ${tone}">
                <span>${tone === 'critical' ? 'Immediate attention' : 'Risk indicator'}</span>
                <strong>${escapeHtml(cleanServiceName(item.domain))}</strong>
                <p>${escapeHtml(detail)}</p>
                <small>${item.downEvents ? 'Open incident review' : 'Compare upstream latency'}</small>
            </article>
        `;
    }).join('');
}

// --- Utilities ---

function setStatusClass(id, tone) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('status-critical', 'status-warning', 'status-normal', 'status-neutral');
    el.classList.add(`status-${tone || 'neutral'}`);
}

function formatSigned(value) {
    const rounded = Math.round(Number(value || 0));
    return rounded > 0 ? `+${rounded}` : String(rounded);
}

function cleanServiceName(value) {
    return String(value || 'Unknown service')
        .replace(/^https?:\/\//i, '')
        .replace(/\/$/, '');
}

function showToast(msg) {
    toastEl.textContent = msg;
    toastEl.classList.remove('hidden');
    setTimeout(() => toastEl.classList.add('hidden'), 5000);
}

window.toggleSidebarModule = function(moduleName) {
    const moduleEl = document.getElementById(`module-${moduleName}`);
    if (!moduleEl) return;

    const isCollapsed = moduleEl.classList.toggle('collapsed');
    const toggle = moduleEl.querySelector('.sidebar-module-toggle');
    const chevron = moduleEl.querySelector('.module-chevron');

    moduleEl.classList.toggle('expanded', !isCollapsed);
    if (toggle) toggle.setAttribute('aria-expanded', String(!isCollapsed));
    if (chevron) chevron.textContent = isCollapsed ? '>' : 'v';
};

function expandSidebarModule(moduleName) {
    const moduleEl = document.getElementById(`module-${moduleName}`);
    if (!moduleEl) return;

    moduleEl.classList.remove('collapsed');
    moduleEl.classList.add('expanded');
    const toggle = moduleEl.querySelector('.sidebar-module-toggle');
    const chevron = moduleEl.querySelector('.module-chevron');
    if (toggle) toggle.setAttribute('aria-expanded', 'true');
    if (chevron) chevron.textContent = 'v';
}

window.showSection = function (sectionId) {
    const overview = document.getElementById('section-overview');
    const infra = document.getElementById('section-infrastructure');
    const report = document.getElementById('section-report');
    const pulse = document.getElementById('section-pulse');
    const analytics = document.getElementById('section-analytics');
    const workspace = document.getElementById('section-workspace');
    const navOverview = document.getElementById('nav-overview');
    const navInfra = document.getElementById('nav-infrastructure');
    const navPulse = document.getElementById('nav-pulse');
    const navReport = document.getElementById('nav-report');
    const navAnalytics = document.getElementById('nav-analytics');
    const navWorkspace = document.getElementById('nav-workspace');
    const pageTitle = document.getElementById('page-title');
    const breadcrumb = document.getElementById('breadcrumb-text');

    if (overview) overview.classList.add('hidden');
    if (infra) infra.classList.add('hidden');
    if (report) report.classList.add('hidden');
    if (pulse) pulse.classList.add('hidden');
    if (analytics) analytics.classList.add('hidden');
    if (workspace) workspace.classList.add('hidden');
    
    if (navOverview) navOverview.classList.remove('active');
    if (navInfra) navInfra.classList.remove('active');
    if (navReport) navReport.classList.remove('active');
    if (navPulse) navPulse.classList.remove('active');
    if (navAnalytics) navAnalytics.classList.remove('active');
    if (navWorkspace) navWorkspace.classList.remove('active');

    if (sectionId === 'overview' || sectionId === 'infrastructure') {
        expandSidebarModule('serview');
        const overviewSelected = sectionId === 'overview';
        if (overviewSelected && overview) overview.classList.remove('hidden');
        if (!overviewSelected && infra) infra.classList.remove('hidden');
        if (overviewSelected && navOverview) navOverview.classList.add('active');
        if (!overviewSelected && navInfra) navInfra.classList.add('active');
        pageTitle.textContent = overviewSelected ? "Overview" : "Infrastructure Status";
        breadcrumb.textContent = overviewSelected ? "Overview" : "Website Status";
    } else if (sectionId === 'report') {
        expandSidebarModule('serview');
        report.classList.remove('hidden');
        if (navReport) navReport.classList.add('active');
        pageTitle.textContent = "Analytics & Reporting";
        breadcrumb.textContent = "Persistence Report";
        window.fetchDetailedReport();
    } else if (sectionId === 'pulse') {
        expandSidebarModule('serview');
        if (pulse) pulse.classList.remove('hidden');
        if (navPulse) navPulse.classList.add('active');
        pageTitle.textContent = "Central Diagnostics";
        breadcrumb.textContent = "Operations Hub";
        window.fetchRealTimeLogs();
    } else if (sectionId === 'analytics') {
        expandSidebarModule('serview');
        if (analytics) analytics.classList.remove('hidden');
        if (navAnalytics) navAnalytics.classList.add('active');
        pageTitle.textContent = "Performance Analytics";
        breadcrumb.textContent = "Historical Latency Trends";
        fetchHistory();
    } else if (sectionId === 'workspace') {
        expandSidebarModule('workspace');
        workspace.classList.remove('hidden');
        navWorkspace.classList.add('active');
        pageTitle.textContent = currentWorkspaceFilter === 'prod' ? "PROD Website Dashboards" : currentWorkspaceFilter === 'staging' ? "Staging/Local Website Dashboards" : "Workspace Apps";
        breadcrumb.textContent = currentWorkspaceFilter ? `Workspace / ${currentWorkspaceFilter === 'prod' ? 'PROD' : 'Staging/Local'}` : "Workspace / Websites";
        renderWebsiteWorkspace();
    }
};

// --- Log Management ---
window.rawLogs = [];

window.fetchRealTimeLogs = async function() {
    if (demoMode() || authRole() === 'Viewer') { window.rawLogs = []; window.renderLogs(); return; }
    try {
        const resp = await apiFetch('/api/logs/realtime');
        if (resp.ok) {
            window.rawLogs = await resp.json();
            window.renderLogs();
        }
    } catch (e) {
        console.error("Live log fetch failed", e);
    }
};

window.renderLogs = function() {
    console.log("Rendering Logs Logic Triggered");
    const tbody = document.getElementById('logTableBody');
    const levelSelect = document.getElementById('logLevel');
    const searchInput = document.getElementById('logSearch');
    
    if (!tbody || !levelSelect || !searchInput) return;
    
    const search = searchInput.value.toLowerCase();
    const level = levelSelect.value || levelSelect.options[levelSelect.selectedIndex].text;
    
    tbody.innerHTML = '';
    
    const filtered = window.rawLogs.filter(log => {
        // Handle "Level: ALL" label or "ALL" value
        const matchesLevel = (level.includes('ALL') || log.level === level || (level === 'WARNING' && log.level === 'WARN'));
        const matchesSearch = (log.message.toLowerCase().includes(search) || log.service.toLowerCase().includes(search));
        return matchesLevel && matchesSearch;
    });
    
    filtered.forEach(log => {
        const tr = document.createElement('tr');
        tr.style.borderBottom = "1px solid #f1f5f9";
        
        let levelColor = "#10b981"; // INFO
        if (log.level === 'ERROR') levelColor = "#ef4444";
        if (log.level === 'WARN') levelColor = "#f59e0b";
        
        tr.innerHTML = `
            <td style="white-space: nowrap; color: #64748b;">${log.time}</td>
            <td>${log.service}</td>
            <td><span style="color: ${levelColor}; font-weight: 700;">[${log.level}]</span></td>
            <td>${log.message}</td>
            <td>${log.source}</td>
        `;
        tbody.appendChild(tr);
    });
};

window.allReportEntries = [];

window.fetchDetailedReport = async function() {
    try {
        const response = await apiFetch(demoMode() ? '/api/demo/collection' : '/api/collection');
        if (response.status === 401 || response.status === 422 || !response.ok) return;
        const data = await response.json();
        
        const loader = document.getElementById('reportLoader');
        const noData = document.getElementById('reportNoData');
        
        if(loader) loader.classList.add('hidden');
        
        const domains = Object.keys(data);
        let entries = [];
        
        domains.forEach(domain => {
            data[domain].forEach(entry => entries.push({ domain, ...entry }));
        });
        
        entries.sort((a, b) => new Date(b.time) - new Date(a.time));
        window.allReportEntries = entries;
        
        if (entries.length === 0 && noData) {
            noData.classList.remove('hidden');
            return;
        }
        
        window.renderReportTable();
    } catch (e) {
        console.error("Report fetch error", e);
    }
}

window.renderReportTable = function() {
    const tableBody = document.getElementById('reportBody');
    const noData = document.getElementById('reportNoData');
    if (!tableBody) return;
    
    const filterDate = document.getElementById('reportDate') ? document.getElementById('reportDate').value : '';
    let filteredEntries = window.allReportEntries;
    
    if (filterDate) {
        filteredEntries = window.allReportEntries.filter(entry => {
            if (!entry.time) return false;
            // entry.time may be '2026-04-23 10:58:44' or '2026-04-23T10:58:44'
            const entryDate = entry.time.substring(0, 10);
            return entryDate === filterDate;
        });
    }

    if (filteredEntries.length === 0 && window.allReportEntries.length > 0) {
        tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:2rem;">No records found for selected date.</td></tr>';
        updateStatsUI(0, 0, 0);
        return;
    } else if (filteredEntries.length === 0) {
        if(noData) noData.classList.remove('hidden');
        return;
    }
    
    let totalLatency = 0;
    const uniqueDomains = new Set();
    
    tableBody.innerHTML = '';
    filteredEntries.forEach(entry => {
        uniqueDomains.add(entry.domain);
        totalLatency += entry.latency || 0;

        const isUp = entry.latency && entry.latency > 0;
        const statusDot = isUp 
            ? '<span style="display: inline-block; width: 8px; height: 8px; background: #22c55e; border-radius: 50%; margin-right: 8px;"></span> UP' 
            : '<span style="display: inline-block; width: 8px; height: 8px; background: #ef4444; border-radius: 50%; margin-right: 8px;"></span> DOWN';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="domain-cell" style="font-weight: 700; color: #0f172a;">${entry.domain}</span></td>
            <td>${statusDot}</td>
            <td><span style="font-weight: 600;">${entry.latency ? entry.latency + 'ms' : '--'}</span></td>
            <td>${entry.failure_analysis || entry.reason || 'OK'}</td>
            <td style="color: #64748b; font-size: 0.85rem;">${entry.time}</td>
        `;
        tableBody.appendChild(tr);
    });


    const statText = document.getElementById('tableStatus');
    if(statText) statText.innerText = `Showing ${filteredEntries.length} persistence entries`;
    
    updateStatsUI(filteredEntries.length, uniqueDomains.size, Math.round(totalLatency / filteredEntries.length) || 0);
}

function updateStatsUI(total, domains, latency) {
    const e1 = document.getElementById('stat-total');
    const e2 = document.getElementById('stat-domains');
    const e3 = document.getElementById('stat-latency');
    
    if(e1) e1.innerText = total;
    if(e2) e2.innerText = domains;
    if(e3) e3.innerText = latency + 'ms';
}

function startTimer() {
    setInterval(() => {
        timeLeft--;
        if (timeLeft <= 0) {
            timeLeft = PING_INTERVAL;
            fetchStatus();
            fetchHistory();
            window.fetchRealTimeLogs();
        }
        if (timerEl) timerEl.textContent = timeLeft;
    }, 1000);
}


// --- Initialization ---

window.onload = async () => {
    await refreshSignedInRole();
    updateAccessUI();
    window.showSection('overview');


    if (addBtn) addBtn.onclick = addDomains;
    if (domInput) domInput.onkeypress = (e) => { if (e.key === 'Enter') addDomains(); };

    initChart();
    startTimer();
    
    fetchStatus();
    fetchHistory();
    historyRange.onchange = fetchHistory;

    // Log Handlers
    const lSearch = document.getElementById('logSearch');
    const lLevel = document.getElementById('logLevel');
    if (lSearch) {
        lSearch.addEventListener('input', window.renderLogs);
    }
    if (lLevel) {
        lLevel.addEventListener('change', window.renderLogs);
    }
    
    // Initial Logs Render
    window.renderLogs();
};

window.exportReport = function() {
    downloadReport(demoMode() ? '/api/demo/report' : reportUrl('/api/report'), demoMode() ? 'uptrix-demo-report.json' : 'uptrix-report.xlsx');
};

window.exportPDF = function() {
    downloadReport(demoMode() ? '/api/demo/report/pdf' : reportUrl('/api/report/pdf'), 'uptrix-sample-report.pdf');
};

function reportUrl(base) {
    const date = document.getElementById('reportDate')?.value;
    return date ? `${base}?date=${encodeURIComponent(date)}` : base;
}

async function downloadReport(url, filename) {
    try {
        const response = await apiFetch(url);
        if (!response.ok) { showToast('You do not have access to this report.'); return; }
        const blob = await response.blob();
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob); link.download = filename; link.click();
        URL.revokeObjectURL(link.href);
    } catch (_) { showToast('Report download failed.'); }
}
