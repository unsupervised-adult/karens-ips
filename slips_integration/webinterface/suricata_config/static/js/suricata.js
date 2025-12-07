document.addEventListener('DOMContentLoaded', function() {
    initTabs();
    loadStatus();
    loadStats();
    loadAlerts();
    loadRules();
    loadConfig();
    
    setInterval(loadStatus, 10000);
    setInterval(loadStats, 5000);
});

function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.getAttribute('data-tab');
            
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            button.classList.add('active');
            document.getElementById(tabName).classList.add('active');
            
            console.log('Suricata: Tab switched to', tabName);
            
            if (tabName === 'alerts') {
                console.log('Suricata: Loading alerts...');
                loadAlerts();
            }
            if (tabName === 'rules') {
                console.log('Suricata: Loading rules...');
                loadRules();
                loadRuleSources();
                loadSeverityClassifications();
                loadTlsSniRules();
            }
            if (tabName === 'config') {
                console.log('Suricata: Loading config...');
                loadConfig();
            }
            if (tabName === 'blocklists') {
                console.log('Suricata: Loading blocklists...');
                loadBlocklists();
            }
            if (tabName === 'database') {
                console.log('Suricata: Loading database stats...');
                loadDatabaseStats();
            }
        });
    });
}

async function loadStatus() {
    try {
        const response = await fetch('/suricata/api/status');
        const data = await response.json();
        
        const statusEl = document.getElementById('status-indicator');
        const statusText = document.getElementById('status-text');
        
        statusEl.className = 'status-badge ' + data.status;
        statusText.textContent = data.status === 'running' ? 'Running' : 'Stopped';
        
        if (data.uptime) {
            document.getElementById('stat-uptime').textContent = formatUptime(data.uptime);
        }
    } catch (error) {
        console.error('Failed to load status:', error);
    }
}

async function loadStats() {
    try {
        const response = await fetch('/suricata/api/stats');
        const data = await response.json();
        
        document.getElementById('stat-packets').textContent = formatNumber(data.packets);
        document.getElementById('stat-alerts').textContent = formatNumber(data.alerts);
        document.getElementById('stat-dropped').textContent = formatNumber(data.dropped);
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

async function loadAlerts() {
    const severity = document.getElementById('alert-severity-filter')?.value || '';
    const tbody = document.getElementById('alerts-body');
    
    tbody.innerHTML = '<tr><td colspan="7">Loading...</td></tr>';
    
    try {
        const url = `/suricata/api/alerts?limit=100${severity ? '&severity=' + severity : ''}`;
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.alerts && data.alerts.length > 0) {
            tbody.innerHTML = data.alerts.map(alert => `
                <tr>
                    <td>${formatTimestamp(alert.timestamp)}</td>
                    <td>${alert.src_ip}</td>
                    <td>${alert.dest_ip}</td>
                    <td>${alert.proto}</td>
                    <td>${alert.signature}</td>
                    <td class="severity-${alert.severity}">${alert.severity}</td>
                    <td>${alert.category}</td>
                    <td class="action-buttons">
                        <button onclick="whitelistIP('${alert.src_ip}')" class="btn-small" title="Allow source IP">Allow IP</button>
                        <button onclick="suppressSignature(${alert.signature_id}, '${escapeHtml(alert.signature)}')" class="btn-small" title="Suppress this signature">Suppress</button>
                    </td>
                </tr>
            `).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="8">No alerts found</td></tr>';
        }
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="8">Error loading alerts</td></tr>';
        console.error('Failed to load alerts:', error);
    }
}

async function whitelistIP(ip) {
    if (!confirm(`Allow all traffic from ${ip}? This will add a pass rule.`)) return;
    
    try {
        const response = await fetch('/suricata/api/actions/whitelist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'ip', value: ip })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification(`IP ${ip} whitelisted`, 'success');
            loadAlerts();
        } else {
            showNotification(data.error || 'Failed to whitelist IP', 'error');
        }
    } catch (error) {
        showNotification('Error whitelisting IP', 'error');
        console.error(error);
    }
}

async function suppressSignature(sid, signature) {
    if (!confirm(`Suppress signature "${signature}" (SID: ${sid})? This will prevent future alerts.`)) return;
    
    try {
        const response = await fetch('/suricata/api/actions/whitelist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'signature', signature_id: sid })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification(`Signature ${sid} suppressed`, 'success');
            loadAlerts();
        } else {
            showNotification(data.error || 'Failed to suppress signature', 'error');
        }
    } catch (error) {
        showNotification('Error suppressing signature', 'error');
        console.error(error);
    }
}

async function whitelistManualIP() {
    const ip = document.getElementById('manual-whitelist-ip').value.trim();
    
    if (!ip) {
        showNotification('IP address cannot be empty', 'error');
        return;
    }
    
    if (!confirm(`Whitelist ${ip}? This will add a pass rule.`)) return;
    
    try {
        const response = await fetch('/suricata/api/actions/whitelist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'ip', value: ip })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification(`IP ${ip} whitelisted`, 'success');
            document.getElementById('manual-whitelist-ip').value = '';
        } else {
            showNotification(data.error || 'Failed to whitelist IP', 'error');
        }
    } catch (error) {
        showNotification('Error whitelisting IP', 'error');
        console.error(error);
    }
}

async function loadBlocklists() {
    const reposDiv = document.getElementById('blocklist-repos');
    const statsDiv = document.getElementById('blocklist-stats');
    
    reposDiv.innerHTML = '<p>Loading...</p>';
    statsDiv.innerHTML = '<p>Loading...</p>';
    
    try {
        const response = await fetch('/suricata/api/blocklists');
        const data = await response.json();
        
        if (data.blocklists && data.blocklists.length > 0) {
            reposDiv.innerHTML = data.blocklists.map(repo => `
                <div class="repo-item">
                    <div class="repo-info">
                        <strong>${repo.name}</strong>
                        <span class="status-badge ${repo.status}">${repo.status}</span>
                    </div>
                    <button onclick="updateBlocklistRepo('${repo.type}')" class="btn-primary">Update from GitHub</button>
                </div>
            `).join('');
        } else {
            reposDiv.innerHTML = '<p>No blocklists cloned yet. Use Update buttons below to clone repositories.</p>';
        }
        
        const statsResponse = await fetch('/suricata/api/blocklists/stats');
        const statsData = await statsResponse.json();
        
        if (statsData.stats) {
            statsDiv.innerHTML = Object.entries(statsData.stats).map(([key, value]) => 
                `<div><strong>${key}:</strong> ${value}</div>`
            ).join('');
        } else {
            statsDiv.innerHTML = '<p>No statistics available</p>';
        }
    } catch (error) {
        reposDiv.innerHTML = '<p>Error loading blocklists</p>';
        console.error('Failed to load blocklists:', error);
    }
}

async function updateBlocklistRepo(type) {
    showNotification(`Updating ${type} repository from GitHub...`, 'success');
    
    try {
        const response = await fetch('/suricata/api/blocklists/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: type })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification(`${type} repository updated`, 'success');
            loadBlocklists();
        } else {
            showNotification(data.error || 'Failed to update repository', 'error');
        }
    } catch (error) {
        showNotification('Error updating repository', 'error');
        console.error(error);
    }
}

async function importBlocklist(type, list) {
    const listName = `${type} ${list}`;
    showNotification(`Importing ${listName}... (this may take several minutes)`, 'success');
    
    try {
        const response = await fetch('/suricata/api/blocklists/import', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: type, list: list })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification(`${listName} imported and synced to Suricata`, 'success');
            loadBlocklists();
        } else {
            showNotification(data.error || 'Failed to import blocklist', 'error');
        }
    } catch (error) {
        showNotification('Error importing blocklist', 'error');
        console.error(error);
    }
}

async function loadRules() {
    const rulesList = document.getElementById('rules-list');
    rulesList.innerHTML = '<p>Loading...</p>';
    
    try {
        const response = await fetch('/suricata/api/rules');
        const data = await response.json();
        
        if (data.rules && data.rules.length > 0) {
            rulesList.innerHTML = data.rules.map(rule => `
                <div class="rule-item ${rule.enabled ? '' : 'disabled'}">
                    <div class="rule-text">${escapeHtml(rule.rule)}</div>
                    <div class="rule-actions">
                        <button onclick="toggleRule(${rule.line})">${rule.enabled ? 'Disable' : 'Enable'}</button>
                        <button onclick="deleteRule(${rule.line})" class="btn-danger">Delete</button>
                    </div>
                </div>
            `).join('');
        } else {
            rulesList.innerHTML = '<p>No custom rules configured</p>';
        }
    } catch (error) {
        rulesList.innerHTML = '<p>Error loading rules</p>';
        console.error('Failed to load rules:', error);
    }
}

async function loadConfig() {
    try {
        const response = await fetch('/suricata/api/config');
        const data = await response.json();
        
        document.getElementById('home-net').value = data.home_net || '';
        document.getElementById('external-net').value = data.external_net || '';
        
        const interfacesInfo = document.getElementById('interfaces-info');
        if (data.interfaces && data.interfaces.length > 0) {
            interfacesInfo.innerHTML = data.interfaces.map(iface => 
                `Interface: ${iface.interface || 'Unknown'}`
            ).join('<br>');
        } else {
            interfacesInfo.innerHTML = 'No interfaces configured';
        }
    } catch (error) {
        console.error('Failed to load config:', error);
    }
}

async function addRule() {
    const ruleText = document.getElementById('new-rule').value.trim();
    
    if (!ruleText) {
        showNotification('Rule cannot be empty', 'error');
        return;
    }
    
    try {
        const response = await fetch('/suricata/api/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule: ruleText })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Rule added successfully', 'success');
            document.getElementById('new-rule').value = '';
            loadRules();
        } else {
            showNotification(data.error || 'Failed to add rule', 'error');
        }
    } catch (error) {
        showNotification('Error adding rule', 'error');
        console.error(error);
    }
}

async function toggleRule(lineNum) {
    try {
        const response = await fetch(`/suricata/api/rules/${lineNum}/toggle`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Rule toggled', 'success');
            loadRules();
        } else {
            showNotification(data.error || 'Failed to toggle rule', 'error');
        }
    } catch (error) {
        showNotification('Error toggling rule', 'error');
        console.error(error);
    }
}

async function deleteRule(lineNum) {
    if (!confirm('Delete this rule?')) return;
    
    try {
        const response = await fetch(`/suricata/api/rules/${lineNum}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Rule deleted', 'success');
            loadRules();
        } else {
            showNotification(data.error || 'Failed to delete rule', 'error');
        }
    } catch (error) {
        showNotification('Error deleting rule', 'error');
        console.error(error);
    }
}

async function updateHomeNet() {
    const homeNet = document.getElementById('home-net').value.trim();
    
    if (!homeNet) {
        showNotification('HOME_NET cannot be empty', 'error');
        return;
    }
    
    try {
        const response = await fetch('/suricata/api/config/home_net', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ home_net: homeNet })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('HOME_NET updated', 'success');
        } else {
            showNotification(data.error || 'Failed to update HOME_NET', 'error');
        }
    } catch (error) {
        showNotification('Error updating HOME_NET', 'error');
        console.error(error);
    }
}

async function reloadRules() {
    try {
        const response = await fetch('/suricata/api/actions/reload', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Rules reloaded', 'success');
        } else {
            showNotification(data.error || 'Failed to reload rules', 'error');
        }
    } catch (error) {
        showNotification('Error reloading rules', 'error');
        console.error(error);
    }
}

async function restartSuricata() {
    if (!confirm('Restart Suricata? This will cause brief downtime.')) return;
    
    showNotification('Restarting Suricata...', 'success');
    
    try {
        const response = await fetch('/suricata/api/actions/restart', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Suricata restarted', 'success');
            setTimeout(loadStatus, 3000);
        } else {
            showNotification(data.error || 'Failed to restart', 'error');
        }
    } catch (error) {
        showNotification('Error restarting Suricata', 'error');
        console.error(error);
    }
}

async function updateRuleSources() {
    showNotification('Updating rule sources... (may take a few minutes)', 'success');
    
    try {
        const response = await fetch('/suricata/api/actions/update_rules', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Rules updated from sources', 'success');
        } else {
            showNotification(data.error || 'Failed to update rules', 'error');
        }
    } catch (error) {
        showNotification('Error updating rules', 'error');
        console.error(error);
    }
}

function showNotification(message, type) {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = 'notification ' + type;
    
    setTimeout(() => {
        notification.classList.add('hidden');
    }, 5000);
}

function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

function formatTimestamp(timestamp) {
    if (!timestamp) return '-';
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function formatUptime(uptime) {
    if (uptime === 'Unknown') return 'Unknown';
    const date = new Date(uptime);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);
    
    const days = Math.floor(diff / 86400);
    const hours = Math.floor((diff % 86400) / 3600);
    const minutes = Math.floor((diff % 3600) / 60);
    
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

async function loadDatabaseStats() {
    try {
        const response = await fetch('/suricata/api/database/count');
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('db-sources-count').textContent = formatNumber(data.counts.sources);
            document.getElementById('db-domains-count').textContent = formatNumber(data.counts.domains);
            document.getElementById('db-active-sources').textContent = formatNumber(data.counts.active_sources);
        }
        
        loadSources();
    } catch (error) {
        console.error('Failed to load database stats:', error);
    }
}

async function searchDomains() {
    const searchTerm = document.getElementById('domain-search').value.trim();
    
    if (!searchTerm) {
        showNotification('Please enter a search term', 'error');
        return;
    }
    
    try {
        const response = await fetch('/suricata/api/database/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                table: 'blocked_domains',
                action: 'select',
                filters: { domain: searchTerm },
                limit: 100
            })
        });
        
        const data = await response.json();
        displayDomains(data.data);
    } catch (error) {
        showNotification('Search failed: ' + error.message, 'error');
    }
}

async function loadDomains() {
    try {
        const response = await fetch('/suricata/api/database/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                table: 'blocked_domains',
                action: 'select',
                limit: 100
            })
        });
        
        const data = await response.json();
        displayDomains(data.data);
    } catch (error) {
        showNotification('Failed to load domains: ' + error.message, 'error');
    }
}

function displayDomains(domains) {
    const resultsEl = document.getElementById('domain-results');
    
    if (!domains || domains.length === 0) {
        resultsEl.innerHTML = '<p>No domains found.</p>';
        return;
    }
    
    let html = '<table class="data-table"><thead><tr>';
    html += '<th>ID</th><th>Domain</th><th>Category</th><th>Source ID</th><th>Confidence</th><th>Actions</th>';
    html += '</tr></thead><tbody>';
    
    domains.forEach(domain => {
        html += '<tr>';
        html += `<td>${domain.id}</td>`;
        html += `<td>${escapeHtml(domain.domain)}</td>`;
        html += `<td>${domain.category || 'N/A'}</td>`;
        html += `<td>${domain.source_id}</td>`;
        html += `<td>${domain.confidence}</td>`;
        html += `<td>`;
        html += `<button onclick="whitelistDomain('${escapeHtml(domain.domain)}')" class="btn-secondary" style="margin-right: 5px;">Whitelist</button>`;
        html += `<button onclick="deleteDomain(${domain.id})" class="btn-danger">Delete</button>`;
        html += `</td>`;
        html += '</tr>';
    });
    
    html += '</tbody></table>';
    resultsEl.innerHTML = html;
}

async function whitelistDomain(domain) {
    if (!confirm(`Whitelist domain: ${domain}?`)) return;
    
    try {
        const response = await fetch('/suricata/api/database/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                table: 'blocked_domains',
                action: 'whitelist',
                filters: { domain: domain }
            })
        });
        
        const data = await response.json();
        if (data.success) {
            showNotification(data.message, 'success');
            loadDatabaseStats();
            loadDomains();
        } else {
            showNotification('Failed to whitelist: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Whitelist failed: ' + error.message, 'error');
    }
}

async function deleteDomain(id) {
    if (!confirm(`Delete domain entry ID ${id}?`)) return;
    
    try {
        const response = await fetch('/suricata/api/database/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                table: 'blocked_domains',
                action: 'delete',
                filters: { id: id }
            })
        });
        
        const data = await response.json();
        if (data.success) {
            showNotification(data.message, 'success');
            loadDatabaseStats();
            loadDomains();
        } else {
            showNotification('Failed to delete: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Delete failed: ' + error.message, 'error');
    }
}

async function loadSources() {
    try {
        const response = await fetch('/suricata/api/database/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                table: 'blocklist_sources',
                action: 'select',
                limit: 100
            })
        });
        
        const data = await response.json();
        displaySources(data.data);
    } catch (error) {
        console.error('Failed to load sources:', error);
    }
}

function displaySources(sources) {
    const sourcesEl = document.getElementById('sources-list');
    
    if (!sources || sources.length === 0) {
        sourcesEl.innerHTML = '<p>No blocklist sources configured.</p>';
        return;
    }
    
    let html = '<table class="data-table"><thead><tr>';
    html += '<th>ID</th><th>Name</th><th>Category</th><th>Entries</th><th>Enabled</th><th>Last Updated</th>';
    html += '</tr></thead><tbody>';
    
    sources.forEach(source => {
        html += '<tr>';
        html += `<td>${source.id}</td>`;
        html += `<td>${escapeHtml(source.name)}</td>`;
        html += `<td>${source.category || 'N/A'}</td>`;
        html += `<td>${formatNumber(source.entry_count || 0)}</td>`;
        html += `<td>${source.enabled ? '✓' : '✗'}</td>`;
        html += `<td>${formatTimestamp(source.last_updated)}</td>`;
        html += '</tr>';
    });
    
    html += '</tbody></table>';
    sourcesEl.innerHTML = html;
}

async function syncDatabaseToSuricata() {
    const btn = event.target;
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '⏳ Syncing...';
    
    try {
        const response = await fetch('/suricata/api/database/sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        if (data.success) {
            showNotification('✓ Database synced to Suricata and rules reloaded', 'success');
            const lastSync = document.getElementById('last-sync');
            if (lastSync) {
                lastSync.textContent = `Last synced: ${new Date().toLocaleTimeString()}`;
            }
        } else {
            showNotification('Sync failed: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Sync failed: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

async function loadRuleSources() {
    try {
        const response = await fetch('/suricata/api/rulesets/sources');
        const data = await response.json();
        
        const sourcesEl = document.getElementById('rule-sources-list');
        
        if (!data.sources || data.sources.length === 0) {
            sourcesEl.innerHTML = '<p>No rule sources available.</p>';
            return;
        }
        
        let html = '<table class="data-table"><thead><tr>';
        html += '<th>Source</th><th>Summary</th><th>License</th><th>Status</th><th>Action</th>';
        html += '</tr></thead><tbody>';
        
        data.sources.forEach(source => {
            const needsSubscription = source.subscription || source.license === 'Commercial';
            html += '<tr>';
            html += `<td><strong>${escapeHtml(source.name)}</strong></td>`;
            html += `<td>${escapeHtml(source.summary || 'N/A')}</td>`;
            html += `<td>${escapeHtml(source.license || 'Unknown')}</td>`;
            html += `<td>${source.enabled ? '<span style="color: green;">✓ Enabled</span>' : '<span style="color: gray;">Disabled</span>'}</td>`;
            html += '<td>';
            
            if (needsSubscription && !source.enabled) {
                html += '<span style="color: #999; font-size: 0.9em;">Requires Subscription</span>';
            } else {
                html += `<button onclick="toggleRuleSource('${escapeHtml(source.name)}', ${!source.enabled})" class="${source.enabled ? 'btn-danger' : 'btn-primary'}">`;
                html += source.enabled ? 'Disable' : 'Enable';
                html += '</button>';
            }
            
            html += '</td>';
            html += '</tr>';
        });
        
        html += '</tbody></table>';
        sourcesEl.innerHTML = html;
    } catch (error) {
        console.error('Failed to load rule sources:', error);
        document.getElementById('rule-sources-list').innerHTML = '<p>Error loading rule sources.</p>';
    }
}

async function toggleRuleSource(sourceName, enable) {
    if (!confirm(`${enable ? 'Enable' : 'Disable'} rule source "${sourceName}"?\n\nThis will update rules and reload Suricata (~30-60 seconds).`)) {
        return;
    }
    
    showNotification(`${enable ? 'Enabling' : 'Disabling'} ${sourceName}...`, 'info');
    
    try {
        const response = await fetch('/suricata/api/rulesets/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                source: sourceName,
                enable: enable
            })
        });
        
        const data = await response.json();
        if (data.success) {
            showNotification(data.message, 'success');
            loadRuleSources();
        } else {
            showNotification('Failed: ' + (data.error || data.warning), 'error');
        }
    } catch (error) {
        showNotification('Toggle failed: ' + error.message, 'error');
    }
}

async function loadSeverityClassifications() {
    try {
        const response = await fetch('/suricata/api/rulesets/severity');
        const data = await response.json();
        
        const classEl = document.getElementById('severity-classifications');
        
        if (!data.classifications || data.classifications.length === 0) {
            classEl.innerHTML = '<p>No classifications available.</p>';
            return;
        }
        
        data.classifications.sort((a, b) => a.priority - b.priority);
        
        let html = '<table class="data-table"><thead><tr>';
        html += '<th>Priority</th><th>Classification</th><th>Description</th>';
        html += '</tr></thead><tbody>';
        
        data.classifications.forEach(cls => {
            let priorityLabel = 'Low';
            let priorityColor = '#999';
            
            if (cls.priority === 1) {
                priorityLabel = 'Critical';
                priorityColor = '#dc3545';
            } else if (cls.priority === 2) {
                priorityLabel = 'High';
                priorityColor = '#fd7e14';
            } else if (cls.priority === 3) {
                priorityLabel = 'Medium';
                priorityColor = '#ffc107';
            }
            
            html += '<tr>';
            html += `<td><strong style="color: ${priorityColor};">${cls.priority} - ${priorityLabel}</strong></td>`;
            html += `<td><code>${escapeHtml(cls.name)}</code></td>`;
            html += `<td>${escapeHtml(cls.description)}</td>`;
            html += '</tr>';
        });
        
        html += '</tbody></table>';
        classEl.innerHTML = html;
    } catch (error) {
        console.error('Failed to load classifications:', error);
        document.getElementById('severity-classifications').innerHTML = '<p>Error loading classifications.</p>';
    }
}

function updateSeverityFilter() {
    const filterValue = document.getElementById('classification-priority-filter').value;
    showNotification(`Alert filter set to priority ${filterValue} and above. Update custom rules or suricata.yaml action settings to apply blocking thresholds.`, 'info');
}

async function loadTlsSniRules() {
    try {
        const response = await fetch('/suricata/api/tls-sni/list');
        const data = await response.json();
        
        const rulesEl = document.getElementById('tls-rules-list');
        
        if (!data.rules || data.rules.length === 0) {
            rulesEl.innerHTML = '<p>No TLS SNI rules found. Add a domain above to create one automatically.</p>';
        } else {
            let html = '<table class="data-table"><thead><tr>';
            html += '<th>Line</th><th>Rule</th><th>Status</th><th>Actions</th>';
            html += '</tr></thead><tbody>';
            
            data.rules.forEach(rule => {
                html += '<tr>';
                html += `<td>${rule.line}</td>`;
                html += `<td><code style="font-size: 0.85em;">${escapeHtml(rule.rule)}</code></td>`;
                html += `<td>${rule.enabled ? '<span style="color: green;">✓ Enabled</span>' : '<span style="color: gray;">Disabled</span>'}</td>`;
                html += `<td><button onclick="toggleRule(${rule.line})" class="btn-secondary">Toggle</button></td>`;
                html += '</tr>';
            });
            
            html += '</tbody></table>';
            rulesEl.innerHTML = html;
        }
        
        if (data.datasets && data.datasets.length > 0) {
            const countEl = document.getElementById('tls-domain-count');
            if (countEl) {
                countEl.textContent = `(${data.datasets.length} dataset files)`;
            }
        }
    } catch (error) {
        console.error('Failed to load TLS SNI rules:', error);
    }
}

async function addTlsDomain() {
    const domain = document.getElementById('tls-domain').value.trim();
    const action = document.getElementById('tls-action').value;
    
    if (!domain) {
        showNotification('Please enter a domain', 'error');
        return;
    }
    
    if (!confirm(`Add "${domain}" to TLS blocklist?\nAction: ${action}`)) {
        return;
    }
    
    try {
        const response = await fetch('/suricata/api/tls-sni/add-domain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: domain, action: action })
        });
        
        const data = await response.json();
        if (data.success) {
            showNotification(data.message, 'success');
            document.getElementById('tls-domain').value = '';
            loadTlsSniRules();
            
            if (document.getElementById('tls-dataset-view').style.display !== 'none') {
                viewTlsDataset();
            }
        } else {
            showNotification('Failed: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Add failed: ' + error.message, 'error');
    }
}

async function viewTlsDataset() {
    const viewEl = document.getElementById('tls-dataset-view');
    const listEl = document.getElementById('tls-domains-list');
    
    if (viewEl.style.display === 'none') {
        viewEl.style.display = 'block';
        listEl.innerHTML = '<p>Loading...</p>';
        
        try {
            const response = await fetch('/suricata/api/tls-sni/view-dataset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ dataset: 'blocked-tls-domains.dat' })
            });
            
            const data = await response.json();
            if (data.success) {
                if (data.domains.length === 0) {
                    listEl.innerHTML = '<p>No domains in blocklist yet.</p>';
                } else {
                    let html = `<p><strong>${data.count} domains blocked</strong></p><ul style="list-style: none; padding: 0;">`;
                    data.domains.forEach(domain => {
                        html += `<li style="padding: 5px; border-bottom: 1px solid #ddd;">`;
                        html += `<span>${escapeHtml(domain)}</span>`;
                        html += `<button onclick="removeTlsDomain('${escapeHtml(domain)}')" class="btn-danger" style="float: right; padding: 2px 8px; font-size: 0.85em;">Remove</button>`;
                        html += `</li>`;
                    });
                    html += '</ul>';
                    listEl.innerHTML = html;
                }
            } else {
                listEl.innerHTML = '<p>Error loading dataset: ' + escapeHtml(data.error) + '</p>';
            }
        } catch (error) {
            listEl.innerHTML = '<p>Error: ' + escapeHtml(error.message) + '</p>';
        }
    } else {
        viewEl.style.display = 'none';
    }
}

async function removeTlsDomain(domain) {
    if (!confirm(`Remove "${domain}" from TLS blocklist?`)) {
        return;
    }
    
    try {
        const response = await fetch('/suricata/api/tls-sni/remove-domain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                domain: domain,
                dataset: 'blocked-tls-domains.dat'
            })
        });
        
        const data = await response.json();
        if (data.success) {
            showNotification(data.message, 'success');
            viewTlsDataset();
            loadTlsSniRules();
        } else {
            showNotification('Failed: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Remove failed: ' + error.message, 'error');
    }
}
