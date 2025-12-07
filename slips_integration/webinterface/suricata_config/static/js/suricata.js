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
            
            if (tabName === 'alerts') loadAlerts();
            if (tabName === 'rules') loadRules();
            if (tabName === 'config') loadConfig();
            if (tabName === 'blocklists') loadBlocklists();
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
    const severity = document.getElementById('severity-filter')?.value || '';
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
