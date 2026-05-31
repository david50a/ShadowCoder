/**
 * ShadowCoder Frontend v2
 * Phase 3: WebSocket real-time scan progress
 * Phase 5: AI explain / fix / triage panels
 * Phase 6: Project analysis view
 */

document.addEventListener('DOMContentLoaded', () => {
    // ── Authentication Check ────────────────────────────────────────────────
    const token = localStorage.getItem('sc_token');
    if (!token) {
        window.location.href = '/';
        return;
    }

    // ── DOM refs ─────────────────────────────────────────────────────────────
    const codeInput     = document.getElementById('code-input');
    const codeHighlight = document.getElementById('code-highlight');
    const scanBtn       = document.getElementById('scan-btn');
    const scanSpinner   = document.getElementById('scan-spinner');
    const btnText       = document.getElementById('btn-text');
    const detailsBody   = document.getElementById('details-body');
    const vulnBadge     = document.getElementById('vuln-count-badge');
    const terminalPanel = document.getElementById('terminal-container');
    const terminalOutput= document.getElementById('terminal-output');
    const terminalClose = document.getElementById('terminal-close');
    const lineNumbers   = document.getElementById('line-numbers');
    const editorContainer = document.querySelector('.editor-container');
    const progressBar   = document.getElementById('progress-bar');
    const progressLabel = document.getElementById('progress-label');
    const progressWrap  = document.getElementById('progress-wrap');
    const aiToggle      = document.getElementById('ai-toggle');
    const exportJsonBtn = document.getElementById('export-json-btn');
    const sabotageBtn   = document.getElementById('sabotage-btn');
    const exploitToggle = document.getElementById('exploit-toggle');

    const sabotageModal = document.getElementById('sabotage-modal');
    const sabotageVulnsList = document.getElementById('sabotage-vulns-list');
    const sabotageCount = document.getElementById('sab-count');
    const sabotageRevertBtn = document.getElementById('sabotage-revert-btn');
    const sabotageProceedBtn = document.getElementById('sabotage-proceed-btn');
    const closeSabotageModal = document.getElementById('close-sabotage-modal');

    let currentScanData = null;
    let currentProjectData = null;
    let currentWs       = null;
    let aiEnabled       = false;
    let originalCode    = '';

    // ── Sabotage (Inject Vulnerabilities) ────────────────────────────────────
    sabotageBtn?.addEventListener('click', async () => {
        console.log('Sabotage button clicked');
        const code = codeInput.value.trim();
        if (!code) {
            alert('Please enter some code first.');
            return;
        }

        originalCode = code; // Store for revert
        sabotageBtn.disabled = true;
        sabotageBtn.textContent = '⚔ SABOTAGING...';
        
        try {
            const resp = await fetch('/api/sabotage', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source_code: code })
            });
            
            if (!resp.ok) {
                const err = await resp.json();
                throw new Error(err.detail || 'Sabotage failed');
            }
            
            const data = await resp.json();
            // The API now returns {"new_code": "...", "summary": [...]}
            const newCode = data.new_code || '';
            codeInput.value = newCode;
            
            // Trigger UI updates
            codeInput.dispatchEvent(new Event('input'));
            
            // Show Sabotage Reveal Modal with the summary
            renderSabotageReport(data);
            
            // Flash success effect on editor
            editorContainer.style.boxShadow = 'inset 0 0 50px rgba(255,45,85,0.2)';
            setTimeout(() => editorContainer.style.boxShadow = '', 1000);
            
        } catch (err) {
            alert('Sabotage Error: ' + err.message);
        } finally {
            sabotageBtn.disabled = false;
            sabotageBtn.textContent = '⚔ SABOTAGE';
        }
    });

    function renderSabotageReport(data) {
        const vulns = data.summary || [];
        sabotageCount.textContent = vulns.length;
        sabotageVulnsList.innerHTML = vulns.map(v => `
            <div class="sab-vuln-item">
                <span class="sab-vuln-type">${esc(v.vuln_type)}</span>
                <span class="sab-vuln-expl">${esc(v.explanation)}</span>
                ${v.line ? `<span class="sab-vuln-line">TARGET: Line ${v.line}</span>` : ''}
            </div>
        `).join('') || '<p style="color:var(--text-muted);font-size:12px;">No specific details provided by AI, but code has been modified.</p>';
        
        sabotageModal.classList.add('visible');
    }

    sabotageRevertBtn?.addEventListener('click', () => {
        if (originalCode) {
            codeInput.value = originalCode;
            codeInput.dispatchEvent(new Event('input'));
            sabotageModal.classList.remove('visible');
        }
    });

    sabotageProceedBtn?.addEventListener('click', () => {
        sabotageModal.classList.remove('visible');
        scanBtn.click(); // Trigger scan
    });

    closeSabotageModal?.addEventListener('click', () => {
        sabotageModal.classList.remove('visible');
    });

    // ── Export Report ────────────────────────────────────────────────────────
    exportJsonBtn?.addEventListener('click', () => {
        let exportData = null;
        let prefix = 'report';

        if (scannerView.style.display === 'flex' && currentScanData) {
            exportData = currentScanData;
            prefix = 'scan-report';
        } else if (projectView.style.display === 'flex' && currentProjectData) {
            exportData = currentProjectData;
            prefix = 'project-analysis';
        }

        if (!exportData) {
            alert('No data available to export in the current view. Run a scan or analysis first.');
            return;
        }

        const dataStr = JSON.stringify(exportData, null, 2);
        const blob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `shadowcoder-${prefix}-${new Date().getTime()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });

    // ── Navigation (View Switching) ──────────────────────────────────────────
    const navLinks = document.querySelectorAll('.nav-links li');
    const scannerView = document.getElementById('scanner-view');
    const projectView = document.getElementById('project-view');
    const scansView   = document.getElementById('scans-view');
    const settingsView = document.getElementById('settings-view');
    const billingView = document.getElementById('billing-view');
    const apiKeysView = document.getElementById('api-keys-view');
    const cicdView    = document.getElementById('cicd-view');

    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            const text = link.textContent.trim().toLowerCase();
            if (text.includes('dashboard')) {
                showView('scanner');
                setActiveLink(link);
            } else if (text.includes('scans')) {
                showView('scans');
                setActiveLink(link);
                loadScanHistory();
            } else if (text.includes('project analysis')) {
                showView('project');
                setActiveLink(link);
            } else if (text.includes('api keys')) {
                showView('api-keys');
                setActiveLink(link);
                loadApiKeys();
            } else if (text.includes('ci/cd')) {
                showView('cicd');
                setActiveLink(link);
                loadCiCd();
            } else if (text.includes('billing')) {
                showView('billing');
                setActiveLink(link);
                loadBillingData();
            } else if (text.includes('settings')) {
                showView('settings');
                setActiveLink(link);
            }
        });
    });

    function showView(view) {
        scannerView.style.display = view === 'scanner' ? 'flex' : 'none';
        projectView.style.display = view === 'project' ? 'flex' : 'none';
        scansView.style.display   = view === 'scans' ? 'flex' : 'none';
        settingsView.style.display = view === 'settings' ? 'flex' : 'none';
        billingView.style.display = view === 'billing' ? 'flex' : 'none';
        apiKeysView.style.display = view === 'api-keys' ? 'flex' : 'none';
        cicdView.style.display    = view === 'cicd' ? 'flex' : 'none';
    }

    // ── API Keys ───────────────────────────────────────────────────────────
    const keysListBody = document.getElementById('keys-list-body');
    const newKeyDisplay = document.getElementById('new-key-display');
    const newKeyRaw = document.getElementById('new-key-raw');

    async function loadApiKeys() {
        if (!keysListBody) return;
        const token = localStorage.getItem('sc_token');
        try {
            const resp = await fetch('/api/user/api-keys', { headers: { 'Authorization': `Bearer ${token}` } });
            if (!resp.ok) throw new Error('Failed to load keys');
            const data = await resp.json();
            
            if (data.api_keys.length === 0) {
                keysListBody.innerHTML = '<div style="padding: 20px; color: var(--text-muted); font-size: 13px;">No API keys found.</div>';
                return;
            }

            keysListBody.innerHTML = data.api_keys.map((k, i) => `
                <div style="display: flex; align-items: center; padding: 14px 20px; border-bottom: ${i < data.api_keys.length - 1 ? '1px solid var(--border)' : 'none'}; gap: 16px;">
                    <div style="flex: 1;">
                        <div style="font-size: 13px; font-weight: 600; color: #fff;">${esc(k.name)}</div>
                        <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); margin-top: 2px;">${esc(k.key_prefix)}</div>
                    </div>
                    <div style="font-size: 11px; color: var(--text-muted);">Last used: ${k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : 'Never'}</div>
                    <div style="font-size: 11px; color: var(--text-muted);">${k.total_requests} req</div>
                    <div style="padding: 2px 8px; border-radius: 4px; font-size: 10px; font-family: var(--font-mono); ${k.active ? 'background: rgba(0,255,136,0.1); color: var(--green);' : 'background: rgba(255,255,255,0.05); color: var(--text-muted);'}">${k.active ? 'ACTIVE' : 'REVOKED'}</div>
                    ${k.active ? `<button onclick="revokeApiKey('${k.key_id}')" style="background: none; border: 1px solid var(--border); border-radius: 4px; color: var(--text-muted); cursor: pointer; padding: 4px 8px; font-size: 11px;">✕</button>` : '<div style="width: 26px;"></div>'}
                </div>
            `).join('');
        } catch (e) {
            keysListBody.innerHTML = `<div style="padding: 20px; color: var(--red); font-size: 13px;">${e.message}</div>`;
        }
    }

    document.getElementById('create-key-btn')?.addEventListener('click', async () => {
        const nameInput = document.getElementById('new-key-name');
        const token = localStorage.getItem('sc_token');
        try {
            const resp = await fetch('/api/user/api-keys', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ name: nameInput.value || 'Production' })
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.detail || 'Failed to create key');
            
            newKeyRaw.textContent = data.raw_key;
            newKeyDisplay.style.display = 'block';
            nameInput.value = '';
            loadApiKeys();
        } catch (e) { alert(e.message); }
    });

    window.revokeApiKey = async (id) => {
        if (!confirm('Revoke this API key? This cannot be undone.')) return;
        const token = localStorage.getItem('sc_token');
        try {
            await fetch(`/api/user/api-keys/${id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } });
            loadApiKeys();
        } catch (e) { alert('Failed to revoke key'); }
    };

    // ── CI/CD ──────────────────────────────────────────────────────────────
    const ciListBody = document.getElementById('ci-list-body');
    
    async function loadCiCd() {
        if (!ciListBody) return;
        const token = localStorage.getItem('sc_token');
        try {
            // Check plan first
            const meResp = await fetch('/api/user/me', { headers: { 'Authorization': `Bearer ${token}` } });
            const meData = await meResp.json();
            const canUse = ['pro', 'team', 'enterprise'].includes(meData.user?.plan);
            
            if (!canUse) {
                document.getElementById('cicd-upgrade-notice').style.display = 'block';
                document.getElementById('cicd-content').style.display = 'none';
                return;
            }
            document.getElementById('cicd-upgrade-notice').style.display = 'none';
            document.getElementById('cicd-content').style.display = 'block';

            const resp = await fetch('/api/user/ci-tokens', { headers: { 'Authorization': `Bearer ${token}` } });
            if (!resp.ok) throw new Error('Failed to load tokens');
            const data = await resp.json();

            if (data.ci_tokens.length === 0) {
                ciListBody.innerHTML = '<div style="padding: 20px; color: var(--text-muted); font-size: 13px;">No CI/CD tokens found.</div>';
                return;
            }

            ciListBody.innerHTML = data.ci_tokens.map((k, i) => `
                <div style="display: flex; align-items: center; padding: 14px 20px; border-bottom: ${i < data.ci_tokens.length - 1 ? '1px solid var(--border)' : 'none'}; gap: 16px;">
                    <div style="flex: 1;">
                        <div style="font-size: 13px; font-weight: 600; color: #fff;">${esc(k.repo)}</div>
                        <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); margin-top: 2px;">${esc(k.name)}</div>
                    </div>
                    <div style="font-family: var(--font-mono); font-size: 11px; color: var(--green);">${esc(k.token)}</div>
                    <div style="font-size: 11px; color: var(--text-muted);">Runs: ${k.total_runs}</div>
                    <div style="padding: 2px 8px; border-radius: 4px; font-size: 10px; font-family: var(--font-mono); ${k.active ? 'background: rgba(0,255,136,0.1); color: var(--green);' : 'background: rgba(255,255,255,0.05); color: var(--text-muted);'}">${k.active ? 'ACTIVE' : 'REVOKED'}</div>
                    ${k.active ? `<button onclick="revokeCiToken('${k.token}')" style="background: none; border: 1px solid var(--border); border-radius: 4px; color: var(--text-muted); cursor: pointer; padding: 4px 8px; font-size: 11px;">✕</button>` : '<div style="width: 26px;"></div>'}
                </div>
            `).join('');
        } catch (e) {
            ciListBody.innerHTML = `<div style="padding: 20px; color: var(--red); font-size: 13px;">${e.message}</div>`;
        }
    }

    document.getElementById('create-ci-btn')?.addEventListener('click', async () => {
        const repoInput = document.getElementById('ci-repo-name');
        const nameInput = document.getElementById('ci-token-name');
        if (!repoInput.value) return;

        const token = localStorage.getItem('sc_token');
        try {
            const resp = await fetch('/api/user/ci-tokens', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ repo: repoInput.value, name: nameInput.value || 'CI Pipeline' })
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.detail || 'Failed to create token');
            
            repoInput.value = '';
            nameInput.value = '';
            loadCiCd();
        } catch (e) { alert(e.message); }
    });

    window.revokeCiToken = async (id) => {
        if (!confirm('Revoke this CI/CD token?')) return;
        const token = localStorage.getItem('sc_token');
        try {
            await fetch(`/api/user/ci-tokens/${id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } });
            loadCiCd();
        } catch (e) { alert('Failed to revoke token'); }
    };

    // ── Scan History ────────────────────────────────────────────────────────
    const scansHistoryBody = document.getElementById('scans-history-body');
    let scanHistory = JSON.parse(localStorage.getItem('sc_history') || '[]');

    async function loadScanHistory() {
        if (!scansHistoryBody) return;
        
        const token = localStorage.getItem('sc_token');
        if (token) {
            try {
                scansHistoryBody.innerHTML = '<div class="ai-loading"><span class="ai-pulse"></span> Syncing history...</div>';
                const resp = await fetch('/api/user/scans', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (resp.ok) {
                    const data = await resp.json();
                    scanHistory = data.scans.map(s => ({
                        date: s.scanned_at,
                        filename: s.filename,
                        vulnerabilities: s.vulnerabilities_found,
                        source: s.source_code || '# Source code not available'
                    }));
                }
            } catch (e) {
                console.error("Failed to sync scans:", e);
            }
        }

        if (scanHistory.length === 0) {
            scansHistoryBody.innerHTML = '<div class="empty-state"><p class="empty-sub">No recent scans found.</p></div>';
            return;
        }

        scansHistoryBody.innerHTML = scanHistory.map((scan, idx) => `
            <div class="scan-history-item">
                <div class="scan-info">
                    <span class="scan-file">${esc(scan.filename || 'stdin')}</span>
                    <span class="scan-date">${new Date(scan.date).toLocaleString()}</span>
                </div>
                <div class="scan-stats">
                    <span class="scan-vulns">${scan.vulnerabilities} VULNS</span>
                    <button class="btn-view-scan" onclick="restoreScan(${idx})">VIEW</button>
                </div>
            </div>
        `).join('');
    }

    window.restoreScan = (idx) => {
        const scan = scanHistory[idx];
        if (!scan) return;
        codeInput.value = scan.source;
        showView('scanner');
        setActiveLink(navLinks[0]);
        // Trigger highlight update
        codeInput.dispatchEvent(new Event('input'));
    };

    document.getElementById('clear-history-btn')?.addEventListener('click', () => {
        if (confirm('Clear all scan history?')) {
            localStorage.removeItem('sc_history');
            scanHistory.length = 0;
            loadScanHistory();
        }
    });

    // ── Settings ───────────────────────────────────────────────────────────
    document.getElementById('save-settings-btn')?.addEventListener('click', async () => {
        const config = {
            model: document.getElementById('setting-ai-model').value,
            sandbox: document.getElementById('setting-sandbox-level').value,
            depth: document.getElementById('setting-scan-depth').value
        };
        localStorage.setItem('sc_config', JSON.stringify(config));
        
        const token = localStorage.getItem('sc_token');
        if (token) {
            try {
                await fetch('/api/user/me', {
                    method: 'PATCH',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}` 
                    },
                    body: JSON.stringify({ settings: config })
                });
            } catch (e) {
                console.error("Failed to sync settings:", e);
            }
        }
        alert('Configuration saved successfully.');
    });

    // Load initial settings
    async function loadInitialSettings() {
        const token = localStorage.getItem('sc_token');
        if (token) {
            try {
                const resp = await fetch('/api/user/me', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (resp.ok) {
                    const data = await resp.json();
                    if (data.user && data.user.settings) {
                        localStorage.setItem('sc_config', JSON.stringify(data.user.settings));
                    }
                }
            } catch (e) {
                console.error("Failed to load settings:", e);
            }
        }

        const config = JSON.parse(localStorage.getItem('sc_config') || '{}');
        if (config.model) document.getElementById('setting-ai-model').value = config.model;
        if (config.sandbox) document.getElementById('setting-sandbox-level').value = config.sandbox;
        if (config.depth) document.getElementById('setting-scan-depth').value = config.depth;
    }
    loadInitialSettings();

    // ── Billing (SaaS Integration) ──────────────────────────────────────────
    const plansGrid = document.getElementById('plans-grid');
    const billingStatusBody = document.getElementById('billing-status-body');

    async function loadBillingData() {
        if (!plansGrid) return;
        
        plansGrid.innerHTML = '<div class="ai-loading"><span class="ai-pulse"></span> Synchronizing with billing engine...</div>';
        
        try {
            const resp = await fetch('/api/billing/plans');
            const data = await resp.json();
            renderPlans(data.plans);
            
            // Try to load user subscription if token exists
            const token = localStorage.getItem('sc_token');
            if (token) {
                const subResp = await fetch('/api/billing/subscription', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (subResp.ok) {
                    const subData = await subResp.json();
                    renderSubscriptionStatus(subData);
                } else {
                    billingStatusBody.innerHTML = '<p class="detail-text">Session expired. <a href="/static/dashboard/index.html" style="color:var(--green)">Login to manage subscription</a></p>';
                }
            } else {
                billingStatusBody.innerHTML = '<p class="detail-text">Authentication required. <a href="/static/dashboard/index.html" style="color:var(--green)">Login/Register</a> to upgrade.</p>';
            }
        } catch (e) {
            plansGrid.innerHTML = `<div class="empty-state"><p class="empty-title" style="color:var(--sev-critical)">BILLING ERROR</p><p class="empty-sub">${e.message}</p></div>`;
        }
    }

    function renderPlans(plans) {
        if (!plans) return;
        const planOrder = ['free', 'pro', 'team', 'enterprise'];
        const planColors = { free: 'var(--text-muted)', pro: 'var(--cyan)', team: 'var(--purple)', enterprise: 'var(--green)' };

        plansGrid.innerHTML = planOrder.filter(p => plans[p]).map(key => {
            const p = plans[key];
            const color = planColors[key];
            const isEnterprise = key === 'enterprise';
            
            return `
                <div class="plan-card" style="border-top: 2px solid ${color}">
                    <div class="plan-header">
                        <span class="plan-name" style="color:${color}">${key.toUpperCase()}</span>
                        <div class="plan-price">
                            ${p.price_monthly === 0 ? 'FREE' : p.price_monthly === null ? 'CUSTOM' : `$${p.price_monthly}<span class="price-period">/mo</span>`}
                        </div>
                    </div>
                    <ul class="plan-features">
                        ${(p.features || []).map(f => `<li><span class="feat-icon">✓</span> ${esc(f)}</li>`).join('')}
                    </ul>
                    ${isEnterprise 
                        ? `<a href="mailto:sales@shadowcoder.dev" class="btn-plan-action enterprise">CONTACT SALES</a>`
                        : `<button class="btn-plan-action ${key}" onclick="initiateCheckout('${key}')">UPGRADE TO ${key.toUpperCase()}</button>`
                    }
                </div>
            `;
        }).join('');
    }

    function renderSubscriptionStatus(data) {
        const sub = data.subscription || {};
        const plan = data.plan || {};
        billingStatusBody.innerHTML = `
            <div class="status-grid">
                <div class="status-item">
                    <span class="status-lbl">CURRENT_PLAN</span>
                    <span class="status-val" style="color:var(--green)">${(sub.plan || 'free').toUpperCase()}</span>
                </div>
                <div class="status-item">
                    <span class="status-lbl">STATUS</span>
                    <span class="status-val">${(sub.status || 'inactive').toUpperCase()}</span>
                </div>
                <div class="status-item">
                    <span class="status-lbl">MONTHLY_QUOTA</span>
                    <span class="status-val">${data.quota?.used} / ${data.quota?.limit === -1 ? '∞' : data.quota?.limit}</span>
                </div>
            </div>
            <div class="section-divider"></div>
            <button class="btn-portal" onclick="openBillingPortal()">MANAGE VIA STRIPE PORTAL</button>
        `;
    }

    window.initiateCheckout = async (plan) => {
        const token = localStorage.getItem('sc_token');
        if (!token) { window.location.href = '/static/dashboard/index.html'; return; }
        
        try {
            const resp = await fetch('/api/billing/checkout', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ plan, billing_period: 'monthly' })
            });
            const data = await resp.json();
            if (data.checkout_url) window.location.href = data.checkout_url;
            else alert(data.detail || 'Checkout failed');
        } catch (e) { alert('Error: ' + e.message); }
    };

    window.openBillingPortal = async () => {
        const token = localStorage.getItem('sc_token');
        try {
            const resp = await fetch('/api/billing/portal', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await resp.json();
            if (data.portal_url) window.location.href = data.portal_url;
        } catch (e) { alert('Error: ' + e.message); }
    };

    function setActiveLink(activeEl) {
        navLinks.forEach(l => l.classList.remove('active'));
        activeEl.classList.add('active');
        // Add/remove dots
        document.querySelectorAll('.nav-dot').forEach(d => d.remove());
        const dot = document.createElement('span');
        dot.className = 'nav-dot';
        activeEl.appendChild(dot);
    }

    // ── Project Analysis (Phase 6) ───────────────────────────────────────────
    const analyzeProjectBtn = document.getElementById('analyze-project-btn');
    const projectPathInput  = document.getElementById('project-path');
    const surfaceBody       = document.getElementById('surface-body');
    const endpointsBody     = document.getElementById('endpoints-body');
    const flowsBody         = document.getElementById('flows-body');

    analyzeProjectBtn?.addEventListener('click', async () => {
        const path = projectPathInput.value.trim();
        if (!path) return;

        analyzeProjectBtn.disabled = true;
        analyzeProjectBtn.innerHTML = '<span class="spinner" style="display:inline-block"></span> ANALYZING...';
        
        surfaceBody.innerHTML = '<div class="ai-loading"><span class="ai-pulse"></span> Scanning project structure...</div>';
        endpointsBody.innerHTML = '';
        flowsBody.innerHTML = '';

        try {
            const resp = await fetch('/api/project/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ project_root: path })
            });
            if (!resp.ok) throw new Error(await resp.text());
            const data = await resp.json();
            currentProjectData = data;
            renderProjectAnalysis(data);
        } catch (e) {
            console.error(e);
            surfaceBody.innerHTML = `<div class="empty-state"><p class="empty-title" style="color:var(--sev-critical)">ANALYSIS ERROR</p><p class="empty-sub">${e.message}</p></div>`;
            currentProjectData = null;
        } finally {
            analyzeProjectBtn.disabled = false;
            analyzeProjectBtn.innerHTML = '<span class="btn-icon">🔍</span> RUN FULL ANALYSIS';
        }
    });

    function renderProjectAnalysis(data) {
        // 1. Surface Score
        const s = data.security_surface;
        const scoreClass = s.attack_surface_score > 70 ? 'high' : s.attack_surface_score > 40 ? 'med' : 'low';
        
        surfaceBody.innerHTML = `
            <div class="surface-stats">
                <div class="surface-score-box">
                    <span class="score-val ${scoreClass}">${s.attack_surface_score}</span>
                    <span class="score-lbl">ATTACK SURFACE SCORE</span>
                </div>
                <div class="mini-stat-grid">
                    <div class="mini-stat"><span class="mini-val">${s.total_endpoints}</span><span class="mini-lbl">ENDPOINTS</span></div>
                    <div class="mini-stat"><span class="mini-val">${s.data_flows}</span><span class="mini-lbl">DATA FLOWS</span></div>
                    <div class="mini-stat"><span class="mini-val">${s.high_risk_endpoints}</span><span class="mini-lbl">HIGH RISK</span></div>
                    <div class="mini-stat"><span class="mini-val">${s.cross_file_taints}</span><span class="mini-lbl">CROSS-FILE</span></div>
                </div>
                <div class="section-divider"></div>
                <p class="section-title">PROJECT METRICS</p>
                <div class="metrics-list">
                    <div class="metric-row"><span>Files Analyzed:</span><span>${data.files_analyzed}</span></div>
                    <div class="metric-row"><span>Total Lines:</span><span>${data.total_lines.toLocaleString()}</span></div>
                    <div class="metric-row"><span>DB Touching:</span><span>${s.db_touching_flows}</span></div>
                    <div class="metric-row"><span>Net Touching:</span><span>${s.network_touching_flows}</span></div>
                </div>
            </div>
        `;

        // 2. Dependencies
        const depsBody = document.getElementById('deps-body');
        const depCountBadge = document.getElementById('dep-count-badge');
        if (depsBody && data.dependencies) {
            depCountBadge.textContent = `${data.files_analyzed} FILES`;
            depsBody.innerHTML = data.dependencies.map(dep => {
                const fileName = dep.source_file.split(/[\\/]/).pop();
                return `
                    <div class="dep-node">
                        <div class="dep-node-header">
                            <span class="dep-file-icon">📄</span>
                            <span class="dep-file-name">${esc(fileName)}</span>
                            ${dep.imported_by.length > 0 ? `<span class="dep-usage-badge">${dep.imported_by.length} refs</span>` : ''}
                        </div>
                        <div class="dep-node-details">
                            ${dep.imports.length > 0 ? `
                                <div class="dep-sub-list">
                                    <span class="dep-sub-label">IMPORTS:</span>
                                    <div class="dep-tags">${dep.imports.map(i => `<span class="dep-tag">${esc(i)}</span>`).join('')}</div>
                                </div>
                            ` : ''}
                            ${dep.exports.length > 0 ? `
                                <div class="dep-sub-list">
                                    <span class="dep-sub-label">EXPORTS:</span>
                                    <div class="dep-tags">${dep.exports.map(e => `<span class="dep-tag export">${esc(e)}</span>`).join('')}</div>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
            }).join('');
        }

        // 3. Endpoints
        if (data.endpoints?.length) {
            endpointsBody.innerHTML = data.endpoints.map(ep => `
                <div class="project-item endpoint-card ${ep.risk_score >= 70 ? 'critical' : ep.risk_score >= 40 ? 'high' : ''}">
                    <div class="ep-row">
                        <span class="ep-method ${ep.method}">${ep.method}</span>
                        <span class="ep-path">${esc(ep.path)}</span>
                        <div class="ep-risk-group">
                            <div class="risk-bar-bg"><div class="risk-bar-fill" style="width:${ep.risk_score}%"></div></div>
                            <span class="ep-risk">${ep.risk_score}%</span>
                        </div>
                    </div>
                    <div class="ep-details">
                        <div class="ep-handler-info">
                            <span class="ep-handler-icon">ƒ</span>
                            <code>${esc(ep.handler)}()</code> 
                            <span class="ep-file-link">in ${esc(ep.file.split(/[\\/]/).pop())}:${ep.line}</span>
                        </div>
                        ${ep.params.length > 0 ? `<div class="ep-params">Params: ${ep.params.map(p => `<span class="param-tag">${esc(p)}</span>`).join('')}</div>` : ''}
                        <div class="ep-reasons">
                            ${ep.risk_reasons.map(r => `<div class="ep-reason">${esc(r)}</div>`).join('')}
                        </div>
                        ${ep.calls.length > 0 ? `
                            <div class="ep-calls-trace">
                                <span class="trace-label">INTERNAL CALLS:</span>
                                <div class="trace-list">${ep.calls.map(c => `<span class="trace-call">${esc(c)}</span>`).join(' → ')}</div>
                            </div>
                        ` : ''}
                        <div class="ep-actions" style="display:flex;gap:8px">
                            <button class="btn-simulate-ep" data-file="${esc(ep.file)}" data-path="${esc(ep.path)}">⚡ SIMULATE PROBE</button>
                            <button class="ai-btn project-ai-btn" data-action="explain-ep" data-file="${esc(ep.file)}" data-ep='${JSON.stringify(ep).replace(/'/g,"&#39;")}'>💡 AI EXPLAIN</button>
                            <button class="ai-btn project-ai-btn" data-action="fix-ep" data-file="${esc(ep.file)}" data-ep='${JSON.stringify(ep).replace(/'/g,"&#39;")}'>🔧 AI FIX</button>
                        </div>
                        <div class="ai-result project-ai-result" id="ai-result-ep-${esc(ep.handler)}-${ep.line}"></div>
                    </div>
                </div>
            `).join('');
        } else {
            endpointsBody.innerHTML = '<div class="empty-state"><p class="empty-sub">No API endpoints detected.</p></div>';
        }

        // 4. Flows
        if (data.data_flows?.length) {
            flowsBody.innerHTML = data.data_flows.map(flow => `
                <div class="project-item flow-card">
                    <div class="flow-header">
                        <div class="flow-title-group">
                            <span class="flow-id">${flow.path_id}</span>
                            <span class="flow-desc">${esc(flow.description)}</span>
                        </div>
                        <span class="flow-risk-pill ${flow.risk}">${flow.risk}</span>
                    </div>
                    <div class="flow-timeline">
                        ${flow.stages.map((step, idx) => `
                            <div class="timeline-step">
                                <div class="step-marker">
                                    <div class="step-dot"></div>
                                    ${idx < flow.stages.length - 1 ? '<div class="step-line"></div>' : ''}
                                </div>
                                <div class="step-content">
                                    <span class="step-stage">${step.stage}</span>
                                    <span class="step-detail">${esc(step.detail)}</span>
                                    <span class="step-loc">${esc(step.file.split(/[\\/]/).pop())}:${step.line}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                    <div class="flow-flags-row">
                        <div class="flow-flags">
                            ${flow.involves_db ? '<span class="flow-flag db">DB</span>' : ''}
                            ${flow.involves_network ? '<span class="flow-flag net">NET</span>' : ''}
                            ${flow.involves_file_io ? '<span class="flow-flag file">FILE</span>' : ''}
                        </div>
                        <div style="display:flex;gap:8px">
                            <button class="btn-simulate-flow" data-file="${esc(flow.stages[0].file)}" data-id="${flow.path_id}">▶ SIMULATE FLOW</button>
                            <button class="ai-btn project-ai-btn" data-action="explain-flow" data-file="${esc(flow.stages[0].file)}" data-flow='${JSON.stringify(flow).replace(/'/g,"&#39;")}'>💡 AI EXPLAIN</button>
                            <button class="ai-btn project-ai-btn" data-action="fix-flow" data-file="${esc(flow.stages[0].file)}" data-flow='${JSON.stringify(flow).replace(/'/g,"&#39;")}'>🔧 AI FIX</button>
                        </div>
                    </div>
                    <div class="ai-result project-ai-result" id="ai-result-flow-${flow.path_id}"></div>
                </div>
            `).join('');
        } else {
            flowsBody.innerHTML = '<div class="empty-state"><p class="empty-sub">No complex data flows traced.</p></div>';
        }

        // Bind simulate buttons
        document.querySelectorAll('.btn-simulate-ep').forEach(btn => {
            btn.addEventListener('click', async () => {
                const file = btn.getAttribute('data-file');
                const path = btn.getAttribute('data-path');
                await runProjectSimulation(file, `[PROBE] ${path}`);
            });
        });
        document.querySelectorAll('.btn-simulate-flow').forEach(btn => {
            btn.addEventListener('click', async () => {
                const file = btn.getAttribute('data-file');
                const id = btn.getAttribute('data-id');
                await runProjectSimulation(file, `[FLOW] ${id} EXPLOIT`);
            });
        });

        // Bind AI buttons
        document.querySelectorAll('.project-ai-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const action = btn.getAttribute('data-action');
                const filePath = btn.getAttribute('data-file');
                const data = action.includes('-ep') 
                    ? JSON.parse(btn.getAttribute('data-ep'))
                    : JSON.parse(btn.getAttribute('data-flow'));
                await loadProjectAiDetail(action, filePath, data, btn);
            });
        });
    }

    async function loadProjectAiDetail(action, filePath, data, btn) {
        const isEp = action.includes('-ep');
        const isFix = action.startsWith('fix-');
        const resultId = isEp ? `ai-result-ep-${data.handler}-${data.line}` : `ai-result-flow-${data.path_id}`;
        const resultEl = document.getElementById(resultId);
        if (!resultEl) return;

        btn.disabled = true;
        btn.textContent = isFix ? '🔧 Generating...' : '💡 Thinking...';
        resultEl.innerHTML = `<div class="ai-loading"><span class="ai-pulse"></span> Querying AI...</div>`;

        try {
            // 1. Get file content for context
            const fResp = await fetch(`/api/file?path=${encodeURIComponent(filePath)}`);
            const { content } = await fResp.json();
            const lines = content.split('\n');
            const startLine = isEp ? data.line : data.stages[0].line;
            const context = lines.slice(Math.max(0, startLine - 10), startLine + 10).join('\n');

            // 2. Construct a mock vulnerability object for the AI
            const mockVuln = isEp ? {
                vuln_type: `Endpoint Risk: ${data.method} ${data.path}`,
                description: `Potential vulnerability in API handler ${data.handler}(). Risk Reasons: ${data.risk_reasons.join(', ')}`,
                line: data.line,
                cwe: 'N/A',
                owasp: 'A1:2021-Broken Access Control'
            } : {
                vuln_type: `Data Flow Risk: ${data.path_id}`,
                description: `Untrusted data flow from entry point to potential sink. Flow: ${data.description}. Risk Level: ${data.risk}`,
                line: data.stages[0].line,
                cwe: 'N/A',
                owasp: 'A3:2021-Injection'
            };

            const endpoint = isFix ? '/api/ai/fix' : '/api/ai/explain';
            const body = isFix 
                ? { vulnerability: mockVuln, source_code: content }
                : { vulnerability: mockVuln, code_context: context };

            const resp = await fetch(endpoint, {
                method: 'POST', 
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(body)
            });
            const aiData = await resp.json();
            const text = aiData.explanation || aiData.fix || '';
            const aiPowered = aiData.ai_powered;

            resultEl.innerHTML = `
                <div class="ai-result-box ${aiPowered ? 'ai-powered' : 'ai-fallback'}">
                    <div class="ai-result-header">
                        <span>${aiPowered ? '🦙 Llama 3' : '📚 Static'}</span>
                        <span class="ai-action-label">PROJECT ANALYSIS</span>
                    </div>
                    <div class="ai-result-text">${formatAiText(text)}</div>
                </div>
            `;
        } catch (e) {
            resultEl.innerHTML = `<div class="ai-result-box ai-fallback"><div class="ai-result-text">AI unavailable: ${e.message}</div></div>`;
        }
        btn.disabled = false;
        btn.textContent = isFix ? '🔧 AI FIX' : '💡 AI EXPLAIN';
    }

    async function runProjectSimulation(filePath, payload) {
        try {
            const resp = await fetch(`/api/file?path=${encodeURIComponent(filePath)}`);
            if (!resp.ok) throw new Error('Could not load file');
            const { content } = await resp.json();
            
            // Switch terminal to project analysis context if needed (handled by making it global)
            await runSimulationInternal(content, payload);
        } catch (e) {
            alert('Simulation failed: ' + e.message);
        }
    }

    // Refactor runSimulation to be reusable
    async function runSimulationInternal(code, payload) {
        terminalPanel.classList.add('visible');
        terminalOutput.className = 'terminal-output';
        let out = `[${new Date().toISOString()}] SHADOWCODER SANDBOX v2.0\n[*] Project Context: Active\n[*] Injecting: ${payload}\n[*] Tracing execution...\n\n`;
        terminalOutput.textContent = out;

        try {
            const resp = await fetch('/api/simulate', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source_code: code, payload })
            });
            const data = await resp.json();
            const lines = data.success
                ? [`[+] EXPLOIT TRIGGERED`, `[+] Output:`, '', ...data.output.split('\n'), '', '[!] Root/admin path confirmed']
                : [`[-] Exploit mitigated`, ...data.output.split('\n')];

            for (const line of lines) {
                out += line + '\n';
                terminalOutput.textContent = out;
                await sleep(40);
                terminalOutput.scrollTop = terminalOutput.scrollHeight;
            }
            terminalOutput.className = 'terminal-output ' + (data.success ? 'success' : 'failure');
        } catch (e) {
            terminalOutput.textContent += `\n[!] Sandbox error: ${e.message}`;
            terminalOutput.className = 'terminal-output failure';
        }
    }

    // ── Clock ────────────────────────────────────────────────────────────────
    setInterval(() => {
        const el = document.getElementById('sys-clock');
        if (el) el.textContent = new Date().toISOString().slice(11,19) + ' UTC';
    }, 1000);

    // ── AI toggle ────────────────────────────────────────────────────────────
    if (aiToggle) {
        aiToggle.addEventListener('click', () => {
            aiEnabled = !aiEnabled;
            aiToggle.classList.toggle('active', aiEnabled);
            aiToggle.textContent = aiEnabled ? '🤖 AI ON' : '🤖 AI OFF';
        });
    }

    // ── Terminal ─────────────────────────────────────────────────────────────
    terminalClose?.addEventListener('click', () => terminalPanel.classList.remove('visible'));

    // ── Line numbers ─────────────────────────────────────────────────────────
    function updateLineNumbers() {
        const n = codeInput.value.split('\n').length;
        lineNumbers.innerHTML = Array.from({length: n}, (_, i) => `<span>${i+1}</span>`).join('');
    }

    editorContainer?.addEventListener('scroll', () => {
        codeHighlight.scrollTop = editorContainer.scrollTop;
        codeHighlight.scrollLeft = editorContainer.scrollLeft;
        lineNumbers.scrollTop = editorContainer.scrollTop;
    });

    // ── Syntax highlighting ───────────────────────────────────────────────────
    let debounce;
    function updateCode() {
        if (typeof Prism === 'undefined') { setTimeout(updateCode, 100); return; }
        let text = codeInput.value;
        if (text.endsWith('\n')) text += ' ';
        let html = Prism.highlight(text, Prism.languages.python, 'python');
        
        // Always wrap lines for consistent layout
        html = applyVulnHighlights(html, currentScanData?.findings || []);
        
        codeHighlight.querySelector('code').innerHTML = html;
        updateLineNumbers();
    }

    codeInput.addEventListener('input', () => {
        currentScanData = null;
        vulnBadge.textContent = 'AWAITING SCAN';
        vulnBadge.className = 'badge-issues';
        resetStats();
        clearTimeout(debounce);
        debounce = setTimeout(updateCode, 150);
    });

    updateCode();

    // ── Stats ─────────────────────────────────────────────────────────────────
    function resetStats() {
        ['stat-critical','stat-high','stat-exploitable','stat-time'].forEach(id => {
            const el = document.querySelector(`#${id} .stat-val`);
            if (el) el.textContent = '—';
        });
    }

    function updateStats(data) {
        const f = data.findings || [];
        const crit = document.querySelector('#stat-critical .stat-val');
        const high = document.querySelector('#stat-high .stat-val');
        const expl = document.querySelector('#stat-exploitable .stat-val');
        const time = document.querySelector('#stat-time .stat-val');
        
        if (crit) crit.textContent = f.filter(x => x.severity === 'CRITICAL').length;
        if (high) high.textContent = f.filter(x => x.severity === 'HIGH').length;
        if (expl) expl.textContent = f.filter(x => x.exploitable).length;
        if (time) time.textContent = (data.scan_time_ms || 0) + 'ms';
    }

    // ── Progress bar ──────────────────────────────────────────────────────────
    function setProgress(pct, label) {
        if (!progressWrap) return;
        progressWrap.style.display = 'block';
        progressBar.style.width = pct + '%';
        progressLabel.textContent = label;
        if (pct >= 100) setTimeout(() => progressWrap.style.display = 'none', 1200);
    }

    // ── WebSocket scan (Phase 3) ──────────────────────────────────────────────
    scanBtn.addEventListener('click', async () => {
        const code = codeInput.value.trim();
        if (!code) return;

        // Close any existing WS
        if (currentWs) { currentWs.close(); currentWs = null; }

        scanBtn.disabled = true;
        scanSpinner.style.display = 'inline-block';
        btnText.textContent = 'SUBMITTING...';
        setProgress(5, 'Submitting scan job...');

        detailsBody.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon spinning">
                    <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
                        <circle cx="20" cy="20" r="16" stroke="#00ff88" stroke-width="1.5" stroke-dasharray="25 75" stroke-linecap="round"/>
                    </svg>
                </div>
                <p class="empty-title" id="scan-phase">INITIALIZING</p>
                <p class="empty-sub" id="scan-detail">Connecting to engine...</p>
            </div>
        `;

        try {
            // 1. Submit job
            const headers = { 'Content-Type': 'application/json' };
            const token = localStorage.getItem('sc_token');
            if (token) headers['Authorization'] = `Bearer ${token}`;

            const resp = await fetch('/api/scan', {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({ 
                    source_code: code, 
                    filename: 'editor.py', 
                    skip_ai: !aiEnabled,
                    exploit: exploitToggle?.checked || false
                })
            });
            if (!resp.ok) throw new Error(`Submit failed: ${resp.status}`);
            const { job_id, cached } = await resp.json();

            btnText.textContent = 'SCANNING...';

            // 2. Connect WebSocket for real-time progress
            const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(`${wsProto}//${location.host}/ws/${job_id}`);
            currentWs = ws;

            // Heartbeat
            const ping = setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send('ping'); }, 15000);

            ws.addEventListener('message', (evt) => {
                const msg = JSON.parse(evt.data);
                handleWsMessage(msg);
            });

            ws.addEventListener('error', () => {
                clearInterval(ping);
                fallbackPoll(job_id);
            });

            ws.addEventListener('close', () => clearInterval(ping));

        } catch (err) {
            console.error(err);
            detailsBody.innerHTML = `<div class="empty-state"><p class="empty-title" style="color:var(--sev-critical)">ERROR</p><p class="empty-sub">${err.message}</p></div>`;
            finishScan();
        }
    });

    function handleWsMessage(msg) {
        switch (msg.type) {
            case 'stage':
                updateStageDisplay(msg);
                setProgress(msg.progress, msg.label);
                break;
            case 'complete':
            case 'cached':
                setProgress(100, msg.type === 'cached' ? 'Cache hit!' : 'Scan complete');
                onScanComplete(msg.result, msg.type === 'cached');
                break;
            case 'error':
                setProgress(0, 'Error');
                onScanError(msg.error);
                break;
        }
    }

    function updateStageDisplay(msg) {
        const el = document.getElementById('scan-phase');
        const det = document.getElementById('scan-detail');
        if (el) el.textContent = msg.label?.toUpperCase() || msg.stage.toUpperCase();
        if (det) det.textContent = msg.detail || '';
    }

    async function fallbackPoll(job_id) {
        // Fallback: poll /api/scan/{job_id} if WS fails
        for (let i = 0; i < 60; i++) {
            await sleep(500);
            try {
                const r = await fetch(`/api/scan/${job_id}`);
                const d = await r.json();
                if (d.status === 'COMPLETE' || d.status === 'CACHED') {
                    onScanComplete(d.result, d.status === 'CACHED');
                    return;
                }
                if (d.status === 'FAILED') { onScanError(d.error); return; }
                if (d.stages?.length) {
                    const last = d.stages[d.stages.length - 1];
                    setProgress(last.progress, last.label);
                }
            } catch {}
        }
        onScanError('Scan timed out');
    }
    function onScanComplete(data, fromCache) {
        currentScanData = data;
        updateStats(data);
        updateCode();

        const n = data.vulnerabilities_found || 0;
        if (n === 0) {
            vulnBadge.textContent = '✓ CLEAN';
            vulnBadge.className = 'badge-issues clean';
            detailsBody.innerHTML = `<div class="empty-state"><div class="empty-icon">✅</div><p class="empty-title" style="color:var(--green)">NO VULNERABILITIES</p><p class="empty-sub">Static analysis complete. ${fromCache ? '(from cache)' : ''}</p></div>`;
        } else {
            vulnBadge.textContent = `⚠ ${n} ISSUES`;
            vulnBadge.className = 'badge-issues has-vulns';
            const cacheLabel = fromCache ? ' <span style="color:var(--cyan);font-size:10px">[CACHED]</span>' : '';
            detailsBody.innerHTML = `<div class="empty-state"><p class="empty-title" style="color:var(--sev-critical)">⚠ ${n} VULNERABILITIES${cacheLabel}</p><p class="empty-sub">Click any highlighted line to view attack details.</p></div>`;

            // Auto-load AI triage if enabled
            if (aiEnabled) loadAiTriage(data.findings);
        }
        finishScan();

        // Save to local history
        saveToHistory(data);
    }

    function saveToHistory(result) {
        const history = JSON.parse(localStorage.getItem('sc_history') || '[]');
        history.unshift({
            date: new Date().toISOString(),
            filename: result.target_file || 'stdin',
            vulnerabilities: result.vulnerabilities_found || 0,
            source: codeInput.value
        });
        localStorage.setItem('sc_history', JSON.stringify(history.slice(0, 50)));
    }

    function onScanError(err) {
        detailsBody.innerHTML = `<div class="empty-state"><p class="empty-title" style="color:var(--sev-critical)">SCAN ERROR</p><p class="empty-sub">${err}</p></div>`;
        finishScan();
    }

    function finishScan() {
        scanBtn.disabled = false;
        scanSpinner.style.display = 'none';
        btnText.textContent = 'EXECUTE SCAN';
    }

    // ── Vulnerability highlights ───────────────────────────────────────────────
    function applyVulnHighlights(html, findings = []) {
        let lines = html.split('\n');
        const byLine = {};
        findings.forEach((f, idx) => {
            const ln = f.vulnerability.line - 1;
            if (!byLine[ln]) byLine[ln] = [];
            byLine[ln].push({ ...f, _idx: idx });
        });
        const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        for (let i = 0; i < lines.length; i++) {
            const lineContent = lines[i] || ' ';
            const safeContent = lineContent === ' ' ? '&nbsp;' : lineContent;
            if (byLine[i]) {
                const sev = byLine[i].reduce((a, c) => order[c.severity] > order[a] ? c.severity : a, 'LOW');
                const idx = byLine[i].map(v => v._idx).join(',');
                lines[i] = `<span class="vuln-line severity-${sev}" data-vuln-idx="${idx}">${safeContent}</span>`;
            } else {
                lines[i] = `<span>${safeContent}</span>`;
            }
        }
        return lines.join('');
    }

    // ── Click to select vulnerability ─────────────────────────────────────────
    const handleClick = () => {
        if (!currentScanData?.findings) return;
        const cursor = codeInput.value.substring(0, codeInput.selectionStart);
        const line = cursor.split('\n').length - 1;
        const hits = currentScanData.findings.filter(f => (f.vulnerability.line - 1) === line);
        if (hits.length) renderDetails(hits);
    };
    codeInput.addEventListener('click', handleClick);
    codeInput.addEventListener('keyup', e => {
        if (['ArrowUp','ArrowDown','ArrowLeft','ArrowRight'].includes(e.key)) handleClick();
    });

    // ── Render finding details ────────────────────────────────────────────────
    function esc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
    const cvssMap = { CRITICAL: '9.8', HIGH: '7.5', MEDIUM: '5.3', LOW: '3.1' };

    function renderDetails(findings) {
        detailsBody.innerHTML = '';
        findings.forEach(finding => {
            const v = finding.vulnerability;
            const payloads = (finding.payloads || []).slice(0, 3);
            const payloadRaw = payloads[0]?.raw || '';

            let payloadHtml = '';
            if (payloads.length) {
                payloadHtml = `
                    <div class="section-divider"></div>
                    <p class="section-title">⚔ EXPLOIT PAYLOADS (${finding.payloads.length})</p>
                    ${payloads.map(p => `<div class="code-snippet">${esc(p.raw)}</div>`).join('')}
                    ${finding.exploitable ? `<button class="simulate-btn" data-payload="${btoa(unescape(encodeURIComponent(payloadRaw)))}">▶ RUN SANDBOX SIMULATION</button>` : ''}
                `;
            }

            let taintHtml = '';
            const tflow = finding.simulation?.taint_flow || [];
            if (tflow.length) {
                taintHtml = `
                    <div class="section-divider"></div>
                    <p class="section-title">⟶ TAINT PROPAGATION</p>
                    <div class="taint-flow">${tflow.slice(0,5).map(s => `<div class="taint-step">${esc(s)}</div>`).join('')}</div>
                `;
            }

            let chainHtml = '';
            let chainToRender = null;
            if (finding.chain_ids?.length) {
                const chain = currentScanData.attack_chains?.find(c => c.chain_id === finding.chain_ids[0]);
                if (chain) {
                    chainToRender = chain;
                    chainHtml = `
                        <div class="section-divider"></div>
                        <p class="section-title">⛓ ATTACK CHAIN — ${esc(chain.name)}</p>
                        <div id="vis-network-${finding.vulnerability.vuln_id}" style="width: 100%; height: 200px; background: rgba(0,0,0,0.3); border: 1px solid var(--border); border-radius: 6px; margin-top: 10px;"></div>
                    `;
                }
            }

            let simMeta = '';
            const sim = finding.simulation || {};
            const flags = [];
            if (sim.rce_possible) flags.push(`<span style="color:var(--sev-critical)">RCE</span>`);
            if (sim.data_exfil_possible) flags.push(`<span style="color:var(--sev-high)">DATA EXFIL</span>`);
            if (sim.privilege_escalation) flags.push(`<span style="color:var(--sev-medium)">PRIV ESC</span>`);
            if (sim.blast_radius) flags.push(`<span style="color:var(--cyan)">BLAST: ${sim.blast_radius}</span>`);
            if (flags.length) simMeta = `<div class="sim-flags">${flags.join('')}</div>`;

            detailsBody.insertAdjacentHTML('beforeend', `
                <div class="detail-card">
                    <div class="card-header">
                        <span class="severity-badge ${finding.severity}">${finding.severity}</span>
                        <div style="display:flex;gap:6px;align-items:center">
                            <span style="font-family:var(--font-mono);font-size:9px;color:var(--sev-medium)">CVSS ${cvssMap[finding.severity] || '—'}</span>
                            <span class="id-badge">${esc(v.vuln_id)}</span>
                        </div>
                    </div>
                    <h3 class="detail-title">${esc(v.vuln_type)}</h3>
                    <div class="detail-meta">
                        <span>Line ${v.line}</span><span>${esc(v.cwe)}</span><span>OWASP ${esc(v.owasp)}</span>
                    </div>
                    <p class="section-title">ANALYSIS</p>
                    <p class="detail-text">${esc(v.description)}</p>
                    ${simMeta}
                    ${payloadHtml}
                    ${taintHtml}
                    ${chainHtml}
                    <div class="ai-action-row">
                        <button class="ai-btn" data-action="explain" data-vuln='${JSON.stringify(v).replace(/'/g,"&#39;")}'>💡 Explain</button>
                        <button class="ai-btn" data-action="fix" data-vuln='${JSON.stringify(v).replace(/'/g,"&#39;")}'>🔧 Fix</button>
                    </div>
                    <div class="ai-result" id="ai-result-${v.vuln_id}"></div>
                    ${finding.exploitable ? '<div class="exploit-confirmed">⚠ EXPLOITATION PATH CONFIRMED</div>' : ''}
                    ${finding.simulation?.exploit_confirmed ? `
                        <div class="exploit-confirmed live">
                            <span class="exploit-pulse"></span> LIVE EXPLOIT CONFIRMED
                        </div>
                        <div class="code-snippet exploit-output" title="Exploit Output">
                            <span style="color:var(--text-muted);font-size:9px;display:block;margin-bottom:4px">// SANDBOX OUTPUT</span>
                            ${esc(finding.simulation.exploit_output)}
                        </div>
                    ` : ''}
                </div>
            `);

            // Render Vis.js network if a chain exists
            if (chainToRender && typeof vis !== 'undefined') {
                setTimeout(() => {
                    const container = document.getElementById(`vis-network-${finding.vulnerability.vuln_id}`);
                    if (!container) return;
                    const nodes = new vis.DataSet();
                    const edges = new vis.DataSet();
                    
                    // Split long text with basic manual wrapping (every ~35 chars) for better nodes
                    const wrapText = (t) => t.replace(/(?![^\n]{1,35}$)([^\n]{1,35})\s/g, '$1\n');
                    
                    chainToRender.steps.forEach((s, i) => {
                        nodes.add({
                            id: i,
                            label: esc(wrapText(s)),
                            shape: 'box',
                            color: {
                                background: i === chainToRender.steps.length - 1 ? 'rgba(255,45,85,0.1)' : 'rgba(0,255,136,0.05)',
                                border: i === chainToRender.steps.length - 1 ? '#ff2d55' : 'rgba(0,255,136,0.3)'
                            },
                            font: { color: i === chainToRender.steps.length - 1 ? '#ff2d55' : '#00ff88', face: 'var(--font-mono)', size: 10 },
                            margin: 8,
                            borderWidth: 1,
                        });
                        if (i > 0) {
                            edges.add({ from: i - 1, to: i, arrows: 'to', color: { color: 'rgba(0,255,136,0.2)' } });
                        }
                    });

                    const network = new vis.Network(container, { nodes, edges }, {
                        layout: { hierarchical: { direction: 'UD', sortMethod: 'directed', nodeSpacing: 100, levelSeparation: 60 } },
                        physics: false,
                        interaction: { dragNodes: false, dragView: true, zoomView: true, selectConnectedEdges: false, hover: true }
                    });

                    // Change cursor on hover to indicate clickability
                    network.on("hoverNode", function () {
                        network.canvas.body.container.style.cursor = 'pointer';
                    });
                    network.on("blurNode", function () {
                        network.canvas.body.container.style.cursor = 'default';
                    });

                    // Handle node click
                    network.on("selectNode", async function (params) {
                        if (params.nodes.length > 0) {
                            const nodeId = params.nodes[0];
                            const stepText = chainToRender.steps[nodeId];
                            
                            // 1. Trigger Sandbox Simulation for this step
                            if (typeof runSimulation === 'function') {
                                runSimulation(`[STEP: ${stepText}]`);
                            }

                            // 2. Trigger AI Explanation for this specific step
                            const resultEl = document.getElementById(`ai-result-${finding.vulnerability.vuln_id}`);
                            if (resultEl) {
                                resultEl.innerHTML = `<div class="ai-loading"><span class="ai-pulse"></span> Analyzing step with AI...</div>`;
                                try {
                                    const mockVuln = {
                                        vuln_type: `Attack Step: ${chainToRender.name}`,
                                        description: `Explain the mechanics and impact of this specific attack step: "${stepText}"`,
                                        line: finding.vulnerability.line,
                                        cwe: finding.vulnerability.cwe,
                                        owasp: finding.vulnerability.owasp
                                    };
                                    
                                    // Extract context
                                    const contextLines = codeInput.value.split('\n');
                                    const context = contextLines.slice(Math.max(0, finding.vulnerability.line - 5), finding.vulnerability.line + 5).join('\n');

                                    const resp = await fetch('/api/ai/explain', {
                                        method: 'POST', headers: {'Content-Type': 'application/json'},
                                        body: JSON.stringify({ vulnerability: mockVuln, code_context: context })
                                    });
                                    const data = await resp.json();
                                    const text = data.explanation || '';
                                    
                                    resultEl.innerHTML = `
                                        <div class="ai-result-box ${data.ai_powered ? 'ai-powered' : 'ai-fallback'}">
                                            <div class="ai-result-header">
                                                <span>${data.ai_powered ? '🦙 Llama 3' : '📚 Static'}</span>
                                                <span class="ai-action-label">STEP ANALYSIS</span>
                                            </div>
                                            <div class="ai-result-text">${formatAiText(text)}</div>
                                        </div>
                                    `;
                                } catch (e) {
                                    resultEl.innerHTML = `<div class="ai-result-box ai-fallback"><div class="ai-result-text">Error: ${e.message}</div></div>`;
                                }
                            }
                        }
                    });
                }, 50);
            }
        });

        // Bind simulate buttons
        document.querySelectorAll('.simulate-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const payload = decodeURIComponent(escape(atob(btn.getAttribute('data-payload'))));
                runSimulation(payload);
            });
        });

        // Bind AI buttons
        document.querySelectorAll('.ai-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const action = btn.getAttribute('data-action');
                const vuln = JSON.parse(btn.getAttribute('data-vuln'));
                await loadAiDetail(action, vuln, btn);
            });
        });
    }

    // ── AI detail panel ───────────────────────────────────────────────────────
    async function loadAiDetail(action, vuln, btn) {
        const resultEl = document.getElementById(`ai-result-${vuln.vuln_id}`);
        if (!resultEl) return;
        btn.disabled = true;
        btn.textContent = action === 'explain' ? '💡 Thinking...' : '🔧 Generating...';
        resultEl.innerHTML = `<div class="ai-loading"><span class="ai-pulse"></span> Querying AI...</div>`;

        try {
            const endpoint = action === 'explain' ? '/api/ai/explain' : '/api/ai/fix';
            const body = action === 'explain'
                ? { vulnerability: vuln, code_context: codeInput.value.split('\n').slice(Math.max(0, vuln.line - 5), vuln.line + 5).join('\n') }
                : { vulnerability: vuln, source_code: codeInput.value };

            const resp = await fetch(endpoint, {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(body)
            });
            const data = await resp.json();
            const text = data.explanation || data.fix || '';
            const aiPowered = data.ai_powered;

            resultEl.innerHTML = `
                <div class="ai-result-box ${aiPowered ? 'ai-powered' : 'ai-fallback'}">
                    <div class="ai-result-header">
                        <span>${aiPowered ? '🦙 Llama 3' : '📚 Static'}</span>
                        <span class="ai-action-label">${action.toUpperCase()}</span>
                    </div>
                    <div class="ai-result-text">${formatAiText(text)}</div>
                </div>
            `;
        } catch (e) {
            resultEl.innerHTML = `<div class="ai-result-box ai-fallback"><div class="ai-result-text">AI unavailable: ${e.message}</div></div>`;
        }
        btn.disabled = false;
        btn.textContent = action === 'explain' ? '💡 Explain' : '🔧 Fix';
    }

    function formatAiText(text) {
        // Convert ```code``` blocks to styled spans
        return esc(text)
            .replace(/```python\n?([\s\S]*?)```/g, '<pre class="ai-code-block">$1</pre>')
            .replace(/```\n?([\s\S]*?)```/g, '<pre class="ai-code-block">$1</pre>')
            .replace(/\n/g, '<br>');
    }

    async function loadAiTriage(findings) {
        try {
            const resp = await fetch('/api/ai/triage', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ findings })
            });
            const data = await resp.json();
            if (!data.triage?.length) return;
            const triageHtml = `
                <div class="detail-card triage-card">
                    <div class="card-header"><span class="severity-badge CRITICAL">AI TRIAGE</span><span class="id-badge">${data.ai_powered ? 'CLAUDE' : 'STATIC'}</span></div>
                    <h3 class="detail-title">Priority Attack Surface</h3>
                    ${data.triage.map(t => `
                        <div class="triage-item">
                            <span class="triage-rank">#${t.rank}</span>
                            <div>
                                <div class="triage-type">${esc(t.vuln_type)}</div>
                                <div class="triage-reason">${esc(t.reason)}</div>
                            </div>
                            <span class="triage-priority ${t.priority}">${t.priority}</span>
                        </div>
                    `).join('')}
                </div>
            `;
            detailsBody.insertAdjacentHTML('afterbegin', triageHtml);
        } catch {}
    }

    // ── Simulation ────────────────────────────────────────────────────────────
    async function runSimulation(payload) {
        terminalPanel.classList.add('visible');
        terminalOutput.className = 'terminal-output';
        let out = `[${new Date().toISOString()}] SHADOWCODER SANDBOX v2.0\n[*] Injecting: ${payload}\n[*] Tracing execution...\n\n`;
        terminalOutput.textContent = out;

        try {
            const resp = await fetch('/api/simulate', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source_code: codeInput.value, payload })
            });
            const data = await resp.json();
            const lines = data.success
                ? [`[+] EXPLOIT TRIGGERED`, `[+] Output:`, '', ...data.output.split('\n'), '', '[!] Root/admin path confirmed']
                : [`[-] Exploit mitigated`, ...data.output.split('\n')];

            for (const line of lines) {
                out += line + '\n';
                terminalOutput.textContent = out;
                await sleep(40);
                terminalOutput.scrollTop = terminalOutput.scrollHeight;
            }
            terminalOutput.className = 'terminal-output ' + (data.success ? 'success' : 'failure');
        } catch (e) {
            terminalOutput.textContent += `\n[!] Sandbox error: ${e.message}`;
            terminalOutput.className = 'terminal-output failure';
        }
    }

    function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
});
