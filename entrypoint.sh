#!/bin/bash

# Ensure directories exist and have correct permissions
mkdir -p /Pentests/Todos_os_Resultados
mkdir -p /Pentests/Historico
mkdir -p /Pentests/Ataque_Bem-Sucedido

# IMPROVED: Ensure index.html exists with better structure
if [ ! -f "/Pentests/index.html" ]; then
    echo "🔧 Criando index.html otimizado..."
    cat > /Pentests/index.html << 'EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔰 Project Pandora - Black Box Results</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔰</text></svg>">
    <style>
        /* RESET & BASE */
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: "Courier New", monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a0a0a 100%);
            color: #00ff00;
            min-height: 100vh;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        /* HEADER */
        .header {
            background: linear-gradient(135deg, #800000 0%, #4a0000 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            margin-bottom: 30px;
            border: 2px solid #660000;
            box-shadow: 0 0 20px rgba(255,0,0,0.3);
        }

        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header h2 { font-size: 1.2em; opacity: 0.9; margin-bottom: 15px; }

        .blackbox-badge {
            background: #660000;
            color: white;
            padding: 8px 20px;
            border-radius: 25px;
            font-size: 12px;
            font-weight: bold;
            animation: pulse 2s infinite;
            display: inline-block;
            margin-top: 10px;
        }

        /* STATUS BANNER */
        .status-banner {
            background: #1a1a1a;
            border: 2px solid #333;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            text-align: center;
        }

        .status-content {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            font-size: 1.2em;
            font-weight: bold;
        }

        #status-icon { font-size: 1.5em; }

        /* CARDS */
        .card {
            background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
            border: 1px solid #333;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 0 15px rgba(0,255,0,0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 25px rgba(0,255,0,0.2);
        }

        .card h3 {
            margin-bottom: 20px;
            color: #00ffff;
            font-size: 1.3em;
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
        }

        /* CARD LINKS */
        .card-links {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        .card-link {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 15px;
            background: #2a2a2a;
            border: 1px solid #444;
            border-radius: 8px;
            color: #00ffff;
            text-decoration: none;
            transition: all 0.3s ease;
        }

        .card-link:hover {
            background: #3a3a3a;
            border-color: #00ffff;
            transform: translateX(5px);
        }

        .card-link.critical {
            border-color: #ff4444;
            background: #2d1a1a;
        }

        .card-link.critical:hover {
            border-color: #ff6666;
            background: #3d2a2a;
        }

        .link-icon { font-size: 1.2em; margin-right: 10px; }
        .link-text { flex: 1; font-weight: bold; }

        .link-badge {
            background: #00ffff;
            color: #000;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.9em;
            font-weight: bold;
        }

        .link-badge.critical {
            background: #ff4444;
            color: white;
            animation: pulse 1.5s infinite;
        }

        /* PROGRESS */
        .progress-info {
            margin-bottom: 20px;
        }

        .progress-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #333;
        }

        .progress-label {
            color: #00ffff;
            font-weight: bold;
        }

        .progress-value {
            color: #00ff00;
            font-family: monospace;
        }

        .progress-bar {
            width: 100%;
            height: 25px;
            background: #333;
            border-radius: 15px;
            overflow: hidden;
            border: 1px solid #555;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00ff00, #00ffff);
            width: 0%;
            transition: width 0.5s ease;
            border-radius: 15px;
        }

        /* GRID */
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }

        /* DETAILED SCOPE SECTION */
        .detailed-scope {
            background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
            border: 1px solid #333;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 30px;
        }

        .detailed-scope h3 {
            color: #00ffff;
            font-size: 1.3em;
            margin-bottom: 20px;
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
        }

        .scope-phase {
            background: #2a2a2a;
            border: 1px solid #444;
            border-radius: 8px;
            margin: 15px 0;
            overflow: hidden;
        }

        .scope-phase-header {
            background: #333;
            color: #ffff00;
            padding: 12px 15px;
            font-weight: bold;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.3s ease;
        }

        .scope-phase-header:hover {
            background: #444;
        }

        .scope-phase-content {
            padding: 15px;
            display: none;
        }

        .scope-phase.active .scope-phase-content {
            display: block;
        }

        .test-item {
            display: flex;
            margin: 8px 0;
            padding: 8px;
            background: #1a1a1a;
            border-radius: 5px;
            border-left: 3px solid #00ffff;
        }

        .test-code {
            font-family: "Courier New", monospace;
            color: #00ffff;
            font-weight: bold;
            min-width: 150px;
            font-size: 0.9em;
        }

        .test-desc {
            color: #cccccc;
            margin-left: 10px;
            font-size: 0.9em;
        }

        .vulnerable {
            border-left-color: #ff4444;
        }

        .vulnerable .test-code {
            color: #ff6666;
        }

        .toggle-arrow {
            font-size: 1.2em;
            transition: transform 0.3s ease;
        }

        .scope-phase.active .toggle-arrow {
            transform: rotate(90deg);
        }

        /* TERMINAL */
        .terminal {
            background: #000;
            color: #00ff00;
            padding: 20px;
            border-radius: 8px;
            font-family: "Courier New", monospace;
            border: 1px solid #00ff00;
            box-shadow: inset 0 0 10px rgba(0,255,0,0.2);
        }

        .terminal-line {
            margin: 8px 0;
            display: flex;
            align-items: center;
        }

        .terminal-label {
            color: #ffff00;
            font-weight: bold;
            min-width: 80px;
        }

        /* STATES */
        .safe {
            background-color: #002d00;
            border-left: 5px solid #44ff44;
            color: #66ff66;
        }

        .warning {
            background-color: #2d2d00;
            border-left: 5px solid #ffff44;
            color: #ffff66;
        }

        .vulnerable {
            background-color: #2d0000;
            border-left: 5px solid #ff4444;
            color: #ff6666;
        }

        .info {
            background-color: #001a2d;
            border-left: 5px solid #4488ff;
            color: #66aaff;
        }

        /* LINKS */
        a {
            color: #00ffff;
            text-decoration: none;
            font-weight: bold;
            transition: color 0.3s ease;
        }

        a:hover {
            color: #ff00ff;
            text-decoration: underline;
        }

        /* ANIMATIONS */
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.6; }
            100% { opacity: 1; }
        }

        /* FOOTER */
        .footer {
            text-align: center;
            padding: 20px;
            margin-top: 40px;
            border-top: 1px solid #333;
            color: #666;
            font-size: 0.9em;
        }

        /* RESPONSIVE */
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .header { padding: 20px; }
            .header h1 { font-size: 2em; }
            .grid { grid-template-columns: 1fr; gap: 15px; }
            .card { padding: 15px; }
            .card-link { padding: 12px; }
            .test-item { flex-direction: column; }
            .test-code { min-width: auto; margin-bottom: 5px; }
            .test-desc { margin-left: 0; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔰 Project Pandora</h1>
            <h2>Black Box Penetration Testing Results</h2>
            <span class="blackbox-badge">DOUBLE BLIND BLACK BOX</span>
        </div>

        <div class="status-banner" id="main-status">
            <div class="status-content">
                <span id="status-icon">🔍</span>
                <span id="status-text">Carregando status...</span>
            </div>
        </div>

        <div class="grid">
            <div class="card results-card">
                <h3>🎯 Resultados Black Box</h3>
                <div class="card-links">
                    <a href="/Todos_os_Resultados/" class="card-link">
                        <span class="link-icon">📁</span>
                        <span class="link-text">Todos os Resultados</span>
                        <span class="link-badge" id="total-tests">0</span>
                    </a>
                    <a href="/Historico/" class="card-link">
                        <span class="link-icon">📦</span>
                        <span class="link-text">Arquivos Compactados</span>
                    </a>
                    <a href="/Ataque_Bem-Sucedido/" class="card-link critical">
                        <span class="link-icon">⚠️</span>
                        <span class="link-text">Possiveis Vulnerabilidades</span>
                        <span class="link-badge critical" id="vuln-count">0</span>
                    </a>
                </div>
            </div>

            <div class="card progress-card">
                <h3>🔄 Progresso em Tempo Real</h3>
                <div class="progress-info">
                    <div class="progress-item">
                        <span class="progress-label">Status:</span>
                        <span id="scan-status" class="progress-value">Verificando...</span>
                    </div>
                    <div class="progress-item">
                        <span class="progress-label">Alvo Atual:</span>
                        <span id="current-target" class="progress-value">N/A</span>
                    </div>
                    <div class="progress-item">
                        <span class="progress-label">Progresso:</span>
                        <span id="scan-progress" class="progress-value">0/0</span>
                    </div>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="progress-fill"></div>
                </div>
            </div>
        </div>

        <div class="detailed-scope">
            <h3>🔬 Escopo Detalhado de Testes</h3>

            <div class="scope-phase active">
                <div class="scope-phase-header" onclick="togglePhase(this)">
                    <span>🌐 FASE 1: Descoberta de Hosts</span>
                    <span class="toggle-arrow">▶</span>
                </div>
                <div class="scope-phase-content">
                    <div class="test-item">
                        <div class="test-code">PING + ARP</div>
                        <div class="test-desc">Descoberta tradicional ICMP + ARP para rede local</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">TCP SYN Discovery</div>
                        <div class="test-desc">Detecta hosts stealth via portas: 22,23,25,53,80,135,139,443,445,993,995,3389,5985,8080</div>
                    </div>
                </div>
            </div>

            <div class="scope-phase">
                <div class="scope-phase-header" onclick="togglePhase(this)">
                    <span>🚪 FASE 2: Mapeamento de Portas</span>
                    <span class="toggle-arrow">▶</span>
                </div>
                <div class="scope-phase-content">
                    <div class="test-item">
                        <div class="test-code">TCP: 1-65535</div>
                        <div class="test-desc">SYN Stealth Scan completo em todas as portas TCP</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">UDP: 19 portas</div>
                        <div class="test-desc">DNS(53), DHCP(67,68), TFTP(69), NTP(123), NetBIOS(135,137,138,139), SNMP(161,162), SMB(445), IKE(500), Syslog(514), RIP(520), IPMI(623), SQL(1434), UPnP(1900), mDNS(5353)</div>
                    </div>
                </div>
            </div>

            <div class="scope-phase">
                <div class="scope-phase-header" onclick="togglePhase(this)">
                    <span>🔓 FASE 3: Testes de Autenticação</span>
                    <span class="toggle-arrow">▶</span>
                </div>
                <div class="scope-phase-content">
                    <div class="test-item vulnerable">
                        <div class="test-code">ftp-anon</div>
                        <div class="test-desc">Login FTP anônimo (anonymous/anonymous)</div>
                    </div>
                    <div class="test-item vulnerable">
                        <div class="test-code">mysql-empty-password</div>
                        <div class="test-desc">MySQL com senha vazia para root</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">ssh-auth-methods</div>
                        <div class="test-desc">Métodos de autenticação SSH</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">telnet-ntlm-info</div>
                        <div class="test-desc">Informações NTLM via Telnet</div>
                    </div>
                </div>
            </div>

            <div class="scope-phase">
                <div class="scope-phase-header" onclick="togglePhase(this)">
                    <span>🛡️ FASE 4: Vulnerabilidades SMB Críticas</span>
                    <span class="toggle-arrow">▶</span>
                </div>
                <div class="scope-phase-content">
                    <div class="test-item vulnerable">
                        <div class="test-code">smb-vuln-ms17-010</div>
                        <div class="test-desc">EternalBlue - Exploit usado pelo WannaCry</div>
                    </div>
                    <div class="test-item vulnerable">
                        <div class="test-code">smb-vuln-ms08-067</div>
                        <div class="test-desc">Conficker - Buffer overflow crítico</div>
                    </div>
                    <div class="test-item vulnerable">
                        <div class="test-code">smb-vuln-ms10-054</div>
                        <div class="test-desc">SMB Pool Overflow</div>
                    </div>
                    <div class="test-item vulnerable">
                        <div class="test-code">smb-vuln-ms10-061</div>
                        <div class="test-desc">Print Spooler - Escalação para SYSTEM</div>
                    </div>
                </div>
            </div>

            <div class="scope-phase">
                <div class="scope-phase-header" onclick="togglePhase(this)">
                    <span>🌐 FASE 5: Testes HTTP/Web</span>
                    <span class="toggle-arrow">▶</span>
                </div>
                <div class="scope-phase-content">
                    <div class="test-item vulnerable">
                        <div class="test-code">http-default-accounts</div>
                        <div class="test-desc">Credenciais padrão (admin/admin, root/root)</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">http-methods</div>
                        <div class="test-desc">Métodos HTTP perigosos (PUT, DELETE)</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">http-enum</div>
                        <div class="test-desc">Brute force de diretórios (/admin, /config)</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">http-robots.txt</div>
                        <div class="test-desc">Diretórios ocultos via robots.txt</div>
                    </div>
                </div>
            </div>

            <div class="scope-phase">
                <div class="scope-phase-header" onclick="togglePhase(this)">
                    <span>🗄️ FASE 6: Testes de Banco de Dados</span>
                    <span class="toggle-arrow">▶</span>
                </div>
                <div class="scope-phase-content">
                    <div class="test-item vulnerable">
                        <div class="test-code">mysql-vuln-cve2012-2122</div>
                        <div class="test-desc">Authentication Bypass MySQL</div>
                    </div>
                    <div class="test-item vulnerable">
                        <div class="test-code">ms-sql-empty-password</div>
                        <div class="test-desc">SQL Server senha vazia para 'sa'</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">oracle-sid-brute</div>
                        <div class="test-desc">Brute force Oracle SID</div>
                    </div>
                </div>
            </div>

            <div class="scope-phase">
                <div class="scope-phase-header" onclick="togglePhase(this)">
                    <span>🖥️ FASE 7: Acesso Remoto + UDP</span>
                    <span class="toggle-arrow">▶</span>
                </div>
                <div class="scope-phase-content">
                    <div class="test-item vulnerable">
                        <div class="test-code">rdp-vuln-ms12-020</div>
                        <div class="test-desc">RDP Denial of Service</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">vnc-info</div>
                        <div class="test-desc">Informações VNC e senhas fracas</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">snmp-info</div>
                        <div class="test-desc">Community strings SNMP (public/private)</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">dns-zone-transfer</div>
                        <div class="test-desc">Transferência de zona DNS</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">dhcp-discover</div>
                        <div class="test-desc">Servidores DHCP</div>
                    </div>
                    <div class="test-item">
                        <div class="test-code">ntp-info</div>
                        <div class="test-desc">Informações NTP</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid">
            <div class="card warning">
                <h3>⚠️ Aviso Legal</h3>
                <p><strong>Este e um teste de penetracao automatizado.</strong></p>
                <p>Resultados sao baseados em scanning automatico e podem nao refletir todos os vetores de ataque possiveis.</p>
                <p><em>Testes manuais adicionais sao recomendados para validacao completa.</em></p>
            </div>

            <div class="card info">
                <h3>🎯 Critérios de Vulnerabilidade</h3>
                <p><strong>Apenas ameaças REAIS aparecem em "Possíveis Vulnerabilidades":</strong></p>
                <div class="terminal">
                    <div class="terminal-line">✅ Exploit confirmado ("VULNERABLE")</div>
                    <div class="terminal-line">✅ Login anônimo funcionando</div>
                    <div class="terminal-line">✅ Senhas padrão/vazias funcionais</div>
                    <div class="terminal-line">✅ Bypass de autenticação</div>
                    <div class="terminal-line">✅ CVEs específicos confirmados</div>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>Project Pandora - Black Box Edition | 25+ Scripts NSE | 65535+19 Portas | Powered by Nmap</p>
        </div>
    </div>

    <script>
        // GLOBAL VARS
        let updateInterval;

        // UTILITY FUNCTIONS
        function getTodayPattern() {
            const today = new Date();
            const day = String(today.getDate()).padStart(2, '0');
            const month = String(today.getMonth() + 1).padStart(2, '0');
            const year = String(today.getFullYear()).slice(-2);
            return `${day}_${month}_${year}`;
        }

        function setMainStatus(icon, text, className = '') {
            const statusBanner = document.getElementById('main-status');
            const statusIcon = document.getElementById('status-icon');
            const statusText = document.getElementById('status-text');

            statusIcon.textContent = icon;
            statusText.textContent = text;

            // Remove existing status classes
            statusBanner.className = 'status-banner';
            if (className) {
                statusBanner.classList.add(className);
            }
        }

        function updateProgressBar(current, total) {
            const progressFill = document.getElementById('progress-fill');
            const percentage = total > 0 ? (current / total) * 100 : 0;
            progressFill.style.width = `${percentage}%`;
        }

        function updateCounters(testCount, vulnCount) {
            // Update total tests
            const totalTestsElement = document.getElementById('total-tests');
            if (totalTestsElement) {
                if (testCount > 0) {
                    totalTestsElement.textContent = testCount;
                } else {
                    fetch("/Todos_os_Resultados/")
                        .then(r => r.text())
                        .then(html => {
                            const completedTests = countIPFiles(html);
                            totalTestsElement.textContent = completedTests;
                        })
                        .catch(() => {
                            totalTestsElement.textContent = 0;
                        });
                }
            }

            // Update vulnerability badge
            const vulnBadge = document.getElementById('vuln-count');
            if (vulnBadge) {
                if (vulnCount === 0 || vulnCount === undefined) {
                    fetch("/Ataque_Bem-Sucedido/")
                        .then(r => r.text())
                        .then(html => {
                            const realVulnCount = countResumoFiles(html);
                            vulnBadge.textContent = realVulnCount;

                            if (realVulnCount > 0) {
                                vulnBadge.style.display = 'inline-block';
                            } else {
                                vulnBadge.style.display = 'none';
                            }
                        })
                        .catch(() => {
                            vulnBadge.textContent = 0;
                            vulnBadge.style.display = 'none';
                        });
                } else {
                    vulnBadge.textContent = vulnCount;
                    if (vulnCount > 0) {
                        vulnBadge.style.display = 'inline-block';
                    } else {
                        vulnBadge.style.display = 'none';
                    }
                }
            }

            console.log(`📊 Stats atualizados: ${testCount} testes, ${vulnCount} vulnerabilidades`);
        }

        // Count RESUMO files specifically
        function countResumoFiles(directoryHTML) {
            if (!directoryHTML) return 0;

            console.log('🔍 Contando arquivos RESUMO_*.txt...');

            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = directoryHTML;
            const links = tempDiv.querySelectorAll('a');
            const resumoFiles = [];

            links.forEach((link) => {
                const fileName = link.textContent.trim();

                if (fileName.match(/^RESUMO_.*\.txt$/)) {
                    resumoFiles.push(fileName);
                    console.log(`✅ Arquivo RESUMO encontrado: "${fileName}"`);
                }
            });

            const count = resumoFiles.length;
            console.log(`📊 Total de arquivos RESUMO encontrados: ${count}`);

            return count;
        }

        // Count test directories
        function countIPFiles(directoryHTML) {
            if (!directoryHTML) return 0;

            console.log('🔍 Analisando conteudo do diretorio para contar diretorios de teste...');

            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = directoryHTML;
            const links = tempDiv.querySelectorAll('a');
            const testDirectories = [];

            console.log(`🔗 Total de links encontrados: ${links.length}`);

            links.forEach((link, index) => {
                const fileName = link.textContent.trim();
                const href = link.getAttribute('href') || '';

                console.log(`📁 [${index}] Verificando: "${fileName}" (href: "${href}")`);

                if (fileName === '../' || fileName === '' || href === '../') {
                    console.log(`⬆️ Ignorado: link para diretorio pai`);
                    return;
                }

                if (fileName.match(/^\d{2}_\d{2}_\d{2}-\d{2}:\d{2}\/$/)) {
                    testDirectories.push(fileName);
                    console.log(`✅ Diretorio de teste valido encontrado: "${fileName}"`);
                } else {
                    console.log(`❌ Ignorado (nao e diretorio de teste): "${fileName}"`);
                }
            });

            const count = testDirectories.length;
            console.log(`📊 Total de diretorios de teste encontrados: ${count}`);

            return count;
        }

        // MAIN STATUS UPDATE FUNCTION
        function updateStatus() {
            console.log('🔄 Atualizando status...');

            // Try to get real-time status first
            fetch("/status.json")
                .then(response => {
                    if (!response.ok) throw new Error('Status file not found');
                    return response.json();
                })
                .then(status => {
                    console.log('📊 Status real-time:', status);
                    updateRealTimeStatus(status);
                })
                .catch(err => {
                    console.log('⚠️ Status real-time indisponivel, usando fallback...');
                    updateFallbackStatus();
                });
        }

        function updateRealTimeStatus(status) {
            document.getElementById('total-tests').textContent = status.progress.current;

            // Update main status banner
            let statusClass = "info";
            let statusIcon = "🔍";
            let statusText = "";

            if (status.vulnerabilities > 0) {
                statusClass = "vulnerable";
                statusIcon = "🚨";
                statusText = `POSSÍVEIS VULNERABILIDADES CRÍTICAS: ${status.vulnerabilities}`;
            } else if (status.status === "running") {
                statusClass = "warning";
                statusIcon = "⚙️";
                statusText = "SCANNING EM ANDAMENTO...";
            } else if (status.status === "completed") {
                statusClass = "safe";
                statusIcon = "✅";
                statusText = "SCAN COMPLETO - NENHUMA VULNERABILIDADE CRÍTICA";
            } else {
                statusIcon = "🔍";
                statusText = "SISTEMA ATIVO - AGUARDANDO INICIO";
            }

            setMainStatus(statusIcon, statusText, statusClass);

            // Update progress information
            document.getElementById('scan-status').textContent =
                status.status === "running" ? "Em Execucao" :
                status.status === "completed" ? "Concluido" : "Standby";

            document.getElementById('current-target').textContent =
                status.current_target || "N/A";

            document.getElementById('scan-progress').textContent =
                `${status.progress?.current || 0}/${status.progress?.total || 0}`;

            // Update progress bar
            updateProgressBar(
                status.progress?.current || 0,
                status.progress?.total || 0
            );

            // Update counters
            updateCounters(
                status.progress?.current || 0,
                status.vulnerabilities || 0
            );
        }

        function updateFallbackStatus() {
            console.log('🔄 Executando fallback status...');

            // Fallback: Get info from directory listings
            Promise.all([
                fetch("/Todos_os_Resultados/").then(r => r.text()).catch(() => ""),
                fetch("/Ataque_Bem-Sucedido/").then(r => r.text()).catch(() => "")
            ]).then(([resultsData, vulnData]) => {

                console.log('📂 Dados do diretorio de resultados recebidos');

                // Count test directories
                const testDirectoriesCount = countIPFiles(resultsData);

                // Count RESUMO files specifically
                const vulnCount = countResumoFiles(vulnData);

                console.log(`📊 Fallback stats: ${testDirectoriesCount} diretorios de teste, ${vulnCount} vulnerabilidades`);

                let statusClass = "info";
                let statusIcon = "🔍";
                let statusText = "";

                if (vulnCount > 0) {
                    statusClass = "vulnerable";
                    statusIcon = "🚨";
                    statusText = `POSSÍVEIS VULNERABILIDADES CRÍTICAS: ${vulnCount}`;
                } else {
                    statusIcon = "🔍";
                    statusText = "SISTEMA ATIVO - AGUARDANDO INICIO";
                }

                setMainStatus(statusIcon, statusText, statusClass);

                // Update progress info (fallback mode)
                document.getElementById('scan-status').textContent = "Standby";
                document.getElementById('current-target').textContent = "N/A";
                document.getElementById('scan-progress').textContent = `${testDirectoriesCount}/∞`;

                // Update counters with correct values
                updateCounters(testDirectoriesCount, vulnCount);
                updateProgressBar(0, 1); // Unknown progress in fallback
            });
        }

        // TOGGLE FUNCTION FOR SCOPE PHASES
        function togglePhase(header) {
            const phase = header.parentElement;
            const isActive = phase.classList.contains('active');

            // Toggle clicked phase
            if (isActive) {
                phase.classList.remove('active');
            } else {
                phase.classList.add('active');
            }
        }

        // INITIALIZATION
        function init() {
            console.log('🚀 Inicializando Project Pandora Interface...');

            // Initial status update
            updateStatus();

            // Set up auto-refresh (every 10 seconds)
            updateInterval = setInterval(updateStatus, 10000);

            console.log('✅ Interface inicializada com sucesso!');
        }

        // ERROR HANDLING
        window.addEventListener('error', function(e) {
            console.error('🚨 JavaScript Error:', e.error);
        });

        // START WHEN DOM IS READY
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', init);
        } else {
            init();
        }

        // CLEANUP ON PAGE UNLOAD
        window.addEventListener('beforeunload', function() {
            if (updateInterval) {
                clearInterval(updateInterval);
            }
        });
    </script>
</body>
</html>
EOF
fi

# Enhanced function to update web stats with IP counting - COUNT ALL IP FILES
update_web_stats() {
    if [ -d "/Pentests/Todos_os_Resultados" ]; then
        echo "📊 Atualizando estatisticas web..."

        # Count ALL IP files (including tcp/udp variants, ignoring control files)
        local ip_count=0
        if [ -d "/Pentests/Todos_os_Resultados" ]; then
            # Find all files that start with IP pattern (including duplicates)
            ip_count=$(find /Pentests/Todos_os_Resultados -type f -name "[0-9]*.[0-9]*.[0-9]*.[0-9]*" 2>/dev/null | wc -l)
        fi

        # Count vulnerabilities
        local vuln_count=0
        if [ -d "/Pentests/Ataque_Bem-Sucedido" ]; then
            vuln_count=$(find /Pentests/Ataque_Bem-Sucedido -type f -name "RESUMO_*" 2>/dev/null | wc -l)
        fi

        # Create enhanced stats file
        cat > /Pentests/stats.json << EOF
{
    "ip_tests_executed": $ip_count,
    "vulnerabilities_found": $vuln_count,
    "last_update": "$(date '+%Y-%m-%d %H:%M:%S')",
    "status": "active",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
}
EOF

        echo "📊 Stats atualizados: $ip_count arquivos IP testados, $vuln_count vulnerabilidades"
    fi
}

# Rest of the original script remains the same...
# Set proper permissions for Apache
chown -R www-data:www-data /Pentests
chmod -R 755 /Pentests

# Enhanced function to check Apache2 status
check_apache() {
    if ! pgrep apache2 > /dev/null; then
        echo "⚠️ Apache2 nao encontrado. Iniciando..."

        # Clean orphaned sockets
        find /var/run/apache2/ -name "cgisock*" -exec unlink {} \; 2>/dev/null || true

        # Start Apache2
        service apache2 start
        sleep 2

        if ! pgrep apache2 > /dev/null; then
            echo "❌ Falha ao iniciar. Tentando restart..."
            service apache2 restart
            sleep 2
        else
            echo "✅ Apache2 iniciado com sucesso!"
        fi
    fi
}

# Start Apache2 and monitoring
echo "🌐 Iniciando servicos web..."
check_apache

# Background monitoring process
(
    while true; do
        check_apache
        update_web_stats
        sleep 300  # Check every 5 minutes
    done
) &

# Start Apache in foreground
/usr/sbin/apache2ctl -D FOREGROUND &

# Keep container alive
exec tail -f /dev/null
