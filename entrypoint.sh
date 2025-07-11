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
    <link rel="stylesheet" href="style.css">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔰</text></svg>">
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
                        <span class="link-text">Vulnerabilidades Detectadas</span>
                        <span class="link-badge critical" id="vuln-count">0</span>
                    </a>
                </div>
            </div>

            <div class="card scope-info">
                <h3>🔬 Escopo de Scanning</h3>
                <div class="terminal">
                    <div class="terminal-line"><span class="terminal-label">TCP:</span> 1-65535 (Full Range)</div>
                    <div class="terminal-line"><span class="terminal-label">UDP:</span> Top 30 Critical Corporate</div>
                    <div class="terminal-line"><span class="terminal-label">Scripts:</span> vuln,safe,discovery,auth,brute</div>
                    <div class="terminal-line"><span class="terminal-label">Method:</span> Double Blind Assessment</div>
                </div>
            </div>
        </div>

        <div class="grid">
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

            <div class="card warning">
                <h3>⚠️ Aviso Legal</h3>
                <p><strong>Este é um teste de penetração automatizado.</strong></p>
                <p>Resultados são baseados em scanning automático e podem não refletir todos os vetores de ataque possíveis.</p>
                <p><em>Testes manuais adicionais são recomendados para validação completa.</em></p>
            </div>
        </div>

        <div class="footer">
            <p>Project Pandora - Black Box Edition | Powered by Nmap & Custom Scripts</p>
        </div>
    </div>

    <script src="script.js"></script>
</body>
</html>
EOF

    echo "🔧 Criando style.css melhorado..."
    cat > /Pentests/style.css << 'EOF'
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

.suspicious {
    background-color: #2d2d00;
    border-left: 5px solid #ffaa00;
    color: #ffcc66;
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
}
EOF

    echo "🔧 Criando script.js aprimorado..."
    cat > /Pentests/script.js << 'EOF'
// GLOBAL VARS
let updateInterval;
let isUpdateRunning = false;

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
    let completedTests = 0; // Declarar fora do if

    const totalTestsElement = document.getElementById('total-tests');
    if (totalTestsElement) {
        if (testCount > 0) {
            completedTests = Math.max(0, testCount - 1);
            totalTestsElement.textContent = completedTests;
        } else {
            fetch("/Todos_os_Resultados/")
                .then(r => r.text())
                .then(html => {
                    completedTests = countIPFiles(html);
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
        vulnBadge.textContent = vulnCount;

        if (vulnCount > 0) {
            vulnBadge.style.display = 'inline-block';
        } else {
            vulnBadge.style.display = 'none';
        }
    }

    console.log(`📊 Stats: ${completedTests} files completed, ${vulnCount} vulnerabilities`);
}

// IMPROVED IP FILE COUNTING FUNCTION - COUNT ALL IP FILES INCLUDING DUPLICATES
function countIPFiles(directoryHTML) {
    if (!directoryHTML) return 0;

    console.log('🔍 Analisando conteúdo do diretório para contar arquivos IP...');
    console.log('📄 HTML recebido:', directoryHTML.substring(0, 500) + '...');

    // Create a temporary div to parse HTML
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = directoryHTML;

    // Get all links in the directory listing
    const links = tempDiv.querySelectorAll('a');
    const ipFiles = []; // Use array to count all files including duplicates

    console.log(`🔗 Total de links encontrados: ${links.length}`);

    links.forEach((link, index) => {
        const fileName = link.textContent.trim();
        const href = link.getAttribute('href') || '';

        console.log(`📄 [${index}] Verificando: "${fileName}" (href: "${href}")`);

        // Skip parent directory links and empty entries
        if (fileName === '../' || fileName === '' || href === '../') {
            console.log(`⬆️ Ignorado: link para diretório pai`);
            return;
        }

        // Check if file/folder name starts with IP pattern (IP followed by numbers and dots)
        // Match patterns like: 172.20.0.102, 172.20.0.102_tcp_full, 172.20.0.102_udp_critical
        if (fileName.match(/^(\d{1,3}\.){3}\d{1,3}/)) {
            ipFiles.push(fileName);
            console.log(`✅ Arquivo IP válido encontrado: "${fileName}"`);
        } else if (fileName.match(/^(01_|02_|03_|04_)/)) {
            console.log(`🚫 Arquivo de controle ignorado: "${fileName}"`);
        } else {
            console.log(`❌ Arquivo ignorado (não é IP): "${fileName}"`);
        }
    });

    const count = ipFiles.length;
    console.log(`📊 Total de arquivos IP encontrados (incluindo duplicatas): ${count}`);
    console.log(`📋 Arquivos IP encontrados:`, ipFiles);

    return count;
}

// MAIN STATUS UPDATE FUNCTION
function updateStatus() {
    if (isUpdateRunning) {
        console.log('⏭️ Update já em execução, pulando...');
        return;
    }

    isUpdateRunning = true;
    console.log('🔄 Atualizando status...');

    // Try to get real-time status first
    fetch("/status.json?" + new Date().getTime()) // Add cache busting
        .then(response => {
            if (!response.ok) throw new Error('Status file not found');
            return response.json();
        })
        .then(status => {
            console.log('📊 Status real-time:', status);
            updateRealTimeStatus(status);
        })
        .catch(err => {
            console.log('⚠️ Status real-time indisponível, usando fallback...');
            updateFallbackStatus();
        })
        .finally(() => {
            isUpdateRunning = false;
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
        statusText = `VULNERABILIDADES CRÍTICAS DETECTADAS: ${status.vulnerabilities}`;
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
        statusText = "SISTEMA ATIVO - AGUARDANDO COMANDOS";
    }

    setMainStatus(statusIcon, statusText, statusClass);

    // Update progress information
    document.getElementById('scan-status').textContent =
        status.status === "running" ? "Em Execução" :
        status.status === "completed" ? "Concluído" : "Standby";

    document.getElementById('current-target').textContent =
        status.current_target || "N/A";

    document.getElementById('scan-progress').textContent =
        `${status.progress?.current || 0}/${status.progress?.total || 0}`;

    // Update progress bar
    updateProgressBar(
        status.progress?.current || 0,
        status.progress?.total || 0
    );

    document.getElementById('total-tests').textContent = status.progress?.current || 0;

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
        fetch("/Todos_os_Resultados/?" + new Date().getTime()).then(r => r.text()).catch(() => ""),
        fetch("/Ataque_Bem-Sucedido/?" + new Date().getTime()).then(r => r.text()).catch(() => "")
    ]).then(([resultsData, vulnData]) => {

        console.log('📂 Dados do diretório de resultados recebidos');

        // Count IP files using improved function
        const ipTestCount = countIPFiles(resultsData);

        // Count vulnerabilities
        const vulnMatches = vulnData.match(/RESUMO_/g) || [];
        const vulnCount = vulnMatches.length;

        console.log(`📊 Fallback stats: ${ipTestCount} arquivos IP testados, ${vulnCount} vulnerabilidades`);

        // Update main status
        let statusClass = "info";
        let statusIcon = "🔍";
        let statusText = "";

        if (vulnCount > 0) {
            statusClass = "vulnerable";
            statusIcon = "🚨";
            statusText = `${vulnCount} VULNERABILIDADES DETECTADAS`;
        } else if (ipTestCount > 0) {
            statusClass = "safe";
            statusIcon = "✅";
            statusText = `${ipTestCount} ARQUIVOS IP TESTADOS - SISTEMA SEGURO`;
        } else {
            statusIcon = "🔍";
            statusText = "SISTEMA ATIVO - NENHUM TESTE EXECUTADO";
        }

        setMainStatus(statusIcon, statusText, statusClass);

        // Update progress info (fallback mode)
        document.getElementById('scan-status').textContent = "Standby";
        document.getElementById('current-target').textContent = "N/A";
        document.getElementById('scan-progress').textContent = `${ipTestCount}/∞`;

        // Update counters
        updateCounters(ipTestCount, vulnCount);
        updateProgressBar(0, 1); // Unknown progress in fallback
            }).finally(() => {
        isUpdateRunning = false;
    });
    });
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
EOF
fi

# Rest of the original script remains the same...
# Set proper permissions for Apache
chown -R www-data:www-data /Pentests
chmod -R 755 /Pentests

# Enhanced function to check Apache2 status
check_apache() {
    if ! pgrep apache2 > /dev/null; then
        echo "⚠️ Apache2 não encontrado. Iniciando..."

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
echo "🌐 Iniciando serviços web..."
check_apache

# Background monitoring process
(
    while true; do
        check_apache
        sleep 150  # Check every 2m 30s
    done
) &

# Start Apache in foreground
/usr/sbin/apache2ctl -D FOREGROUND &

# Keep container alive
exec tail -f /dev/null
