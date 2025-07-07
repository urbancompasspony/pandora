#!/bin/bash

# Ensure directories exist and have correct permissions
mkdir -p /Pentests/Todos_os_Resultados
mkdir -p /Pentests/Historico
mkdir -p /Pentests/Ataque_Bem-Sucedido

# Ensure index.html exists (recreate if missing)
if [ ! -f "/Pentests/index.html" ]; then
    echo "🔧 Criando index.html..."
    cat > /Pentests/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>🔰 Project Pandora - Black Box Results</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: "Courier New", monospace; margin: 20px; background: #0a0a0a; color: #00ff00; }
        .header { background: linear-gradient(135deg, #800000 0%, #4a0000 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px; border: 2px solid #660000; }
        .card { background: #1a1a1a; border: 1px solid #333; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 0 10px rgba(255,0,0,0.3); }
        .status { padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 3px solid #00ff00; }
        .vulnerable { background-color: #2d0000; border-left: 5px solid #ff4444; color: #ff6666; }
        .safe { background-color: #002d00; border-left: 5px solid #44ff44; color: #66ff66; }
        .warning { background-color: #2d2d00; border-left: 5px solid #ffff44; color: #ffff66; }
        .info { background-color: #001a2d; border-left: 5px solid #4488ff; color: #66aaff; }
        a { color: #00ffff; text-decoration: none; font-weight: bold; }
        a:hover { color: #ff00ff; text-decoration: underline; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .blackbox-badge { background: #660000; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; animation: pulse 2s infinite; }
        .terminal { background: #000; color: #00ff00; padding: 15px; border-radius: 5px; font-family: "Courier New", monospace; border: 1px solid #00ff00; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .scope-info { background: #1a0a1a; border: 1px solid #ff00ff; padding: 10px; border-radius: 5px; color: #ff88ff; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔰 Project Pandora</h1>
        <h2>Black Box Penetration Testing Results</h2>
        <span class="blackbox-badge">DOUBLE BLIND BLACK BOX</span>
    </div>
    <div class="grid">
        <div class="card">
            <h3>🎯 Resultados Black Box</h3>
            <p><a href="/Todos_os_Resultados/">📁 Todos os Resultados</a></p>
            <p><a href="/Historico/">📦 Arquivos Compactados</a></p>
            <p><a href="/Ataque_Bem-Sucedido/">🚨 Vulnerabilidades Críticas</a></p>
        </div>
        <div class="card scope-info">
            <h3>🔬 Escopo de Scanning</h3>
            <div class="terminal">
                TCP: 1-65535 (Full Range)<br>
                UDP: Top 30 Critical Corporate<br>
                Scripts: vuln,safe,discovery,auth,brute<br>
                Methodology: Double Blind Assessment
            </div>
        </div>
    </div>
    <div class="grid">
        <div class="card">
            <h3>🔄 Status em Tempo Real</h3>
            <div id="status-info">Carregando status...</div>
        </div>
        <div class="card warning">
            <h3>⚠️ Aviso Legal</h3>
            <p><strong>Este é um teste de penetração automatizado.</strong></p>
            <p>Resultados são baseados em scanning automático e podem não refletir todos os vetores de ataque possíveis.</p>
            <p><em>Testes manuais adicionais são recomendados.</em></p>
        </div>
    </div>
    <script>
function updateStatus() {
    // Try to get stats from dedicated endpoint first
    fetch("/stats.json")
        .then(response => response.json())
        .then(stats => {
            const statusDiv = document.getElementById("status-info");
            
            let statusClass = "safe";
            let statusIcon = "✅";
            
            if (stats.vulnerabilities > 0) {
                statusClass = "vulnerable";
                statusIcon = "🚨";
            }
            
            statusDiv.innerHTML = `<div class="${statusClass}">${statusIcon} Testes: ${stats.tests_today} | IPs: ${stats.total_ips_scanned} | Vulnerabilidades: ${stats.vulnerabilities}</div>`;
        })
        .catch(err => {
            // Fallback to directory listing method
            fetch("/Todos_os_Resultados/")
                .then(response => response.text())
                .then(data => {
                    const statusDiv = document.getElementById("status-info");

                    const today = new Date();
                    const day = String(today.getDate()).padStart(2, '0');
                    const month = String(today.getMonth() + 1).padStart(2, '0');
                    const year = String(today.getFullYear()).slice(-2);
                    const todayPattern = `${day}_${month}_${year}`;

                    // Count directories with today's pattern
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(data, 'text/html');
                    const links = doc.querySelectorAll('a[href]');
                    
                    let testCount = 0;
                    links.forEach(link => {
                        const href = link.getAttribute('href');
                        if (href && href.includes(todayPattern) && href.endsWith('/')) {
                            testCount++;
                        }
                    });

                    fetch("/Ataque_Bem-Sucedido/")
                        .then(vulnResponse => vulnResponse.text())
                        .then(vulnData => {
                            const vulnCount = vulnData.trim().length > 100 ?
                                (vulnData.match(/RESUMO_/g) || []).length : 0;

                            let statusClass = "safe";
                            let statusIcon = "✅";

                            if (vulnCount > 0) {
                                statusClass = "vulnerable";
                                statusIcon = "🚨";
                            }

                            statusDiv.innerHTML = `<div class="${statusClass}">${statusIcon} Testes: ${testCount} | Vulnerabilidades: ${vulnCount}</div>`;
                        })
                        .catch(vulnErr => {
                            statusDiv.innerHTML = `<div class="info">🔍 Testes: ${testCount} | Verificando vulnerabilidades...</div>`;
                        });
                })
                .catch(err => {
                    document.getElementById("status-info").innerHTML = `<div class="warning">⚙️ Sistema executando scan...</div>`;
                });
        });
}

updateStatus();
setInterval(updateStatus, 30000);
    </script>
</body>
</html>
EOF
fi

# Set proper permissions for Apache
chown -R www-data:www-data /Pentests
chmod -R 755 /Pentests

# Function to check Apache2 status
check_apache() {
    # Verifica se Apache2 está rodando
    if ! pgrep apache2 > /dev/null; then
        echo "⚠️ Apache2 não encontrado. Iniciando..."

        # Limpa sockets órfãos
        find /var/run/apache2/ -name "cgisock*" -exec unlink {} \; 2>/dev/null || true

        # Inicia Apache2
        service apache2 start
        sleep 2

        # Verifica se iniciou corretamente
        if ! pgrep apache2 > /dev/null; then
            echo "❌ Falha ao iniciar. Tentando restart..."
            service apache2 restart
            sleep 2
        else
            echo "✅ Apache2 iniciado com sucesso!"
        fi
    fi
}

# Function to update web index with latest stats
update_web_stats() {
    if [ -d "/Pentests/Todos_os_Resultados" ]; then
        local test_count=$(find /Pentests/Todos_os_Resultados -type d -maxdepth 1 | wc -l)
        local vuln_count=0
        if [ -d "/Pentests/Ataque_Bem-Sucedido" ]; then
            vuln_count=$(find /Pentests/Ataque_Bem-Sucedido -type f -name "RESUMO_*" 2>/dev/null | wc -l)
        fi

        # Create a simple stats file for the web interface
        cat > /Pentests/stats.json << EOF
{
    "tests_executed": $test_count,
    "vulnerabilities_found": $vuln_count,
    "last_update": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
    fi
}

# Start Apache2 and ensure it stays running
echo "🌐 Iniciando Apache2..."
check_apache

# Background process to monitor Apache and update stats
(
    while true; do
        check_apache
        update_web_stats
        sleep 300  # Check every 5 minutes
    done
) &

# Try to start Apache in foreground, but keep container alive regardless
/usr/sbin/apache2ctl -D FOREGROUND &

# Keep container running no matter what
exec tail -f /dev/null
