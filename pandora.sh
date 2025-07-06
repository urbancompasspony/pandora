#!/bin/bash
###################
# Project Pandora #
################################################################################
# Name for this Pandora device.
namepan=$(cat /Data/hostname)
# ntfy server:
ntfysh=$(cat /Data/ntfysh)
# How many parallel jobs will run at time.
RUNA=$(cat /Data/runa)
# PID FILE
pidfile="/Pentests"
# Vulnerable Systems!
vuln0="$pidfile/Ataque_Bem-Sucedido"
# Custom path for PENTESTS results
pathtest="$pidfile/Todos_os_Resultados"
# Custom path for ZIPPED files from results.
zipfiles="$pidfile/Historico"
# Cache file for recent scans
cachefile="$pidfile/cache_ips"
# Status
statustest=".teste.em.andamento"
################################################################################

# Function to check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command -v nmap &> /dev/null; then
        missing_deps+=("nmap")
    fi
    
    if ! command -v parallel &> /dev/null; then
        missing_deps+=("parallel")
    fi
    
    if ! command -v bc &> /dev/null; then
        missing_deps+=("bc")
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo "Dependências não encontradas: ${missing_deps[*]}" | tee -a "$tolog"
        echo "Instalando dependências..." | tee -a "$tolog"
        apt-get update && apt-get install -y "${missing_deps[@]}"
        
        if [ $? -ne 0 ]; then
            echo "Erro ao instalar dependências! Saindo..." | tee -a "$tolog"
            exit 1
        fi
    fi
}

# Function to adjust parallel jobs based on system load
adjust_parallel_jobs() {
    local current_load=$(uptime | awk '{print $10}' | cut -d',' -f1)
    
    if command -v bc &> /dev/null; then
        if (( $(echo "$current_load > 2.0" | bc -l) )); then
            RUNA=$((RUNA/2))
            echo "Sistema sobrecarregado (load: $current_load). Reduzindo jobs paralelos para $RUNA" | tee -a "$tolog"
        fi
    fi
    
    # Ensure minimum of 1 job
    if [ "$RUNA" -lt 1 ]; then
        RUNA=1
    fi
}

# Function to generate HTML report
generate_html_report() {
    local vuln_count=$(find "$vuln0" -type f -name "RESUMO_*" 2>/dev/null | wc -l)
    local total_files=$(find "$pathtest/$name" -type f -name "[0-9]*" 2>/dev/null | wc -l)
    
    cat > "$pathtest/$name/relatorio.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Relatório Pentester - $name</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .stats { background-color: #e8f5e8; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .vulnerable { background-color: #ffe6e6; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .safe { background-color: #e6ffe6; padding: 15px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Relatório de Pentest - Project Pandora</h1>
        <h2>Dispositivo: $namepan</h2>
        <p><strong>Período:</strong> $datetime até $datetime2</p>
    </div>
    
    <div class="stats">
        <h3>📊 Estatísticas Gerais</h3>
        <p><strong>IPs descobertos:</strong> $lres</p>
        <p><strong>IPs testados:</strong> $total_files</p>
        <p><strong>Vulnerabilidades encontradas:</strong> $vuln_count</p>
        <p><strong>Jobs paralelos utilizados:</strong> $RUNA</p>
    </div>
    
    $(if [ "$vuln_count" -gt 0 ]; then
        echo '<div class="vulnerable">'
        echo '<h3>⚠️ VULNERABILIDADES DETECTADAS</h3>'
        echo '<p><strong>Atenção:</strong> Foram encontradas vulnerabilidades críticas!</p>'
        echo '<p>Verifique os arquivos em: '"$vuln0"'</p>'
        echo '</div>'
    else
        echo '<div class="safe">'
        echo '<h3>✅ NENHUMA VULNERABILIDADE CRÍTICA</h3>'
        echo '<p>Não foram encontradas vulnerabilidades exploráveis neste scan.</p>'
        echo '</div>'
    fi)
    
    <div class="stats">
        <h3>📁 Arquivos Gerados</h3>
        <p><strong>Resultados completos:</strong> $pathtest/$name</p>
        <p><strong>Arquivo compactado:</strong> $zipfiles/$name.zip</p>
        <p><strong>Logs do teste:</strong> $tolog</p>
    </div>
    
    <hr>
    <p><em>Relatório gerado automaticamente pelo Project Pandora</em></p>
</body>
</html>
EOF
}

# Function to perform comprehensive port scanning
smart_port_scan() {
    local ip=$1
    local temp_ports="$pathtest/$name/${ip}_ports_temp"
    local temp_udp="$pathtest/$name/${ip}_udp_temp"
    
    # Phase 1: Quick TCP SYN scan on common ports
    echo "[$counter/$total_ips] 🔍 TCP SYN scan em portas comuns - $ip..." | tee -a "$tolog"
    nmap -Pn -sS --top-ports 1000 --min-rate 1000 "$ip" | tee "$temp_ports"
    
    # Phase 2: Quick UDP scan on critical ports
    echo "[$counter/$total_ips] 🔍 UDP scan em portas críticas - $ip..." | tee -a "$tolog"
    nmap -Pn -sU --top-ports 100 --min-rate 500 "$ip" | tee "$temp_udp"
    
    # Check if any TCP ports are open
    local tcp_open=false
    local udp_open=false
    
    if grep -q "open" "$temp_ports"; then
        tcp_open=true
    fi
    
    if grep -q "open" "$temp_udp"; then
        udp_open=true
    fi
    
    if [ "$tcp_open" = true ] || [ "$udp_open" = true ]; then
        echo "[$counter/$total_ips] ✅ Portas abertas encontradas em $ip. Iniciando análise detalhada..." | tee -a "$tolog"
        
        # Extract open TCP ports
        local tcp_ports=""
        if [ "$tcp_open" = true ]; then
            tcp_ports=$(grep "open" "$temp_ports" | grep "tcp" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
        fi
        
        # Extract open UDP ports  
        local udp_ports=""
        if [ "$udp_open" = true ]; then
            udp_ports=$(grep "open" "$temp_udp" | grep "udp" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
        fi
        
        # Phase 3: Detailed scanning with version detection and vulnerability scripts
        if [ -n "$tcp_ports" ]; then
            echo "[$counter/$total_ips] 🔬 Análise detalhada TCP - $ip (portas: $tcp_ports)..." | tee -a "$tolog"
            nmap -Pn -sS -sV --script vuln,safe -T4 --min-rate 1000 -p "$tcp_ports" "$ip" | tee -a "$pathtest/$name/$ip"
            
            # Optional: Stealth scans for evasion (uncomment if needed)
            # echo "[$counter/$total_ips] 🥷 XMAS scan para evasão - $ip..." | tee -a "$tolog"
            # nmap -Pn -sX -p "$tcp_ports" "$ip" | tee -a "$pathtest/$name/${ip}_stealth"
        fi
        
        if [ -n "$udp_ports" ]; then
            echo "[$counter/$total_ips] 🔬 Análise detalhada UDP - $ip (portas: $udp_ports)..." | tee -a "$tolog"
            nmap -Pn -sU -sV --script vuln,safe -T4 --min-rate 500 -p "$udp_ports" "$ip" | tee -a "$pathtest/$name/$ip"
        fi
        
        # Clean up temp files
        rm -f "$temp_ports" "$temp_udp"
        return 0
    else
        echo "[$counter/$total_ips] ❌ Nenhuma porta aberta encontrada em $ip. Pulando..." | tee -a "$tolog"
        echo "No open ports found on $ip (TCP/UDP)" > "$pathtest/$name/$ip"
        rm -f "$temp_ports" "$temp_udp"
        return 1
    fi
}

# Function to check for vulnerabilities with enhanced detection
check_vulnerabilities() {
    local vuln_found=0
    
    while read -r line; do
        if [ -f "$pathtest/$name/$line" ]; then
            if grep -E "(VULNERABLE|Exploitable|CVE-|EXPLOIT|CRITICAL)" "$pathtest/$name/$line" > /dev/null; then
                mkdir -p "$vuln0"
                cp "$pathtest/$name/$line" "$vuln0"
                
                # Generate detailed summary
                echo "=== VULNERABILIDADE ENCONTRADA ===" > "$vuln0/RESUMO_$line"
                echo "IP: $line" >> "$vuln0/RESUMO_$line"
                echo "Data: $datetime2" >> "$vuln0/RESUMO_$line"
                echo "Dispositivo: $namepan" >> "$vuln0/RESUMO_$line"
                echo "" >> "$vuln0/RESUMO_$line"
                echo "DETALHES:" >> "$vuln0/RESUMO_$line"
                grep -E "(VULNERABLE|Exploitable|CVE-|EXPLOIT|CRITICAL)" "$pathtest/$name/$line" >> "$vuln0/RESUMO_$line"
                
                vuln_found=1
                echo "⚠️  VULNERABILIDADE DETECTADA em $line!" | tee -a "$tolog"
            fi
        fi
    done < "$toip1"
    
    return $vuln_found
}

# Function to manage IP cache
manage_ip_cache() {
    # Create cache directory if it doesn't exist
    mkdir -p "$(dirname "$cachefile")"
    
    # Remove old cache entries (older than 24 hours)
    if [ -f "$cachefile" ]; then
        find "$cachefile" -mtime +1 -delete 2>/dev/null
    fi
    
    # Filter out recently scanned IPs
    if [ -f "$cachefile" ]; then
        echo "Removendo IPs escaneados recentemente..." | tee -a "$tolog"
        local recent_count=$(wc -l < "$cachefile")
        grep -v -F -x -f "$cachefile" "$toip1" > "$toip1.filtered"
        mv "$toip1.filtered" "$toip1"
        echo "Removidos $recent_count IPs do cache." | tee -a "$tolog"
    fi
    
    # Add current IPs to cache
    cat "$toip1" >> "$cachefile"
    sort -u "$cachefile" -o "$cachefile"
}

function init {
    # Set some vars
    datetime=$(date +"%d/%m/%y %H:%M")
    name=$(date +"%d_%m_%y-%H:%M")
    
    # Create main dir, if it does not exist
    mkdir -p "$zipfiles"
    mkdir -p "$pathtest"/"$name"
    
    # Check if directories were created successfully
    if [ ! -d "$pathtest/$name" ]; then
        echo "Erro ao criar diretório de testes!" | tee -a "$tolog"
        exit 1
    fi
    
    # Generate some Files and Vars
    touch "$pathtest"/"$name"/01_A_IP; toip="$pathtest"/"$name"/01_A_IP
    touch "$pathtest"/"$name"/02_Logs; tolog="$pathtest"/"$name"/02_Logs
    touch "$pathtest"/"$name"/03_WBIP; toip1="$pathtest"/"$name"/03_WBIP
    touch "$pathtest"/"$name"/04_Blacklist
    cat "/Data/blacklist" | tee "$pathtest"/"$name"/04_Blacklist
    
    # Check dependencies
    check_dependencies
    
    # Some logs
    echo "🚀 Pentest iniciado em $datetime!" | tee -a "$tolog"
    echo "📱 Dispositivo: $namepan" | tee -a "$tolog"
    
    # Generate IPs to analyze with improved discovery
    echo "🔍 Descobrindo hosts ativos..." | tee -a "$tolog"
    nmap -n -sn --min-rate 1000 $(hostname -I | awk '{print $1}')"/24" | grep "Nmap scan report" | awk '{print $5}' | tee "$toip"
    
    # Remove Blacklist IPs
    grep -v -F -x -f "/Data/blacklist" "$toip" | tee "$toip1"
    
    # Manage IP cache
    manage_ip_cache
    
    # Calculate remaining hosts
    lres=$(wc -l < "$toip1")
    echo "📊 Encontramos $lres IPs para analisar." | tee -a "$tolog"
    
    if [ "$lres" -eq 0 ]; then
        echo "⚠️  Nenhum IP para testar. Finalizando..." | tee -a "$tolog"
        exit 0
    fi
    
    # Adjust parallel jobs based on system load
    adjust_parallel_jobs
    echo "⚙️  Utilizando $RUNA jobs paralelos." | tee -a "$tolog"
    
    # Kill nmap after 3600 seconds (60 min) if hang!
    sleep 3600 && pkill nmap & echo $! | tee "$pidfile"/"$statustest"
    
    # Progress tracking
    total_ips=$lres
    counter=0
    
    echo "🔥 Iniciando testes de vulnerabilidade..." | tee -a "$tolog"
    
    # Export functions for parallel execution
    export -f smart_port_scan
    export pathtest name tolog counter total_ips
    
    # Do smart scanning with parallel processing
    cat "$toip1" | parallel -j "$RUNA" -k "smart_port_scan {} && echo 'Concluído: {}' || echo 'Falhou: {}'"
    
    # When finished
    datetime2=$(date +"%d/%m/%y %H:%M")
    
    # Just some last logs to finish this.
    echo "✅ Esse teste executou de $datetime ate $datetime2." | tee -a "$tolog"
    
    # Kill NMAP killer!
    if [ -f "$pidfile/$statustest" ]; then
        pidsleep=$(cat "$pidfile/$statustest")
        echo "🔄 Killing PID $pidsleep of sleep_&_auto_kill nmap process" | tee -a "$tolog"
        kill -9 "$pidsleep" 2>/dev/null
        pkill sleep 2>/dev/null
        rm "$pidfile"/"$statustest"
    fi
    
    # Enhanced vulnerability detection
    echo "🔍 Analisando vulnerabilidades..." | tee -a "$tolog"
    check_vulnerabilities
    vuln_result=$?
    
    sleep 1
    
    # Register some logs
    echo "📁 Os testes estao em $pathtest/$name" | tee -a "$tolog"
    
    # Generate HTML report
    echo "📊 Gerando relatório HTML..." | tee -a "$tolog"
    generate_html_report
    
    sleep 1
    
    # Zip files!
    echo "📦 Compactando resultados..." | tee -a "$tolog"
    zip -r "$zipfiles/$name.zip" "$pathtest/$name" >> "$tolog" 2>&1
    
    sleep 1
    
    # Change permissions
    chmod 777 -R "$pidfile"
    
    # Remove old Files with better cleanup
    echo "🧹 Limpando arquivos antigos..." | tee -a "$tolog"
    find "$vuln0" -type f -mtime +3 -delete 2>/dev/null
    find "$pathtest" -type d -mtime +3 -exec rm -rf {} + 2>/dev/null
    find "$pathtest" -type d -empty -delete 2>/dev/null
    find "$zipfiles" -type f -mtime +15 -delete 2>/dev/null
    
    # Send message with attachments
    sleep 1
    tontfy=$(cat /Data/ntfysh)
    
    if [ "$tontfy" != "0" ]; then
        if [ "$vuln_result" -eq 0 ]; then
            echo "📤 Enviando notificação com vulnerabilidades encontradas..." | tee -a "$tolog"
            curl -u admin:5V06auso -T "$zipfiles"/"$name".zip -H "Filename: $name.zip" -H "Title: ⚠️ VULNERABILIDADES ENCONTRADAS - $namepan" -H "Priority: high" "$ntfysh"/"$namepan"
        else
            echo "📤 Enviando notificação - scan concluído sem vulnerabilidades críticas." | tee -a "$tolog"
            curl -u admin:5V06auso -d "✅ Scan concluído em $namepan. $lres IPs testados. Nenhuma vulnerabilidade crítica encontrada." -H "Title: Scan Concluído - $namepan" "$ntfysh"/"$namepan"
        fi
    fi
    
    echo "🎉 Pentest finalizado com sucesso!" | tee -a "$tolog"
    echo "📊 Relatório HTML disponível em: $pathtest/$name/relatorio.html" | tee -a "$tolog"
}

# SUDO check!
if [ "$EUID" -ne 0 ]; then
    echo "❌ Execute esse script como Root! Saindo..."
    exit 1
fi

# Start all here
echo "🔰 Project Pandora - Pentester Automatizado"
echo "🔰 Versão Melhorada com Otimizações"
echo "=============================================="

init

echo "✅ Processo finalizado com sucesso!"
exit 0
