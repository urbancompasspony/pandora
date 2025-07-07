#!/bin/bash
###################
# Project Pandora #
# Black Box Edition #
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
# Status files for real-time updates
statusfile="$pidfile/status.json"
counterfile="$pidfile/counter.txt"
# Status
statustest=".teste.em.andamento"
# Top 30 Critical UDP Ports for Corporate Black Box
critical_udp_ports="53,67,68,88,123,137,138,161,162,514,520,1161,1434,1645,1646,1701,1812,1813,3074,4500,5060,5061,8161,10161,10162,69,1069,8069,500,27015"
################################################################################

# Function to update status for web interface
update_status() {
    local current_counter=$1
    local total_ips=$2
    local vulnerabilities_found=$3
    local current_ip=${4:-"N/A"}
    
    # Determine status
    local scan_status="running"
    if [ "$current_ip" = "FINALIZADO" ] || [ "$current_counter" -eq "$total_ips" ]; then
        scan_status="completed"
        # Count actual vulnerabilities when completed
        vulnerabilities_found=$(find /Pentests/Ataque_Bem-Sucedido -name "RESUMO_*" -type f 2>/dev/null | wc -l)
    fi

    # Create JSON status for web interface
    cat > "$statusfile" << EOF
{
    "timestamp": "$(date '+%d-%m-%Y %H:%M')",
    "status": "$scan_status",
    "progress": {
        "current": $current_counter,
        "total": $total_ips,
        "percentage": $(( current_counter * 100 / total_ips ))
    },
    "vulnerabilities": $vulnerabilities_found,
    "current_target": "$current_ip",
    "device": "$namepan"
}
EOF
    
    # Update web stats as well
    update_web_stats
}

# Function to update web statistics
update_web_stats() {
    local today_pattern=$(date +"%d_%m_%y")
    local test_count=$(find /Pentests/Todos_os_Resultados -maxdepth 1 -type d -name "${today_pattern}*" 2>/dev/null | wc -l)
    local vuln_count=$(find /Pentests/Ataque_Bem-Sucedido -name "RESUMO_*" -type f -newermt "today" 2>/dev/null | wc -l)
    local total_ips_scanned=0
    
    # Count total IPs scanned today
    if [ -d "/Pentests/Todos_os_Resultados" ]; then
        for dir in /Pentests/Todos_os_Resultados/${today_pattern}*; do
            if [ -d "$dir" ]; then
                local ip_count=$(find "$dir" -maxdepth 1 -type f -name "[0-9]*" 2>/dev/null | wc -l)
                total_ips_scanned=$((total_ips_scanned + ip_count))
            fi
        done
    fi
    
    cat > /Pentests/stats.json << EOF
{
    "tests_today": $test_count,
    "vulnerabilities": $vuln_count,
    "total_ips_scanned": $total_ips_scanned,
    "last_update": "$(date '+%Y-%m-%d %H:%M:%S')",
    "device": "$namepan",
    "status": "active"
}
EOF
    
    chmod 644 /Pentests/stats.json
    chown www-data:www-data /Pentests/stats.json
}

# Function to get current counter atomically
get_counter() {
    local lockfile="${counterfile}.lock"

    # Atomic increment with file locking
    (
        flock -x 200
        if [ -f "$counterfile" ]; then
            counter=$(cat "$counterfile")
        else
            counter=0
        fi
        counter=$((counter + 1))
        echo "$counter" > "$counterfile"
        echo "$counter"
    ) 200>"$lockfile"
}

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
        echo "Dependencias nao encontradas: ${missing_deps[*]}" | tee -a "$tolog"
        echo "Instalando dependencias..." | tee -a "$tolog"
        apt-get update && apt-get install -y "${missing_deps[@]}"

        if [ $? -ne 0 ]; then
            echo "Erro ao instalar dependencias! Saindo..." | tee -a "$tolog"
            exit 1
        fi
    fi
}

# Function to adjust parallel jobs based on system load
adjust_parallel_jobs() {
    local current_load=$(uptime | awk '{print $10}' | cut -d',' -f1)

    if command -v bc &> /dev/null; then
        if (( $(echo "$current_load > 3.0" | bc -l) )); then
            RUNA=$((RUNA/2))
            echo "Sistema sobrecarregado (load: $current_load). Reduzindo jobs paralelos para $RUNA" | tee -a "$tolog"
        fi
    fi

    # For black box aggressive scanning, minimum of 1 job
    if [ "$RUNA" -lt 1 ]; then
        RUNA=1
    fi

    # For networks with pfSense/firewalls, reduce aggressiveness
    if [ "$RUNA" -gt 2 ]; then
        RUNA=2
        echo "Rede com firewall detectada: Limitando a 2 jobs paralelos para evitar state table overflow" | tee -a "$tolog"
    fi
}

# Function to generate HTML report
generate_html_report() {
    local vuln_count=$(find "$vuln0" -type f -name "RESUMO_*" 2>/dev/null | wc -l)
    local total_files=$(find "$pathtest/$name" -type f -name "[0-9]*" 2>/dev/null | wc -l)
    local tcp_scan_count=$(find "$pathtest/$name" -type f -name "*_tcp_*" 2>/dev/null | wc -l)
    local udp_scan_count=$(find "$pathtest/$name" -type f -name "*_udp_*" 2>/dev/null | wc -l)

    cat > "$pathtest/$name/relatorio.html" << 'REPORTEOF'
<!DOCTYPE html>
<html>
<head>
    <title>Relatorio Black Box Pentest</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #0a0a0a; color: #e0e0e0; }
        .header { background: linear-gradient(135deg, #800000 0%, #4a0000 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px; }
        .stats { background: #1a1a1a; border: 1px solid #333; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .vulnerable { background-color: #2d0000; border-left: 5px solid #ff4444; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .safe { background-color: #002d00; border-left: 5px solid #44ff44; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .warning { background-color: #2d2d00; border-left: 5px solid #ffff44; padding: 15px; border-radius: 5px; margin: 10px 0; }
        a { color: #4499ff; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .blackbox-badge { background: #660000; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Project Pandora - Black Box Edition</h1>
        <h2>Penetration Testing Results</h2>
        <span class="blackbox-badge">DOUBLE BLIND BLACK BOX</span>
    </div>

    <div class="grid">
        <div class="stats">
            <h3>Estatisticas de Scanning</h3>
        </div>

        <div class="stats">
            <h3>Metodologia Black Box</h3>
            <p><strong>TCP Ports:</strong> Full scan 1-65535</p>
            <p><strong>UDP Ports:</strong> Top 30 criticas corporativas</p>
            <p><strong>Scripts:</strong> vuln,safe,discovery</p>
            <p><strong>Stealth Level:</strong> T2 (Firewall-friendly)</p>
        </div>
    </div>

    <div class="warning">
        <h3>Consideracoes Black Box</h3>
        <p><strong>Cobertura:</strong> Este scan cobriu servicos expostos externamente</p>
        <p><strong>Limitacoes:</strong> Aplicacoes web, autenticacao e logica de negocio requerem testes manuais</p>
        <p><strong>Proximos passos:</strong> Manual enumeration, web app testing, social engineering</p>
    </div>

    <hr>
    <p><em>Relatorio gerado automaticamente pelo Project Pandora - Black Box Edition</em></p>
    <p><em>Este e um pentest automatizado. Testes manuais adicionais sao recomendados.</em></p>
</body>
</html>
REPORTEOF
}

# Function to perform aggressive black box port scanning
aggressive_black_box_scan() {
    local ip=$1
    local tcp_results="$pathtest/$name/${ip}_tcp_full"
    local udp_results="$pathtest/$name/${ip}_udp_critical"
    local final_results="$pathtest/$name/$ip"

    # Get current counter atomically
    local current_counter=$(get_counter)
    local total_ips=$(cat "$toip1" | wc -l)

    echo "[$current_counter/$total_ips] BLACK BOX SCAN: $ip" | tee -a "$tolog"

    # Update status for web interface
    update_status "$current_counter" "$total_ips" "0" "$ip"

    # Phase 1: Full TCP port scan (1-65535) with firewall-friendly settings
    echo "[$current_counter/$total_ips] TCP Full Scan (1-65535) - $ip..." | tee -a "$tolog"
    nmap -Pn -sS -p 1-65535 --min-rate 1000 --max-retries 1 -T2 "$ip" | tee "$tcp_results"

    # Phase 2: Critical UDP ports with reduced rate for firewall compatibility
    echo "[$current_counter/$total_ips] UDP Critical Corporate Scan - $ip..." | tee -a "$tolog"
    nmap -Pn -sU -p "$critical_udp_ports" --min-rate 500 --max-retries 1 -T2 "$ip" | tee "$udp_results"

    # Check if any ports were found open
    local tcp_open=false
    local udp_open=false
    local open_tcp_ports=""
    local open_udp_ports=""

    if grep -q "open" "$tcp_results"; then
        tcp_open=true
        open_tcp_ports=$(grep "open" "$tcp_results" | grep "tcp" | awk '{print $1}' | cut -d'/' -f1 | grep -E '^[0-9]+$' | sort -n | tr '\n' ',' | sed 's/,$//')
    fi

    if grep -q "open" "$udp_results"; then
        udp_open=true
        open_udp_ports=$(grep "open" "$udp_results" | grep "udp" | awk '{print $1}' | cut -d'/' -f1 | grep -E '^[0-9]+$' | sort -n | tr '\n' ',' | sed 's/,$//')
    fi

    if [ "$tcp_open" = true ] || [ "$udp_open" = true ]; then
        echo "[$current_counter/$total_ips] ALVO INTERESSANTE: $ip - Iniciando analise de vulnerabilidades..." | tee -a "$tolog"

        # Initialize final results file
        echo "=== BLACK BOX PENETRATION TEST RESULTS ===" > "$final_results"
        echo "Target: $ip" >> "$final_results"
        echo "Scan Date: $(date)" >> "$final_results"
        echo "Methodology: Double Blind Black Box" >> "$final_results"
        echo "=============================================" >> "$final_results"
        echo "" >> "$final_results"

        # Phase 3: Detailed vulnerability assessment on open TCP ports
        if [ "$tcp_open" = true ] && [ -n "$open_tcp_ports" ]; then
            echo "[$current_counter/$total_ips] TCP Vulnerability Assessment - $ip (portas: $open_tcp_ports)..." | tee -a "$tolog"

            if echo "$open_tcp_ports" | grep -qE '^[0-9]+(,[0-9]+)*$'; then
                echo "=== TCP VULNERABILITY SCAN RESULTS ===" >> "$final_results"
                nmap -Pn -sS -sV -sC --script vuln,safe,discovery,auth,brute --script-timeout 300s -T2 -p "$open_tcp_ports" "$ip" | tee -a "$final_results"
                echo "" >> "$final_results"
            else
                echo "Formato de portas TCP invalido para $ip: $open_tcp_ports" | tee -a "$tolog"
                echo "Fazendo scan de servicos basicos como fallback..." | tee -a "$tolog"
                echo "=== TCP SERVICE DETECTION (FALLBACK) ===" >> "$final_results"
                nmap -Pn -sS -sV -sC --script safe -T2 "$ip" | tee -a "$final_results"
                echo "" >> "$final_results"
            fi
        fi

        # Phase 4: Detailed vulnerability assessment on open UDP ports
        if [ "$udp_open" = true ] && [ -n "$open_udp_ports" ]; then
            echo "[$current_counter/$total_ips] UDP Vulnerability Assessment - $ip (portas: $open_udp_ports)..." | tee -a "$tolog"

            if echo "$open_udp_ports" | grep -qE '^[0-9]+(,[0-9]+)*$'; then
                echo "=== UDP VULNERABILITY SCAN RESULTS ===" >> "$final_results"
                nmap -Pn -sU -sV -sC --script vuln,safe,discovery --script-timeout 300s -T2 -p "$open_udp_ports" "$ip" | tee -a "$final_results"
                echo "" >> "$final_results"
            else
                echo "Formato de portas UDP invalido para $ip: $open_udp_ports" | tee -a "$tolog"
                echo "Fazendo scan UDP limitado como fallback..." | tee -a "$tolog"
                echo "=== UDP SERVICE DETECTION (FALLBACK) ===" >> "$final_results"
                nmap -Pn -sU --script safe -T2 -p "$critical_udp_ports" "$ip" | tee -a "$final_results"
                echo "" >> "$final_results"
            fi
        fi

        # Phase 5: Additional reconnaissance for interesting targets
        if [ "$tcp_open" = true ]; then
            echo "[$current_counter/$total_ips] Reconnaissance adicional - $ip..." | tee -a "$tolog"
            echo "=== ADDITIONAL RECONNAISSANCE ===" >> "$final_results"

            # OS Detection
            nmap -Pn -O --osscan-guess -T2 "$ip" 2>/dev/null | grep -E "(OS|Device|Network Distance)" >> "$final_results" 2>/dev/null || echo "OS Detection: Failed" >> "$final_results"

            # Traceroute for network mapping
            nmap -Pn --traceroute -T2 "$ip" 2>/dev/null | grep -A 20 "TRACEROUTE" >> "$final_results" 2>/dev/null || echo "Traceroute: Failed" >> "$final_results"

            echo "" >> "$final_results"
        fi

        # Clean up temp files
        rm -f "$tcp_results" "$udp_results"
        return 0
    else
        echo "[$current_counter/$total_ips] Host sem servicos expostos: $ip" | tee -a "$tolog"
        echo "No accessible services found on $ip (Black Box Scan)" > "$final_results"
        echo "TCP Scan: 1-65535 (No open ports)" >> "$final_results"
        echo "UDP Scan: Critical 30 ports (No open ports)" >> "$final_results"
        rm -f "$tcp_results" "$udp_results"
        return 1
    fi
}

# Function to check for vulnerabilities with enhanced detection
check_vulnerabilities() {
    local vuln_found=1  # Default to no vulnerabilities found

    echo "Analisando resultados para vulnerabilidades criticas..." | tee -a "$tolog"

    while read -r line; do
    if [ -f "$pathtest/$name/$line" ]; then
            if grep -E "(VULNERABLE|Exploitable|CVE-|EXPLOIT|CRITICAL|HIGH|appears to be vulnerable)" "$pathtest/$name/$line" > /dev/null; then
                # Check if it's NOT a false positive
                if ! grep -E "(NOT VULNERABLE|not vulnerable|Not vulnerable|NOT Exploitable|not exploitable|Not exploitable|State: NOT VULNERABLE|: Not vulnerable|Status: Not vulnerable)" "$pathtest/$name/$line" > /dev/null; then
                    mkdir -p "$vuln0"
                    
                    # Copy the full scan result directly to vuln folder (no subfolder)
                    cp "$pathtest/$name/$line" "$vuln0/${line}_scan.txt"
                    
                    # Generate detailed summary directly in vuln folder (no subfolder)
                    echo "=== VULNERABILIDADE CRITICA ENCONTRADA ===" > "$vuln0/RESUMO_${line}.txt"
                    echo "IP: $line" >> "$vuln0/RESUMO_${line}.txt"
                    echo "Data: $datetime2" >> "$vuln0/RESUMO_${line}.txt"
                    echo "Dispositivo: $namepan" >> "$vuln0/RESUMO_${line}.txt"
                    echo "Metodologia: Black Box Double Blind" >> "$vuln0/RESUMO_${line}.txt"
                    echo "" >> "$vuln0/RESUMO_${line}.txt"
                    echo "VULNERABILIDADES DETECTADAS:" >> "$vuln0/RESUMO_${line}.txt"
                    echo "=============================" >> "$vuln0/RESUMO_${line}.txt"
                    grep -E "(VULNERABLE|Exploitable|CVE-|EXPLOIT|CRITICAL|HIGH|appears to be vulnerable)" "$pathtest/$name/$line" >> "$vuln0/RESUMO_${line}.txt"
                    echo "" >> "$vuln0/RESUMO_${line}.txt"
                    echo "CONTEXTO COMPLETO:" >> "$vuln0/RESUMO_${line}.txt"
                    echo "==================" >> "$vuln0/RESUMO_${line}.txt"
                    cat "$pathtest/$name/$line" >> "$vuln0/RESUMO_${line}.txt"

                    vuln_found=0  # Vulnerabilities found
                    echo "VULNERABILIDADE CRITICA DETECTADA em $line!" | tee -a "$tolog"
                else
                    echo "[$line] Resultado 'not vulnerable' ignorado (não é vulnerabilidade real)" | tee -a "$tolog"
                fi
            fi
        fi
    done < "$toip1"

    # Create an index file for better web navigation if vulnerabilities found
    if [ "$vuln_found" -eq 0 ]; then
        cat > "$vuln0/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerabilidades Criticas - Project Pandora</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: "Courier New", monospace; background: #0a0a0a; color: #ff6666; margin: 20px; }
        .header { background: #2d0000; border: 2px solid #ff0000; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .vuln-list { background: #1a0000; border: 1px solid #ff4444; padding: 15px; border-radius: 5px; }
        a { color: #ff8888; text-decoration: none; font-weight: bold; display: block; margin: 5px 0; padding: 10px; background: #2d1111; border-radius: 3px; }
        a:hover { background: #442222; color: #ffaaaa; }
        .back-link { color: #00ffff; border: 1px solid #00ffff; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>VULNERABILIDADES CRITICAS DETECTADAS</h1>
HTMLEOF

        echo "        <p><strong>Scan Date:</strong> $datetime2</p>" >> "$vuln0/index.html"
        echo "        <p><strong>Device:</strong> $namepan</p>" >> "$vuln0/index.html"

        cat >> "$vuln0/index.html" << 'HTMLEOF'
    </div>
    <div class="vuln-list">
        <h3>Arquivos de Vulnerabilidades:</h3>
HTMLEOF

        # List all vulnerability files
        for file in "$vuln0"/*.txt; do
            if [ -f "$file" ]; then
                filename=$(basename "$file")
                echo "        <a href=\"$filename\">$filename</a>" >> "$vuln0/index.html"
            fi
        done

        cat >> "$vuln0/index.html" << 'HTMLEOF'
    </div>
    <br><a href="/" class="back-link">Voltar ao Dashboard</a>
</body>
</html>
HTMLEOF
    fi

    return $vuln_found
}

# Function to manage IP cache for black box environments
manage_ip_cache() {
    # Create cache directory if it doesn't exist
    mkdir -p "$(dirname "$cachefile")"

    # For black box, keep cache for 48 hours instead of 24
    if [ -f "$cachefile" ]; then
        find "$cachefile" -mtime +2 -delete 2>/dev/null
    fi

    # Filter out recently scanned IPs
    if [ -f "$cachefile" ]; then
        echo "Removendo IPs escaneados nas ultimas 48h (Black Box Mode)..." | tee -a "$tolog"
        local recent_count=$(wc -l < "$cachefile" 2>/dev/null || echo 0)
        grep -v -F -x -f "$cachefile" "$toip1" > "$toip1.filtered" 2>/dev/null || cp "$toip1" "$toip1.filtered"
        mv "$toip1.filtered" "$toip1"
        echo "Cache: $recent_count IPs removidos da lista de scan." | tee -a "$tolog"
    fi

    # Add current IPs to cache
    cat "$toip1" >> "$cachefile"
    sort -u "$cachefile" -o "$cachefile" 2>/dev/null
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
        echo "Erro ao criar diretorio de testes!" | tee -a "$tolog"
        exit 1
    fi

    # Generate some Files and Vars
    touch "$pathtest"/"$name"/01_A_IP; toip="$pathtest"/"$name"/01_A_IP
    touch "$pathtest"/"$name"/02_Logs; tolog="$pathtest"/"$name"/02_Logs
    touch "$pathtest"/"$name"/03_WBIP; toip1="$pathtest"/"$name"/03_WBIP
    touch "$pathtest"/"$name"/04_Blacklist
    cat "/Data/blacklist" | tee "$pathtest"/"$name"/04_Blacklist

    # Initialize counter file
    echo "0" > "$counterfile"
    update_web_stats
    
    # Check dependencies
    check_dependencies

    # Some logs
    echo "BLACK BOX PENTEST INICIADO em $datetime!" | tee -a "$tolog"
    echo "Dispositivo: $namepan" | tee -a "$tolog"
    echo "Metodologia: Double Blind Black Box" | tee -a "$tolog"
    echo "TCP Scope: Full scan 1-65535" | tee -a "$tolog"
    echo "UDP Scope: Top 30 portas criticas corporativas" | tee -a "$tolog"

    # Generate IPs to analyze with improved discovery
    echo "Descobrindo hosts ativos na rede..." | tee -a "$tolog"
    nmap -n -sn --min-rate 2000 $(hostname -I | awk '{print $1}')"/24" | grep "Nmap scan report" | awk '{print $5}' | tee "$toip"

    # Remove Blacklist IPs
    grep -v -F -x -f "/Data/blacklist" "$toip" | tee "$toip1"

    # Manage IP cache for black box
    manage_ip_cache

    # Calculate remaining hosts
    lres=$(wc -l < "$toip1")
    echo "BLACK BOX TARGET: $lres IPs para analise completa." | tee -a "$tolog"

    if [ "$lres" -eq 0 ]; then
        echo "Nenhum IP para testar. Finalizando..." | tee -a "$tolog"
        exit 0
    fi

    # Adjust parallel jobs for black box stealth
    adjust_parallel_jobs
    echo "Black Box Mode: Utilizando $RUNA jobs paralelos (stealth)." | tee -a "$tolog"

    # Kill nmap after 7200 seconds (2 hours) for black box comprehensive scans
    sleep 7200 && pkill nmap & echo $! | tee "$pidfile"/"$statustest"

    # Progress tracking
    total_ips=$lres

    echo "INICIANDO BLACK BOX PENETRATION TEST..." | tee -a "$tolog"
    echo "Target Network: $(hostname -I | awk '{print $1}')/24" | tee -a "$tolog"
    echo "Critical UDP Ports: $critical_udp_ports" | tee -a "$tolog"

    # Export functions and variables for parallel execution
    export -f aggressive_black_box_scan get_counter update_status
    export pathtest name tolog total_ips critical_udp_ports counterfile statusfile toip1

    # Execute aggressive black box scanning
    cat "$toip1" | parallel -j "$RUNA" -k "aggressive_black_box_scan {} && echo 'CONCLUIDO: {}' || echo 'FALHOU: {}'"

    # When finished
    datetime2=$(date +"%d/%m/%y %H:%M")

    # Update final status
    final_counter=$(cat "$counterfile" 2>/dev/null || echo "$total_ips")
    update_status "$final_counter" "$total_ips" "0" "FINALIZADO"

    # Just some last logs to finish this.
    echo "BLACK BOX PENTEST CONCLUIDO: $datetime ate $datetime2." | tee -a "$tolog"

    # Kill NMAP killer!
    if [ -f "$pidfile/$statustest" ]; then
        pidsleep=$(cat "$pidfile/$statustest")
        echo "Killing PID $pidsleep of sleep_&_auto_kill nmap process" | tee -a "$tolog"
        kill -9 "$pidsleep" 2>/dev/null
        pkill sleep 2>/dev/null
        rm "$pidfile"/"$statustest"
    fi

    # Enhanced vulnerability detection
    echo "Analisando resultados para vulnerabilidades criticas..." | tee -a "$tolog"
    check_vulnerabilities
    vuln_result=$?

    sleep 1

    # Register some logs
    echo "Resultados completos em: $pathtest/$name" | tee -a "$tolog"

    # Generate comprehensive HTML report
    echo "Gerando relatorio Black Box HTML..." | tee -a "$tolog"
    generate_html_report

    sleep 1

    # Zip files!
    echo "Compactando resultados do Black Box..." | tee -a "$tolog"
    zip -r "$zipfiles/$name.zip" "$pathtest/$name" >> "$tolog" 2>&1

    sleep 1

    # Change permissions
    chmod 777 -R "$pidfile"

    # Remove old Files with better cleanup
    echo "Limpando arquivos antigos..." | tee -a "$tolog"
    find "$vuln0" -type f -mtime +3 -delete 2>/dev/null
    find "$pathtest" -type d -mtime +3 -exec rm -rf {} + 2>/dev/null
    find "$pathtest" -type d -empty -delete 2>/dev/null
    find "$zipfiles" -type f -mtime +15 -delete 2>/dev/null

    # Send message with attachments
    sleep 1
    tontfy=$(cat /Data/ntfysh)

    if [ "$tontfy" != "0" ]; then
        if [ "$vuln_result" -eq 0 ]; then
            echo "ALERTA: Enviando notificacao de vulnerabilidades criticas..." | tee -a "$tolog"
            curl -u admin:5V06auso -T "$zipfiles"/"$name".zip -H "Filename: $name.zip" -H "Title: VULNERABILIDADES CRITICAS - BLACK BOX - $namepan" -H "Priority: urgent" "$ntfysh"/"$namepan"
        else
            echo "Enviando notificacao - Black Box scan concluido." | tee -a "$tolog"
            curl -u admin:5V06auso -d "Black Box Pentest concluido em $namepan. $lres IPs testados. TCP: 1-65535, UDP: Top 30 criticas. Nenhuma vulnerabilidade critica detectada." -H "Title: Black Box Scan Concluido - $namepan" "$ntfysh"/"$namepan"
        fi
    fi

    echo "BLACK BOX PENETRATION TEST FINALIZADO!" | tee -a "$tolog"
    echo "Relatorio HTML: $pathtest/$name/relatorio.html" | tee -a "$tolog"
    echo "Metodologia: Double Blind Black Box Complete" | tee -a "$tolog"
    echo "Cobertura: TCP 1-65535 + UDP Top 30 Critical" | tee -a "$tolog"

    # Clean up counter file
    update_web_stats
    rm -f "$counterfile" "${counterfile}.lock"
}

# SUDO check!
if [ "$EUID" -ne 0 ]; then
    echo "Execute esse script como Root! Saindo..."
    exit 1
fi

# Start all here
echo "Project Pandora - Black Box Penetration Tester"
echo "Double Blind Corporate Assessment Edition"
echo "TCP: Full 1-65535 | UDP: Top 30 Critical"
echo "=============================================="

init

echo "Black Box Penetration Test finalizado com sucesso!"
exit 0
