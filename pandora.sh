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
# Arquivo de controle de IPs testados
tested_ips_file="$pidfile/controle_ips_testados"
# Arquivo de controle de IPs pendentes
pending_ips_file="$pidfile/controle_ips_pendentes"
# Arquivo de controle de IPs falhas
failed_ips_file="$pidfile/controle_ips_falhas"
# Lock file para operacoes atomicas
control_lock_file="$pidfile/controle.lock"
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
    local today_pattern
    today_pattern=$(date +"%d_%m_%y")
    local test_count
    test_count=$(find /Pentests/Todos_os_Resultados -maxdepth 1 -type d -name "${today_pattern}*" 2>/dev/null | wc -l)
    local vuln_count
    vuln_count=$(find /Pentests/Ataque_Bem-Sucedido -name "RESUMO_*" -type f -newermt "today" 2>/dev/null | wc -l)
    local total_ips_scanned
    total_ips_scanned=0
    local test_count_48h=0
    local vuln_count_48h=0
    local yesterday_pattern
    yesterday_pattern=$(date -d "yesterday" +"%d_%m_%y")

    # Count total IPs scanned today
    if [ -d "/Pentests/Todos_os_Resultados" ]; then
        for dir in /Pentests/Todos_os_Resultados/"${today_pattern}"*; do
            if [ -d "$dir" ]; then
                local ip_count
                ip_count=$(find "$dir" -maxdepth 1 -type f -name "[0-9]*" 2>/dev/null | wc -l)
                total_ips_scanned=$((total_ips_scanned + ip_count))
            fi
        done
    fi

    if [ -d "/Pentests/Todos_os_Resultados" ]; then
        # Hoje
        test_count_48h=$(find /Pentests/Todos_os_Resultados -maxdepth 1 -type d -name "${today_pattern}*" 2>/dev/null | wc -l)
        # Ontem
        local yesterday_count
        yesterday_count=$(find /Pentests/Todos_os_Resultados -maxdepth 1 -type d -name "${yesterday_pattern}*" 2>/dev/null | wc -l)
        test_count_48h=$((test_count_48h + yesterday_count))
    fi

    vuln_count_48h=$(find /Pentests/Ataque_Bem-Sucedido -name "RESUMO_*" -type f -newermt "48 hours ago" 2>/dev/null | wc -l)

    {
        echo "{"
        echo "    \"tests_48h\": $test_count_48h,"
        echo "    \"vulnerabilities_48h\": $vuln_count_48h,"
        echo "    \"last_update\": \"$(date '+%Y-%m-%d %H:%M:%S')\","
        echo "    \"device\": \"$namepan\","
        echo "    \"status\": \"active\""
        echo "}"
    } > /Pentests/stats.json

    chmod 644 /Pentests/stats.json
    chown www-data:www-data /Pentests/stats.json
}

# Funcao para adicionar IP como testado (thread-safe)
mark_ip_as_tested() {
    local ip=$1
    local result=$2  # "success", "no_services", "host_down", "timeout", "network_error"
    local details=${3:-""}  # Detalhes opcionais da falha

    (
        flock -x 200

        # Adicionar ao arquivo de testados com timestamp, resultado e detalhes
        echo "$(date '+%d/%m/%y %H:%M:%S') $ip $result $details" >> "$tested_ips_file"

        # Remover das pendencias se existir
        if [ -f "$pending_ips_file" ]; then
            grep -v "^$ip$" "$pending_ips_file" > "$pending_ips_file.tmp" 2>/dev/null || touch "$pending_ips_file.tmp"
            mv "$pending_ips_file.tmp" "$pending_ips_file"
        fi

        # Estrategia de retry baseada no tipo de falha
        case "$result" in
            "host_down")
                # Host down: retry mais cedo (equipamento pode ligar)
                echo "$(date '+%d/%m/%y %H:%M:%S') $ip $result $details RETRY_6H" >> "$failed_ips_file"
                ;;
            "timeout")
                # Timeout: retry depois de mais tempo (pode estar sobrecarregado)
                echo "$(date '+%d/%m/%y %H:%M:%S') $ip $result $details RETRY_24H" >> "$failed_ips_file"
                ;;
            "network_error")
                # Erro de rede: retry em horario diferente
                echo "$(date '+%d/%m/%y %H:%M:%S') $ip $result $details RETRY_12H" >> "$failed_ips_file"
                ;;
        esac

    ) 200>"$control_lock_file"
}

# Funcao para verificar se IP deve ser testado
# Funcao para verificar se IP deve ser testado - APRIMORADA
should_test_ip() {
    local ip=$1

    # REGRA PRINCIPAL: Verificar se foi testado com sucesso nas ultimas 48h
    if is_ip_recently_tested "$ip" 48; then
        local last_result=""
        local last_test_time=""
        
        if [ -f "$tested_ips_file" ]; then
            local last_test_line
            last_test_line=$(grep " $ip " "$tested_ips_file" | tail -1)
            last_result=$(echo "$last_test_line" | awk '{print $3}')
            last_test_time=$(echo "$last_test_line" | awk '{print $1 " " $2}')
        fi

        # Se foi testado com sucesso ou sem servicos nas ultimas 48h, pular
        if [ "$last_result" = "success" ] || [ "$last_result" = "no_services" ]; then
            echo "IP $ip testado com sucesso nas ultimas 48h ($last_test_time - $last_result) - PULANDO" | tee -a "$tolog"
            return 1  # Nao testar
        fi
        
        # Se foi testado com falha nas ultimas 48h, verificar estrategia de retry
        echo "IP $ip testado com falha nas ultimas 48h ($last_result) - verificando retry..." | tee -a "$tolog"
    fi

    # Verificar retry baseado no tipo de falha (apenas se houve falha recente)
    if [ -f "$failed_ips_file" ]; then
        local last_failure
        last_failure=$(grep " $ip " "$failed_ips_file" | tail -1)

        if [ -n "$last_failure" ]; then
            local failure_date
            failure_date=$(echo "$last_failure" | awk '{print $1}')
            local failure_time
            failure_time=$(echo "$last_failure" | awk '{print $2}')
            local failure_type
            failure_type=$(echo "$last_failure" | awk '{print $3}')
            local retry_strategy
            retry_strategy=$(echo "$last_failure" | awk '{print $NF}')

            # Converter timestamp da falha
            local failure_timestamp
            failure_timestamp=$(date -d "$failure_date $failure_time" +%s 2>/dev/null)
            local current_timestamp
            current_timestamp=$(date +%s)
            local hours_since_failure
            hours_since_failure=$(( (current_timestamp - failure_timestamp) / 3600 ))

            # Aplicar estrategia de retry apenas se a falha foi recente
            case "$retry_strategy" in
                "RETRY_6H")
                    if [ "$hours_since_failure" -lt 6 ]; then
                        echo "IP $ip falhou ha ${hours_since_failure}h (host_down) - aguardando 6h para retry" | tee -a "$tolog"
                        return 1
                    fi
                    ;;
                "RETRY_12H")
                    if [ "$hours_since_failure" -lt 12 ]; then
                        echo "IP $ip falhou ha ${hours_since_failure}h (network_error) - aguardando 12h para retry" | tee -a "$tolog"
                        return 1
                    fi
                    ;;
                "RETRY_24H")
                    if [ "$hours_since_failure" -lt 24 ]; then
                        echo "IP $ip falhou ha ${hours_since_failure}h (timeout) - aguardando 24h para retry" | tee -a "$tolog"
                        return 1
                    fi
                    ;;
            esac

            echo "IP $ip elegivel para retry apos ${hours_since_failure}h (falha: $failure_type)" | tee -a "$tolog"
        fi
    fi

    # Se chegou ate aqui, pode testar
    echo "IP $ip APROVADO para teste" | tee -a "$tolog"
    return 0  # Pode testar
}

# Funcao para detectar tipo de ambiente/horario
detect_environment_context() {
    local current_hour
    current_hour=$(date +%H)

    # Detectar se e horario comercial (7-18h)
    if [ "$current_hour" -ge 7 ] && [ "$current_hour" -le 18 ]; then
        echo "business_hours"
    else
        echo "after_hours"
    fi
}

# Funcao avancada de verificacao de conectividade
advanced_connectivity_check() {
    local ip=$1

    echo "Verificando conectividade avancada para $ip..." | tee -a "$tolog"

    # Teste 1: Ping basico (ICMP)
    if ping -c 1 -W 2 "$ip" >/dev/null 2>&1; then
        echo "ICMP ping: OK" | tee -a "$tolog"
        return 0  # Host responde
    fi

    # Teste 2: TCP ping em portas comuns (mesmo se ICMP bloqueado)
    local common_ports="22 23 25 53 80 135 139 443 445 993 995 3389 5985 5986"

    for port in $common_ports; do
        if timeout 3 bash -c "</dev/tcp/$ip/$port" 2>/dev/null; then
            echo "TCP ping porta $port: OK (ICMP possivelmente bloqueado)" | tee -a "$tolog"
            return 0  # Host responde em TCP
        fi
    done

    # Teste 3: Nmap host discovery (ultimo recurso)
    if timeout 30 nmap -Pn -p 80,443,22,135 --max-retries 1 "$ip" 2>/dev/null | grep -q "Host is up"; then
        echo "Nmap discovery: Host detectado" | tee -a "$tolog"
        return 0
    fi

    echo "✗ Todos os testes falharam - host down ou inacessivel" | tee -a "$tolog"
    return 1  # Host realmente down
}

# Funcao para verificar se IP ja foi testado nas ultimas X horas
is_ip_recently_tested() {
    local ip=$1
    local hours_limit=${2:-24}  # Default 24h

    if [ ! -f "$tested_ips_file" ]; then
        return 1  # Nao foi testado
    fi

    # Buscar ultima entrada do IP
    local last_test
    last_test=$(grep " $ip " "$tested_ips_file" | tail -1)

    if [ -z "$last_test" ]; then
        return 1  # Nao encontrado
    fi

    # Extrair timestamp
    local test_date
    test_date=$(echo "$last_test" | awk '{print $1 " " $2}')

    # Converter para timestamp Unix
    local test_timestamp
    test_timestamp=$(date -d "$test_date" +%s 2>/dev/null)

    if [ -z "$test_timestamp" ]; then
        return 1  # Erro na conversao
    fi

    # Calcular diferenca em horas
    local current_timestamp
    current_timestamp=$(date +%s)
    local diff_hours
    diff_hours=$(( (current_timestamp - test_timestamp) / 3600 ))

    if [ "$diff_hours" -lt "$hours_limit" ]; then
        return 0  # Foi testado recentemente
    else
        return 1  # Nao foi testado recentemente
    fi
}

# Funcao para adicionar IPs pendentes - CORRIGIDA
add_pending_ips() {
    local ip_list_file=$1

    (
        flock -x 200

        # Limpar arquivo de pendentes existente para re-avaliar todos os IPs
        > "$pending_ips_file"

        # Adicionar IPs como pendentes APENAS se nao foram testados nas ultimas 48h
        while read -r ip; do
            if ! is_ip_recently_tested "$ip" 48; then
                echo "$ip" >> "$pending_ips_file"
            else
                echo "IP $ip testado nas ultimas 48h - removendo dos pendentes" | tee -a "$tolog"
            fi
        done < "$ip_list_file"

        # Remover duplicatas
        if [ -f "$pending_ips_file" ]; then
            sort -u "$pending_ips_file" -o "$pending_ips_file"
        fi

    ) 200>"$control_lock_file"
}

# Funcao para limpar arquivos de controle antigos
cleanup_old_control_files() {
    local days_limit=${1:-7}  # Default 7 dias

    echo "Limpando registros de controle antigos (>$days_limit dias)..." | tee -a "$tolog"

    if [ -f "$tested_ips_file" ]; then
        # Criar backup se arquivo muito grande
        if [ $(wc -l < "$tested_ips_file") -gt 10000 ]; then
            mv "$tested_ips_file" "${tested_ips_file}.backup.$(date +%Y%m%d)"
            touch "$tested_ips_file"
        fi
    fi

    # Limpar falhas antigas
    if [ -f "$failed_ips_file" ]; then
        find "$failed_ips_file" -mtime +"$days_limit" -delete 2>/dev/null
    fi
}

cleanup_old_files() {
    echo "=== INICIANDO LIMPEZA AGRESSIVA (MAX 7 DIAS) ===" | tee -a "$tolog"

    # 1. Limpeza do diretório de vulnerabilidades (/Ataque_Bem-Sucedido/)
    # REGRA: 3 dias máximo
    if [ -d "$vuln0" ]; then
        echo "Limpando vulnerabilidades antigas em $vuln0 (>3 dias)..." | tee -a "$tolog"

        # Contar arquivos antes
        vuln_before=$(find "$vuln0" -type f 2>/dev/null | wc -l)

        # AGRESSIVO: Apagar TODOS os arquivos > 3 dias
        find "$vuln0" -type f -mtime +3 -delete 2>/dev/null

        # Contar após limpeza
        vuln_after=$(find "$vuln0" -type f 2>/dev/null | wc -l)
        vuln_removed=$((vuln_before - vuln_after))

        echo "Vulnerabilidades: $vuln_removed arquivos removidos ($vuln_after mantidos - max 3 dias)" | tee -a "$tolog"
    fi

    # 2. Limpeza dos resultados de testes (/Todos_os_Resultados/)
    # REGRA: 5 dias máximo
    if [ -d "$pathtest" ]; then
        echo "Limpando resultados de testes antigos (>5 dias)..." | tee -a "$tolog"

        # Contar diretórios de teste antes
        test_dirs_before=$(find "$pathtest" -maxdepth 1 -type d -name "*_*_*-*:*" 2>/dev/null | wc -l)

        # Apagar diretórios de teste > 5 dias
        find "$pathtest" -maxdepth 1 -type d -name "*_*_*-*:*" -mtime +5 -exec rm -rf {} + 2>/dev/null

        # Apagar diretórios vazios
        find "$pathtest" -type d -empty -delete 2>/dev/null

        # Contar após limpeza
        test_dirs_after=$(find "$pathtest" -maxdepth 1 -type d -name "*_*_*-*:*" 2>/dev/null | wc -l)
        test_dirs_removed=$((test_dirs_before - test_dirs_after))

        echo "Testes: $test_dirs_removed diretórios removidos ($test_dirs_after mantidos - max 5 dias)" | tee -a "$tolog"
    fi

    # 3. Limpeza dos arquivos zipados (/Historico/)
    # REGRA: 7 dias máximo
    if [ -d "$zipfiles" ]; then
        echo "Limpando arquivos históricos (>7 dias)..." | tee -a "$tolog"

        # Contar zips antes
        zip_before=$(find "$zipfiles" -type f -name "*.zip" 2>/dev/null | wc -l)

        # AGRESSIVO: Apagar zips > 7 dias (não 30!)
        find "$zipfiles" -type f -name "*.zip" -mtime +7 -delete 2>/dev/null

        # Contar após limpeza
        zip_after=$(find "$zipfiles" -type f -name "*.zip" 2>/dev/null | wc -l)
        zip_removed=$((zip_before - zip_after))

        echo "Histórico: $zip_removed arquivos ZIP removidos ($zip_after mantidos - max 7 dias)" | tee -a "$tolog"
    fi

    # 4. Limpeza AGRESSIVA dos arquivos de controle
    echo "Limpeza agressiva de arquivos de controle..." | tee -a "$tolog"

    # Arquivo de IPs testados - manter apenas 500 entradas mais recentes
    if [ -f "$tested_ips_file" ] && [ $(wc -l < "$tested_ips_file") -gt 500 ]; then
        echo "Compactando arquivo de IPs testados para 500 entradas..." | tee -a "$tolog"
        tail -500 "$tested_ips_file" > "${tested_ips_file}.tmp"
        mv "${tested_ips_file}.tmp" "$tested_ips_file"
    fi

    # Arquivo de falhas - manter apenas últimos 3 dias
    if [ -f "$failed_ips_file" ]; then
        failed_before=$(wc -l < "$failed_ips_file" 2>/dev/null || echo "0")

        if [ "$failed_before" -gt 0 ]; then
            local temp_failed
            temp_failed=$(mktemp)
            local cutoff_date
            cutoff_date=$(date -d "3 days ago" "+%d/%m/%y")

            # Filtrar por data (manter apenas >= cutoff_date)
            awk -v cutoff="$cutoff_date" '$1 >= cutoff' "$failed_ips_file" > "$temp_failed" 2>/dev/null || touch "$temp_failed"
            mv "$temp_failed" "$failed_ips_file"

            failed_after=$(wc -l < "$failed_ips_file" 2>/dev/null || echo "0")
            failed_removed=$((failed_before - failed_after))
            echo "Controle: $failed_removed falhas antigas removidas ($failed_after mantidas - max 3 dias)" | tee -a "$tolog"
        fi
    fi

    # Cache de IPs - limpar completamente se > 7 dias
    if [ -f "$cachefile" ]; then
        find "$cachefile" -mtime +7 -delete 2>/dev/null
        echo "Cache de IPs limpo (>7 dias)" | tee -a "$tolog"
    fi

    # 5. Limpeza de logs - manter apenas 2000 linhas
    if [ -f "$tolog" ] && [ $(wc -l < "$tolog") -gt 2000 ]; then
        echo "Compactando log principal para 2000 linhas..." | tee -a "$tolog"
        tail -2000 "$tolog" > "${tolog}.tmp"
        mv "${tolog}.tmp" "$tolog"
    fi

    # 6. Limpeza de arquivos temporários e locks antigos
    echo "Removendo arquivos temporários e locks antigos..." | tee -a "$tolog"
    find /tmp -name "*pandora*" -mtime +1 -delete 2>/dev/null
    find "$pidfile" -name "*.lock" -mtime +1 -delete 2>/dev/null
    find "$pidfile" -name "*.tmp" -mtime +1 -delete 2>/dev/null

    # 7. Estatísticas finais
    echo "=== LIMPEZA AGRESSIVA CONCLUÍDA ===" | tee -a "$tolog"
    echo "Política aplicada: 3 dias (vulns), 5 dias (testes), 7 dias (zips)" | tee -a "$tolog"
    echo "RESUMO files mantidos: $(find "$vuln0" -name "RESUMO_*" 2>/dev/null | wc -l)" | tee -a "$tolog"
    echo "Diretórios de teste mantidos: $(find "$pathtest" -maxdepth 1 -type d -name "*_*_*-*:*" 2>/dev/null | wc -l)" | tee -a "$tolog"
    echo "Arquivos ZIP mantidos: $(find "$zipfiles" -name "*.zip" 2>/dev/null | wc -l)" | tee -a "$tolog"
    echo "Espaço total usado: $(du -sh "$pidfile" 2>/dev/null | cut -f1)" | tee -a "$tolog"
    echo "=================================" | tee -a "$tolog"
}

# Função para verificar espaço em disco
check_disk_space() {
    local available_space
    available_space=$(df "$pidfile" | awk 'NR==2 {print $4}')
    local available_gb
    available_gb=$((available_space / 1024 / 1024))

    echo "Espaço disponível: ${available_gb}GB" | tee -a "$tolog"

    # Se menos de 2GB, fazer limpeza de emergência
    if [ "$available_gb" -lt 2 ]; then
        echo "ALERTA: Pouco espaço em disco! Executando limpeza de emergência..." | tee -a "$tolog"
        emergency_cleanup
    # Se menos de 5GB, fazer limpeza agressiva extra
    elif [ "$available_gb" -lt 5 ]; then
        echo "AVISO: Espaço limitado. Executando limpeza extra..." | tee -a "$tolog"
        find "$vuln0" -type f -mtime +1 -delete 2>/dev/null
        find "$pathtest" -maxdepth 1 -type d -name "*_*_*-*:*" -mtime +3 -exec rm -rf {} + 2>/dev/null
        find "$zipfiles" -type f -name "*.zip" -mtime +3 -delete 2>/dev/null
    fi
}

# Funcao para gerar relatorio de controle
generate_control_report() {
    local report_file="$pathtest/$name/relatorio_controle_ips.txt"

    {
        echo "=== RELATORIO DE CONTROLE DE IPs ==="
        echo "Data: $(date)"
        echo "Dispositivo: $namepan"
        echo "====================================="
        echo ""
    } > "$report_file"

    # Estatisticas gerais
    local total_tested=0
    local total_pending=0
    local total_failed=0

    if [ -f "$tested_ips_file" ]; then
        total_tested=$(wc -l < "$tested_ips_file")
    fi

    if [ -f "$pending_ips_file" ]; then
        total_pending=$(wc -l < "$pending_ips_file")
    fi

    if [ -f "$failed_ips_file" ]; then
        total_failed=$(wc -l < "$failed_ips_file")
    fi

    {
        echo "ESTATISTICAS:"
        echo "IPs testados (total): $total_tested"
        echo "IPs pendentes: $total_pending"
        echo "IPs com falha: $total_failed"
        echo ""
    } >> "$report_file"

    # IPs testados hoje
    if [ -f "$tested_ips_file" ]; then
        local today_pattern
        today_pattern=$(date +"%d/%m/%y")
        local tested_today
        tested_today=$(grep -c "^$today_pattern" "$tested_ips_file")

        {
            echo "IPs testados hoje: $tested_today"
            echo ""
            echo "uLTIMOS 10 IPs TESTADOS:"
        } >> "$report_file"

        tail -10 "$tested_ips_file" >> "$report_file"
        echo "" >> "$report_file"
    fi

    # IPs pendentes
    if [ -f "$pending_ips_file" ] && [ "$total_pending" -gt 0 ]; then
        echo "IPs PENDENTES PARA PRoXIMA EXECUcaO:" >> "$report_file"
        cat "$pending_ips_file" >> "$report_file"
        echo "" >> "$report_file"
    fi

    # IPs com falha para retry
    if [ -f "$failed_ips_file" ] && [ "$total_failed" -gt 0 ]; then
        echo "IPs COM FALHA (PARA RETRY):" >> "$report_file"
        tail -20 "$failed_ips_file" >> "$report_file"
        echo "" >> "$report_file"
    fi

    echo "Relatorio de controle gerado: $report_file" | tee -a "$tolog"
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

        if ! apt-get update && apt-get install -y "${missing_deps[@]}"; then
            echo "Erro ao instalar dependencias! Saindo..." | tee -a "$tolog"
            exit 1
        fi
    fi
}

# Function to adjust parallel jobs based on system load
adjust_parallel_jobs() {
    local current_load
    current_load=$(uptime | awk '{print $10}' | cut -d',' -f1)

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

# Function to perform aggressive black box port scanning
aggressive_black_box_scan() {
    local ip=$1
    local tcp_results="$pathtest/$name/${ip}_tcp_full"
    local udp_results="$pathtest/$name/${ip}_udp_critical"
    local final_results="$pathtest/$name/$ip"

    # Verificar se deve testar este IP
    if ! should_test_ip "$ip"; then
        return 1  # Pular este IP
    fi

    # Get current counter atomically
    local current_counter
    current_counter=$(get_counter)
    local total_ips
    total_ips=$(wc -l < "$toip1")

    echo "[$current_counter/$total_ips] BLACK BOX SCAN: $ip" | tee -a "$tolog"
    update_status "$current_counter" "$total_ips" "0" "$ip"

    # Verificacao avancada de conectividade
    if ! advanced_connectivity_check "$ip"; then
        echo "[$current_counter/$total_ips] IP $ip nao acessivel - marcando como host_down" | tee -a "$tolog"
        mark_ip_as_tested "$ip" "host_down" "no_connectivity"
        {
            echo "Host $ip inacessivel (multiplos testes falharam)"
            echo "Testes realizados: ICMP ping, TCP ping (portas comuns), Nmap discovery"
            echo "Resultado: Host down ou firewalled"
        } > "$final_results"
        return 1
    fi

    echo "[$current_counter/$total_ips] Host $ip acessivel - iniciando scan completo..." | tee -a "$tolog"

    # Phase 1: Full TCP port scan com deteccao melhorada de timeout
    echo "[$current_counter/$total_ips] TCP Full Scan (1-65535) - $ip..." | tee -a "$tolog"

    local tcp_start_time
    tcp_start_time=$(date +%s)

    timeout 900 nmap -Pn -sS -p 1-65535 --min-rate 1000 --max-retries 1 -T2 "$ip" > "$tcp_results" 2>&1
    local tcp_exit_code=$?

    local tcp_end_time
    tcp_end_time=$(date +%s)
    local tcp_duration
    tcp_duration=$((tcp_end_time - tcp_start_time))

    if [ "$tcp_exit_code" -eq 124 ]; then
        echo "[$current_counter/$total_ips] TCP scan timeout apos ${tcp_duration}s para $ip" | tee -a "$tolog"
        mark_ip_as_tested "$ip" "timeout" "tcp_scan_${tcp_duration}s"
        echo "TCP scan timeout apos $tcp_duration segundos" > "$final_results"
        rm -f "$tcp_results" "$udp_results"
        return 1
    elif [ "$tcp_exit_code" -ne 0 ]; then
        echo "[$current_counter/$total_ips] TCP scan erro (exit code: $tcp_exit_code) para $ip" | tee -a "$tolog"
        mark_ip_as_tested "$ip" "network_error" "tcp_error_code_$tcp_exit_code"
        echo "TCP scan error (exit code: $tcp_exit_code)" > "$final_results"
        rm -f "$tcp_results" "$udp_results"
        return 1
    fi

    echo "[$current_counter/$total_ips] TCP scan concluido em ${tcp_duration}s" | tee -a "$tolog"

    # Phase 2: Critical UDP ports
    echo "[$current_counter/$total_ips] UDP Critical Corporate Scan - $ip..." | tee -a "$tolog"

    local udp_start_time
    udp_start_time=$(date +%s)

    timeout 600 nmap -Pn -sU -p "$critical_udp_ports" --min-rate 500 --max-retries 1 -T2 "$ip" > "$udp_results" 2>&1
    local udp_exit_code=$?

    local udp_end_time
    udp_end_time=$(date +%s)
    local udp_duration
    udp_duration=$((udp_end_time - udp_start_time))

    if [ "$udp_exit_code" -eq 124 ]; then
        echo "[$current_counter/$total_ips] UDP scan timeout apos ${udp_duration}s - prosseguindo com TCP" | tee -a "$tolog"
        echo "UDP scan timeout apos $udp_duration segundos - apenas resultados TCP" > "$udp_results"
    else
        echo "[$current_counter/$total_ips] UDP scan concluido em ${udp_duration}s" | tee -a "$tolog"
    fi

    # Check if any ports were found open
    local tcp_open=false
    local udp_open=false
    local open_tcp_ports=""
    local open_udp_ports=""

    if [ -f "$tcp_results" ] && grep -q "open" "$tcp_results"; then
        tcp_open=true
        open_tcp_ports=$(grep "open" "$tcp_results" | grep "tcp" | awk '{print $1}' | cut -d'/' -f1 | grep -E '^[0-9]+$' | sort -n | tr '\n' ',' | sed 's/,$//')
    fi

    if [ -f "$udp_results" ] && grep -q "open" "$udp_results"; then
        udp_open=true
        open_udp_ports=$(grep "open" "$udp_results" | grep "udp" | awk '{print $1}' | cut -d'/' -f1 | grep -E '^[0-9]+$' | sort -n | tr '\n' ',' | sed 's/,$//')
    fi

    if [ "$tcp_open" = true ] || [ "$udp_open" = true ]; then
        echo "[$current_counter/$total_ips] ALVO INTERESSANTE: $ip - Iniciando analise de vulnerabilidades..." | tee -a "$tolog"

        # Initialize final results file
        {
            echo "=== BLACK BOX PENETRATION TEST RESULTS ==="
            echo "Target: $ip"
            echo "Scan Date: $(date)"
            echo "Methodology: Double Blind Black Box"
            echo "TCP Scan Duration: ${tcp_duration}s"
            echo "UDP Scan Duration: ${udp_duration}s"
            echo "============================================="
            echo ""
        } > "$final_results"

        # Phase 3: Detailed vulnerability assessment on open TCP ports
        if [ "$tcp_open" = true ] && [ -n "$open_tcp_ports" ]; then
            echo "[$current_counter/$total_ips] TCP Vulnerability Assessment - $ip (portas: $open_tcp_ports)..." | tee -a "$tolog"

            if echo "$open_tcp_ports" | grep -qE '^[0-9]+(,[0-9]+)*$'; then
                echo "=== TCP VULNERABILITY SCAN RESULTS ===" >> "$final_results"
                timeout 1800 nmap -Pn -sS -sV -sC --script vuln,safe,discovery,auth,brute --script-timeout 300s -T2 -p "$open_tcp_ports" "$ip" >> "$final_results" 2>&1
                echo "" >> "$final_results"
            else
                echo "Formato de portas TCP invalido para $ip: $open_tcp_ports" | tee -a "$tolog"
                echo "Fazendo scan de servicos basicos como fallback..." | tee -a "$tolog"
                echo "=== TCP SERVICE DETECTION (FALLBACK) ===" >> "$final_results"
                timeout 900 nmap -Pn -sS -sV -sC --script safe -T2 "$ip" >> "$final_results" 2>&1
                echo "" >> "$final_results"
            fi
        fi

        # Phase 4: Detailed vulnerability assessment on open UDP ports
        if [ "$udp_open" = true ] && [ -n "$open_udp_ports" ]; then
            echo "[$current_counter/$total_ips] UDP Vulnerability Assessment - $ip (portas: $open_udp_ports)..." | tee -a "$tolog"

            if echo "$open_udp_ports" | grep -qE '^[0-9]+(,[0-9]+)*$'; then
                echo "=== UDP VULNERABILITY SCAN RESULTS ===" >> "$final_results"
                timeout 1200 nmap -Pn -sU -sV -sC --script vuln,safe,discovery --script-timeout 300s -T2 -p "$open_udp_ports" "$ip" >> "$final_results" 2>&1
                echo "" >> "$final_results"
            else
                echo "Formato de portas UDP invalido para $ip: $open_udp_ports" | tee -a "$tolog"
                echo "Fazendo scan UDP limitado como fallback..." | tee -a "$tolog"
                echo "=== UDP SERVICE DETECTION (FALLBACK) ===" >> "$final_results"
                timeout 600 nmap -Pn -sU --script safe -T2 -p "$critical_udp_ports" "$ip" >> "$final_results" 2>&1
                echo "" >> "$final_results"
            fi
        fi

        # Phase 5: Additional reconnaissance for interesting targets
        if [ "$tcp_open" = true ]; then
            echo "[$current_counter/$total_ips] Reconnaissance adicional - $ip..." | tee -a "$tolog"
            echo "=== ADDITIONAL RECONNAISSANCE ===" >> "$final_results"

            # OS Detection com timeout
            timeout 300 nmap -Pn -O --osscan-guess -T2 "$ip" 2>/dev/null | grep -E "(OS|Device|Network Distance)" >> "$final_results" 2>/dev/null || echo "OS Detection: Failed" >> "$final_results"

            # Traceroute for network mapping com timeout
            timeout 300 nmap -Pn --traceroute -T2 "$ip" 2>/dev/null | grep -A 20 "TRACEROUTE" >> "$final_results" 2>/dev/null || echo "Traceroute: Failed" >> "$final_results"

            echo "" >> "$final_results"
        fi

        # Clean up temp files
        rm -f "$tcp_results" "$udp_results"

        # Marcar como testado com sucesso
        mark_ip_as_tested "$ip" "success" "tcp_${tcp_duration}s_udp_${udp_duration}s"
        return 0
    else
        echo "[$current_counter/$total_ips] Host sem servicos expostos: $ip" | tee -a "$tolog"
        {
            echo "No accessible services found on $ip (Black Box Scan)"
            echo "TCP Scan: 1-65535 (No open ports) - Duration: ${tcp_duration}s"
            echo "UDP Scan: Critical 30 ports (No open ports) - Duration: ${udp_duration}s"
        } > "$final_results"
        rm -f "$tcp_results" "$udp_results"

        # Marcar como testado sem servicos
        mark_ip_as_tested "$ip" "no_services" "scanned_successfully"
        return 1
    fi
}

# Funcao para gerar relatorio detalhado de retry
generate_retry_report() {
    local report_file="$pathtest/$name/relatorio_retry_strategy.txt"

    {
        echo "=== RELATORIO DE ESTRATEGIA DE TENTATIVAS ==="
        echo "Data: $(date)"
        echo "Dispositivo: $namepan"
        echo "============================================="
        echo ""
    } > "$report_file"

    # Estatisticas por tipo de falha
    if [ -f "$failed_ips_file" ]; then
        {
            echo "ESTATISTICAS DE FALHAS:"
            echo "Host Down (RETRY_6H): $(grep -c 'RETRY_6H' "$failed_ips_file" 2>/dev/null || echo 0)"
            echo "Network Error (RETRY_12H): $(grep -c 'RETRY_12H' "$failed_ips_file" 2>/dev/null || echo 0)"
            echo "Timeout (RETRY_24H): $(grep -c 'RETRY_24H' "$failed_ips_file" 2>/dev/null || echo 0)"
            echo ""
            echo "PRoXIMOS RETRIES AGENDADOS:"
            echo "==========================="
        } >> "$report_file"

        local current_timestamp
        current_timestamp=$(date +%s)

        while read -r line; do
            if [[ "$line" =~ RETRY_ ]]; then
                local failure_date
                failure_date=$(echo "$line" | awk '{print $1}')
                local failure_time
                failure_time=$(echo "$line" | awk '{print $2}')
                local ip
                ip=$(echo "$line" | awk '{print $3}')
                local retry_type
                retry_type=$(echo "$line" | awk '{print $NF}')

                local failure_timestamp
                failure_timestamp=$(date -d "$failure_date $failure_time" +%s 2>/dev/null)

                if [ -n "$failure_timestamp" ]; then
                    local retry_hours
                    case "$retry_type" in
                        "RETRY_6H") retry_hours=6 ;;
                        "RETRY_12H") retry_hours=12 ;;
                        "RETRY_24H") retry_hours=24 ;;
                        *) retry_hours=24 ;;
                    esac

                    local retry_timestamp
                    retry_timestamp=$((failure_timestamp + retry_hours * 3600))
                    local retry_date
                    retry_date=$(date -d "@$retry_timestamp" '+%d/%m/%y %H:%M')

                    if [ "$retry_timestamp" -gt "$current_timestamp" ]; then
                        echo "$ip - Retry em: $retry_date ($retry_type)" >> "$report_file"
                    else
                        echo "$ip - Pronto para retry agora ($retry_type)" >> "$report_file"
                    fi
                fi
            fi
        done < "$failed_ips_file"
    fi

    echo "" >> "$report_file"
    echo "Relatorio de retry gerado: $report_file" | tee -a "$tolog"
}

check_vulnerabilities() {
    local vuln_found=1  # Default to no vulnerabilities found

    echo "Analisando resultados para vulnerabilidades 2024/2025..." | tee -a "$tolog"

    while read -r line; do
        if [ -f "$pathtest/$name/$line" ]; then

            # FILTRO PRINCIPAL: Apenas CVEs de 2024 e 2025
            local vuln_detected=false
            local vuln_summary=""
            local vuln_details=""

            # 1. CVEs criticos de 2024/2025 APENAS (8.0+)
            local critical_cves_2024_2025
            critical_cves_2024_2025=$(grep -E "CVE-(2024|2025)-[0-9]+.*([89]\.[0-9]|10\.0)" "$pathtest/$name/$line" 2>/dev/null || true)
            if [ -n "$critical_cves_2024_2025" ]; then
                vuln_detected=true
                vuln_summary+="CVEs criticos 2024/2025 detectados (Score 8.0+)\n"
                vuln_details+="CRITICAL CVEs 2024/2025:\n$critical_cves_2024_2025\n\n"
            fi

            # 2. CVEs medios/altos de 2024/2025 (4.0+)
            local medium_cves_2024_2025
            medium_cves_2024_2025=$(grep -E "CVE-(2024|2025)-[0-9]+.*[4-7]\.[0-9]" "$pathtest/$name/$line" 2>/dev/null || true)
            if [ -n "$medium_cves_2024_2025" ]; then
                vuln_detected=true
                vuln_summary+="CVEs medios/altos 2024/2025 detectados (Score 4.0-7.9)\n"
                vuln_details+="MEDIUM/HIGH CVEs 2024/2025:\n$medium_cves_2024_2025\n\n"
            fi

            # 3. Exploits especificos para CVEs 2024/2025
            local exploits_2024_2025
            exploits_2024_2025=$(grep -E "\*EXPLOIT\*.*CVE-(2024|2025)" "$pathtest/$name/$line" 2>/dev/null || true)
            if [ -n "$exploits_2024_2025" ]; then
                vuln_detected=true
                vuln_summary+="Exploits publicos para CVEs 2024/2025\n"
                vuln_details+="EXPLOITS 2024/2025:\n$exploits_2024_2025\n\n"
            fi

            # 4. Vulnerabilidades de configuracao (sempre relevantes)
            local config_vulns
            config_vulns=$(grep -E "(default credentials|weak.*config|anonymous.*access|VULNERABLE.*config)" "$pathtest/$name/$line" 2>/dev/null || true)
            if [ -n "$config_vulns" ]; then
                vuln_detected=true
                vuln_summary+="Problemas de configuracao detectados\n"
                vuln_details+="CONFIG ISSUES:\n$config_vulns\n\n"
            fi

            # 5. Apenas servicos criticos SEM filtro de ano (AD, Kerberos, etc)
            if grep -E "(Active Directory|Domain Controller|Kerberos.*server)" "$pathtest/$name/$line" > /dev/null 2>&1; then
                local critical_services_cves
                critical_services_cves=$(grep -E "CVE-(2024|2025)-[0-9]+" "$pathtest/$name/$line" 2>/dev/null || true)
                if [ -n "$critical_services_cves" ]; then
                    vuln_detected=true
                    vuln_summary+="Servicos criticos com CVEs 2024/2025\n"
                    vuln_details+="CRITICAL SERVICES 2024/2025:\n$critical_services_cves\n\n"
                fi
            fi

            # SE encontrou vulnerabilidades 2024/2025, processar
            if [ "$vuln_detected" = true ]; then
                # Verificar falsos positivos mesmo para CVEs recentes
                local false_positives
                false_positives=$(grep -E "(NOT VULNERABLE|not vulnerable|Not vulnerable|NOT Exploitable|not exploitable|State: NOT VULNERABLE)" "$pathtest/$name/$line" 2>/dev/null || true)

                # Contar vulnerabilidades vs falsos positivos
                local vuln_count
                vuln_count=$(echo "$vuln_details" | grep -c "CVE-" || echo "0")
                local false_positive_count
                false_positive_count=0
                if [ -n "$false_positives" ]; then
                    false_positive_count=$(echo "$false_positives" | wc -l)
                fi

                echo "[$line] CVEs 2024/2025: $vuln_count | Falsos positivos: $false_positive_count" | tee -a "$tolog"

                # So criar alerta se ha mais vulnerabilidades que falsos positivos
                if [ "$vuln_count" -gt "$false_positive_count" ] || [ "$false_positive_count" -eq 0 ]; then
                    mkdir -p "$vuln0"

                    # Copy the full scan result
                    cp "$pathtest/$name/$line" "$vuln0/${line}_scan.txt"

                    # Generate focused summary para CVEs 2024/2025
                    {
                        echo "=== VULNERABILIDADES 2024/2025 DETECTADAS ==="
                        echo "IP: $line"
                        echo "Data: $datetime2"
                        echo "Dispositivo: $namepan"
                        echo "Filtro: Apenas CVEs de 2024 e 2025"
                        echo ""
                        echo "RESUMO DA DETECCAO:"
                        echo "=================="
                    } > "$vuln0/RESUMO_${line}.txt"

                    echo -e "$vuln_summary" >> "$vuln0/RESUMO_${line}.txt"

                    {
                        echo ""
                        echo "DETALHES DAS VULNERABILIDADES 2024/2025:"
                        echo "========================================"
                    } >> "$vuln0/RESUMO_${line}.txt"

                    echo -e "$vuln_details" >> "$vuln0/RESUMO_${line}.txt"

                    # Lista CVEs antigas encontrados (mas ignorados)
                    local old_cves
                    old_cves=$(grep -E "CVE-(201[0-9]|202[0-3])-[0-9]+" "$pathtest/$name/$line" 2>/dev/null | wc -l || echo "0")

                    {
                        echo "NOTA: $old_cves CVEs antigos (2010-2023) foram ignorados por este filtro."
                        echo "Foco: Apenas vulnerabilidades de 2024 e 2025 que podem nao ter patches."
                        echo ""
                    } >> "$vuln0/RESUMO_${line}.txt"

                    # Se ha falsos positivos, mencionar
                    if [ -n "$false_positives" ]; then
                        {
                            echo "FALSOS POSITIVOS DETECTADOS:"
                            echo "============================"
                        } >> "$vuln0/RESUMO_${line}.txt"

                        echo "$false_positives" >> "$vuln0/RESUMO_${line}.txt"
                        echo "" >> "$vuln0/RESUMO_${line}.txt"
                    fi

                    {
                        echo "SCAN COMPLETO (SOMENTE CVEs 2024/2025):"
                        echo "======================================="
                    } >> "$vuln0/RESUMO_${line}.txt"

                    # Filtrar o scan completo para mostrar apenas linhas com CVEs 2024/2025
                    grep -E "(CVE-(2024|2025)|VULNERABLE|exploitable|Target:|Scan Date:)" "$pathtest/$name/$line" >> "$vuln0/RESUMO_${line}.txt" 2>/dev/null || {
                        echo "Nenhuma linha adicional com CVEs 2024/2025 encontrada no scan completo." >> "$vuln0/RESUMO_${line}.txt"
                    }

                    vuln_found=0  # Vulnerabilities found
                    echo "VULNERABILIDADE 2024/2025 DETECTADA em $line!" | tee -a "$tolog"
                    echo "Resumo: $(echo -e "$vuln_summary" | tr '\n' ' ')" | tee -a "$tolog"

                else
                    echo "[$line] CVEs 2024/2025 descartados - muitos falsos positivos" | tee -a "$tolog"
                fi
            else
                echo "[$line] Nenhuma vulnerabilidade 2024/2025 detectada" | tee -a "$tolog"
            fi
        fi
    done < "$toip1"

    return $vuln_found
}

generate_cve_filter_report() {
    local report_file="$pathtest/$name/relatorio_filtro_cves.txt"

    {
        echo "=== RELATORIO DE FILTRO DE CVEs ==="
        echo "Data: $(date)"
        echo "Dispositivo: $namepan"
        echo "Filtro aplicado: CVEs 2024 e 2025 apenas"
        echo "==================================="
        echo ""
    } > "$report_file"

    # Estatisticas de CVEs por ano nos arquivos
    local total_files=0
    local files_with_2024_cves=0
    local files_with_2025_cves=0
    local total_old_cves=0
    local total_new_cves=0

    while read -r line; do
        if [ -f "$pathtest/$name/$line" ]; then
            total_files=$((total_files + 1))

            # Contar CVEs 2024
            local cves_2024
            cves_2024=$(grep -c "CVE-2024-" "$pathtest/$name/$line" 2>/dev/null || echo "0")
            if [ "$cves_2024" -gt 0 ]; then
                files_with_2024_cves=$((files_with_2024_cves + 1))
                total_new_cves=$((total_new_cves + cves_2024))
            fi

            # Contar CVEs 2025
            local cves_2025
            cves_2025=$(grep -c "CVE-2025-" "$pathtest/$name/$line" 2>/dev/null || echo "0")
            if [ "$cves_2025" -gt 0 ]; then
                files_with_2025_cves=$((files_with_2025_cves + 1))
                total_new_cves=$((total_new_cves + cves_2025))
            fi

            # Contar CVEs antigos (ignorados)
            local old_cves
            old_cves=$(grep -c "CVE-\(201[0-9]\|202[0-3]\)-" "$pathtest/$name/$line" 2>/dev/null || echo "0")
            total_old_cves=$((total_old_cves + old_cves))
        fi
    done < "$toip1"

    {
        echo "ESTATISTICAS DO FILTRO:"
        echo "======================"
        echo "Total de arquivos analisados: $total_files"
        echo "Arquivos com CVEs 2024: $files_with_2024_cves"
        echo "Arquivos com CVEs 2025: $files_with_2025_cves"
        echo "Total CVEs 2024/2025 (analisados): $total_new_cves"
        echo "Total CVEs antigos (ignorados): $total_old_cves"
        echo "Eficiencia do filtro: $(( total_old_cves * 100 / (total_old_cves + total_new_cves) ))% de ruido removido"
        echo ""

        echo "JUSTIFICATIVA DO FILTRO:"
        echo "======================="
        echo "• CVEs 2010-2023: Provavelmente ja patchados em sistemas atualizados"
        echo "• CVEs 2024/2025: Podem nao ter patches ainda, requerem atencao"
        echo "• Foco em relevancia temporal e probabilidade real de exploracao"
        echo ""
    } >> "$report_file"

    echo "Relatorio de filtro CVE gerado: $report_file" | tee -a "$tolog"
}

# Funcao adicional para limpar mensagens do log principal (opcional)
update_log_messages() {
    # Substituir mensagens com acentuacao no log
    sed -i 's/Analisando/Analisando/g' "$tolog" 2>/dev/null || true
    sed -i 's/configuração/configuracao/g' "$tolog" 2>/dev/null || true
    sed -i 's/vulnerabilidade/vulnerabilidade/g' "$tolog" 2>/dev/null || true
    sed -i 's/críticos/criticos/g' "$tolog" 2>/dev/null || true
    sed -i 's/públicos/publicos/g' "$tolog" 2>/dev/null || true
}

# Funcao para atualizar mensagens do init (linha ~407)
init_log_messages_without_accents() {
    echo "BLACK BOX PENTEST INICIADO em $datetime!" | tee -a "$tolog"
    echo "Dispositivo: $namepan" | tee -a "$tolog"
    echo "Metodologia: Double Blind Black Box" | tee -a "$tolog"
    echo "Filtro CVE: Apenas 2024 e 2025" | tee -a "$tolog"
    echo "TCP Scope: Full scan 1-65535" | tee -a "$tolog"
    echo "UDP Scope: Top 30 portas criticas corporativas" | tee -a "$tolog"
}

# Funcao para finalizar com mensagens sem acentuacao
final_log_messages_without_accents() {
    datetime2=$(date +"%d/%m/%y %H:%M")
    echo "BLACK BOX PENTEST CONCLUIDO: $datetime ate $datetime2." | tee -a "$tolog"
    echo "Analisando resultados para vulnerabilidades 2024/2025..." | tee -a "$tolog"
    echo "Resultados completos em: $pathtest/$name" | tee -a "$tolog"
    echo "Compactando resultados do Black Box..." | tee -a "$tolog"
    echo "Limpando arquivos antigos..." | tee -a "$tolog"
    echo "BLACK BOX PENETRATION TEST FINALIZADO!" | tee -a "$tolog"
    echo "Relatorio HTML disponivel via web interface" | tee -a "$tolog"
    echo "Metodologia: Double Blind Black Box Complete" | tee -a "$tolog"
    echo "Cobertura: TCP 1-65535 + UDP Top 30 Critical" | tee -a "$tolog"
}

manage_ip_cache() {
    # Create cache directory if it doesn't exist
    mkdir -p "$(dirname "$cachefile")"

    echo "Gerenciando controle de IPs testados..." | tee -a "$tolog"

    # Limpar arquivos de controle antigos (7 dias)
    cleanup_old_control_files 7

    # SEMPRE re-avaliar IPs com base na regra de 48h
    echo "Re-avaliando todos os IPs com base na regra de 48h..." | tee -a "$tolog"
    
    # Filtrar IPs que NaO foram testados nas ultimas 48h
    local filtered_file="$toip1.filtered"
    > "$filtered_file"

    local total_ips=0
    local recently_tested=0
    local eligible_for_test=0

    while read -r ip; do
        total_ips=$((total_ips + 1))
        
        # Verificar se foi testado nas ultimas 48h
        if is_ip_recently_tested "$ip" 48; then
            recently_tested=$((recently_tested + 1))
            
            # Verificar o resultado do ultimo teste
            local last_result=""
            if [ -f "$tested_ips_file" ]; then
                last_result=$(grep " $ip " "$tested_ips_file" | tail -1 | awk '{print $3}')
            fi
            
            echo "IP $ip testado nas ultimas 48h (resultado: $last_result) - IGNORANDO" | tee -a "$tolog"
        else
            # IP elegivel para teste
            eligible_for_test=$((eligible_for_test + 1))
            echo "$ip" >> "$filtered_file"
            echo "IP $ip elegivel para teste (nao testado nas ultimas 48h)" | tee -a "$tolog"
        fi
    done < "$toip1"

    # Atualizar arquivo de IPs pendentes com base na filtragem atual
    if [ -s "$filtered_file" ]; then
        cp "$filtered_file" "$pending_ips_file"
        echo "Arquivo de IPs pendentes atualizado com $eligible_for_test IPs" | tee -a "$tolog"
    else
        > "$pending_ips_file"
        echo "Nenhum IP pendente - todos foram testados nas ultimas 48h" | tee -a "$tolog"
    fi

    # Aplicar filtro de cache antigo tambem (para compatibilidade com sistema legado)
    if [ -f "$cachefile" ]; then
        find "$cachefile" -mtime +2 -delete 2>/dev/null

        if [ -f "$cachefile" ]; then
            local temp_filtered
            temp_filtered=$(mktemp)
            grep -v -F -x -f "$cachefile" "$filtered_file" > "$temp_filtered" 2>/dev/null || cp "$filtered_file" "$temp_filtered"
            
            # So aplicar cache legado se nao reduzir muito a lista (evitar conflitos)
            local cache_filtered_count
            cache_filtered_count=$(wc -l < "$temp_filtered")
            
            if [ "$cache_filtered_count" -gt 0 ]; then
                mv "$temp_filtered" "$filtered_file"
                echo "Cache legado aplicado - $cache_filtered_count IPs restantes apos cache" | tee -a "$tolog"
            else
                rm -f "$temp_filtered"
                echo "Cache legado ignorado - todos os IPs ja foram filtrados pela regra de 48h" | tee -a "$tolog"
            fi
        fi
    fi

    # Mostrar estatisticas detalhadas
    local final_count
    final_count=$(wc -l < "$filtered_file")

    echo "=== ESTATiSTICAS DE CONTROLE DE IPs ===" | tee -a "$tolog"
    echo "Total de IPs descobertos: $total_ips" | tee -a "$tolog"
    echo "IPs testados nas ultimas 48h: $recently_tested" | tee -a "$tolog"
    echo "IPs elegiveis para teste: $final_count" | tee -a "$tolog"
    echo "=========================================" | tee -a "$tolog"

    # Substituir lista original pela filtrada
    mv "$filtered_file" "$toip1"

    # Adicionar IPs atuais ao cache legado (manter compatibilidade)
    if [ -s "$toip1" ]; then
        cat "$toip1" >> "$cachefile"
        sort -u "$cachefile" -o "$cachefile" 2>/dev/null
    fi

    # Se nenhum IP para testar, informar
    if [ "$final_count" -eq 0 ]; then
        echo "AVISO: Nenhum IP para testar - todos foram testados nas ultimas 48h" | tee -a "$tolog"
        echo "Proxima execucao recomendada: apos 48h do ultimo teste" | tee -a "$tolog"
    fi
}

# Funcao para limpar IPs pendentes baseado na regra de 48h - NOVA
cleanup_pending_ips() {
    echo "Limpando IPs pendentes baseado na regra de 48h..." | tee -a "$tolog"
    
    if [ ! -f "$pending_ips_file" ]; then
        echo "Arquivo de IPs pendentes nao encontrado - nada para limpar" | tee -a "$tolog"
        return 0
    fi

    local temp_pending
    temp_pending=$(mktemp)
    local cleaned_count=0
    local kept_count=0

    # Verificar cada IP pendente
    while read -r ip; do
        if [ -n "$ip" ]; then
            if is_ip_recently_tested "$ip" 48; then
                # IP foi testado nas ultimas 48h - remover dos pendentes
                cleaned_count=$((cleaned_count + 1))
                echo "Removendo IP $ip dos pendentes (testado nas ultimas 48h)" | tee -a "$tolog"
            else
                # IP ainda e valido para teste - manter
                echo "$ip" >> "$temp_pending"
                kept_count=$((kept_count + 1))
            fi
        fi
    done < "$pending_ips_file"

    # Substituir arquivo de pendentes
    mv "$temp_pending" "$pending_ips_file"
    
    echo "Limpeza de IPs pendentes concluida:" | tee -a "$tolog"
    echo "- IPs removidos (testados < 48h): $cleaned_count" | tee -a "$tolog"
    echo "- IPs mantidos (elegiveis): $kept_count" | tee -a "$tolog"
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
    local network_range
    network_range=$(hostname -I | awk '{print $1}')
    nmap -n -sn --min-rate 2000 "${network_range}/24" | grep "Nmap scan report" | awk '{print $5}' | tee "$toip"

    # Remove Blacklist IPs
    grep -v -F -x -f "/Data/blacklist" "$toip" | tee "$toip1"

    # Limpar IPs pendentes primeiro (baseado na regra de 48h)
    cleanup_pending_ips

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
    echo "Target Network: ${network_range}/24" | tee -a "$tolog"
    echo "Critical UDP Ports: $critical_udp_ports" | tee -a "$tolog"

    # Export functions and variables for parallel execution
    export -f aggressive_black_box_scan get_counter update_status should_test_ip advanced_connectivity_check mark_ip_as_tested is_ip_recently_tested
    export pathtest name tolog total_ips critical_udp_ports counterfile statusfile toip1 tested_ips_file pending_ips_file failed_ips_file control_lock_file

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
    echo "Analisando resultados para vulnerabilidades suspeitas..." | tee -a "$tolog"
    check_vulnerabilities
    generate_cve_filter_report

    vuln_result=$?

    sleep 1

    # Generate control and retry reports
    generate_control_report
    generate_retry_report

    # Register some logs
    echo "Resultados completos em: $pathtest/$name" | tee -a "$tolog"

    sleep 1

    # Zip files!
    echo "Compactando resultados do Black Box..." | tee -a "$tolog"
    zip -r "$zipfiles/$name.zip" "$pathtest/$name" >> "$tolog" 2>&1

    sleep 1

    # Change permissions
    chmod 777 -R "$pidfile"

    # Remove old Files with better cleanup
    check_disk_space
    cleanup_old_files

    # Send message with attachments
    sleep 1
    tontfy=$(cat /Data/ntfysh)

    if [ "$tontfy" != "0" ]; then
        if [ "$vuln_result" -eq 0 ]; then
            echo "ALERTA: Enviando notificacao de vulnerabilidades suspeitas..." | tee -a "$tolog"
            curl -u admin:5V06auso -T "$zipfiles"/"$name".zip -H "Filename: $name.zip" -H "Title: POSSiVEIS VULNERABILIDADES - BLACK BOX - $namepan" -H "Priority: urgent" "$ntfysh"/"$namepan"
        else
            echo "Enviando notificacao - Black Box scan concluido." | tee -a "$tolog"
            curl -u admin:5V06auso -d "Black Box Pentest concluido em $namepan. $lres IPs testados. TCP: 1-65535, UDP: Top 30 criticas. Nenhuma possivel vulnerabilidade detectada." -H "Title: Black Box Scan Concluido - $namepan" "$ntfysh"/"$namepan"
        fi
    fi

    echo "BLACK BOX PENETRATION TEST FINALIZADO!" | tee -a "$tolog"
    echo "Relatorio HTML disponivel via web interface" | tee -a "$tolog"
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
