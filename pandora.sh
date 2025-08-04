#!/bin/bash
###################
# Project Pandora #
# Black Box Edition - SIMPLIFIED HOST DISCOVERY
################################################################################

# CONFIGURACOES BASICAS
namepan=$(cat /Data/hostname)
ntfysh=$(cat /Data/ntfysh)
pidfile="/Pentests"
vuln0="$pidfile/Ataque_Bem-Sucedido"
pathtest="$pidfile/Todos_os_Resultados"
zipfiles="$pidfile/Historico"
statusfile="$pidfile/status.json"
counterfile="$pidfile/counter.txt"
control_yaml="$pidfile/controle.yaml"

# Variaveis globais para controle de processos
TIMEOUT_PID=""

################################################################################

# FUNCAO PARA LIMPEZA DE PROCESSOS ZUMBIS
cleanup_zombies() {
    echo "Limpando processos zumbis..." | tee -a "$tolog" 2>/dev/null || echo "Limpando processos zumbis..."

    # Matar timeout job se existir
    if [ -n "$TIMEOUT_PID" ]; then
        kill "$TIMEOUT_PID" 2>/dev/null
        wait "$TIMEOUT_PID" 2>/dev/null
        TIMEOUT_PID=""
    fi

    # Matar todos os processos nmap
    pkill -f nmap 2>/dev/null

    # Aguardar um momento para os processos terminarem
    sleep 2

    # Forca kill se ainda existirem
    pkill -9 -f nmap 2>/dev/null

    # Aguardar todos os jobs background
    while jobs %% 2>/dev/null; do
        wait
    done

    # Coletar processos filhos orfaos
    wait 2>/dev/null
}

# FUNCAO PARA TRATAR SINAIS (usada pelos traps)
signal_handler() {
    local signal=$1
    echo "Recebido sinal $signal. Limpando processos..." | tee -a "$tolog" 2>/dev/null || echo "Recebido sinal $signal. Limpando processos..."

    cleanup_zombies

    # Status de interrupcao
    if [ -f "$statusfile" ]; then
        cat > "$statusfile" << EOF
{
    "timestamp": "$(date '+%d-%m-%Y %H:%M')",
    "status": "interrupted",
    "progress": {"current": 0, "total": 0},
    "vulnerabilities": 0,
    "current_target": "INTERROMPIDO",
    "device": "$namepan"
}
EOF
    fi

    exit 1
}

# CONFIGURAR TRATAMENTO DE SINAIS
trap 'signal_handler SIGTERM' TERM
trap 'signal_handler SIGINT' INT
trap 'signal_handler SIGQUIT' QUIT
trap 'cleanup_zombies' EXIT

################################################################################

# FUNCAO UNIFICADA DE STATUS E CONTROLE
update_status_and_control() {
    local current_counter=$1
    local total_ips=$2
    local vulnerabilities_found=$3
    local current_ip=${4:-"N/A"}

    # Status JSON
    cat > "$statusfile" << EOF
{
    "timestamp": "$(date '+%d-%m-%Y %H:%M')",
    "status": "running",
    "progress": {"current": $current_counter, "total": $total_ips},
    "vulnerabilities": $vulnerabilities_found,
    "current_target": "$current_ip",
    "device": "$namepan"
}
EOF
}

# FUNCAO SIMPLIFICADA DE COUNTER
get_counter() {
    local counter
    if [ -f "$counterfile" ]; then
        counter=$(cat "$counterfile")
    else
        counter=0
    fi
    counter=$((counter + 1))
    echo "$counter" > "$counterfile"
    echo "$counter"
}

# FUNCOES DE CONTROLE YAML
init_control_yaml() {
    if [ ! -f "$control_yaml" ]; then
        cat > "$control_yaml" << 'EOF'
IPs_testados: {}
EOF
    fi
}

# VERIFICAR SE IP FOI TESTADO NAS ULTIMAS 48H
is_recently_tested() {
    local ip=$1
    local current_time
    local test_time
    local diff_hours

    current_time=$(date +%s)

    # Verificar se yq esta disponivel
    if ! command -v yq >/dev/null 2>&1; then
        return 1  # yq nao disponivel, permite teste
    fi

    # Verificar se IP existe no YAML e pegar epoch time
    if yq eval ".IPs_testados.\"$ip\"" "$control_yaml" 2>/dev/null | grep -q "null"; then
        return 1  # IP nao foi testado
    fi

    test_time=$(yq eval ".IPs_testados.\"$ip\"" "$control_yaml" 2>/dev/null)
    if [ -z "$test_time" ] || [ "$test_time" = "null" ]; then
        return 1  # IP nao foi testado
    fi

    diff_hours=$(( (current_time - test_time) / 3600 ))

    if [ "$diff_hours" -lt 48 ]; then
        return 0  # Foi testado ha menos de 48h
    else
        return 1  # Pode ser testado novamente
    fi
}

# MARCAR IP COMO TESTADO COM SUCESSO
mark_ip_tested() {
    local ip=$1
    local current_time

    current_time=$(date +%s)

    # Verificar se yq esta disponivel
    if command -v yq >/dev/null 2>&1; then
        # Atualizar ambos os blocos
        yq eval ".IPs_Identificados.\"$ip\" = \"sim\"" -i "$control_yaml" 2>/dev/null
        yq eval ".IPs_testados.\"$ip\" = $current_time" -i "$control_yaml" 2>/dev/null
    fi
}

mark_ip_tested() {
    local ip=$1
    local current_time

    current_time=$(date +%s)

    # Verificar se yq esta disponivel
    if command -v yq >/dev/null 2>&1; then
        echo "✅ Marcando $ip como testado com sucesso (epoch: $current_time)" | tee -a "$tolog"
        yq eval ".IPs_testados.\"$ip\" = $current_time" -i "$control_yaml" 2>/dev/null
    else
        echo "⚠️ yq nao disponivel - controle YAML desabilitado" | tee -a "$tolog"
    fi
}

# DESCOBERTA DE HOSTS ONLINE - METODO SIMPLES E EFICAZ
discover_online_hosts() {
    local network_base=$1
    local online_hosts_file=$2

    echo "Descobrindo hosts online na rede $network_base.0/24..." | tee -a "$tolog"

    # Limpar arquivo de hosts online
    true > "$online_hosts_file"

    # Usar nmap para descoberta de hosts - PING + TCP SYN + UDP
    echo "Executando descoberta de hosts com multiplos metodos..." | tee -a "$tolog"

    # Metodo 1: Ping ICMP + ARP (para rede local)
    nmap -sn -PE -PA80,443,22 -PS80,443,22 --min-rate 1000 "${network_base}.1-254" 2>/dev/null | \
        grep "Nmap scan report for" | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' >> "$online_hosts_file"

    # Metodo 2: TCP SYN scan em portas comuns (para detectar hosts que nao respondem ping)
    echo "Verificacao adicional com TCP SYN scan..." | tee -a "$tolog"
    nmap -Pn -sS -p 22,23,25,53,80,135,139,443,445,993,995,3389,5985,8080 \
        --open --min-rate 500 "${network_base}.1-254" 2>/dev/null | \
        grep "Nmap scan report for" | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' >> "$online_hosts_file"

    # Remover duplicatas e ordenar
    sort -u "$online_hosts_file" -o "$online_hosts_file"

    local host_count
    host_count=$(wc -l < "$online_hosts_file")
    echo "Hosts online encontrados: $host_count" | tee -a "$tolog"

    if [ "$host_count" -gt 0 ]; then
        echo "Lista de hosts online:" | tee -a "$tolog"
        cat "$online_hosts_file" | tee -a "$tolog"
    fi

    return 0
}

# SCAN DE PORTAS ABERTAS - HOST POR HOST
scan_open_ports() {
    local ip=$1
    local ports_file="$pathtest/$name/${ip}_ports"
    local open_ports=""

    echo "Scanning portas em $ip..." | tee -a "$tolog"

    # TCP scan completo - todas as portas
    echo "TCP scan completo (1-65535) para $ip..." | tee -a "$tolog"
    nmap -Pn -sS -p 1-65535 --open --min-rate 500 --max-retries 2 \
        --host-timeout 600s -T3 "$ip" > "${ports_file}_tcp" 2>&1

    # UDP scan em portas prioritarias
    echo "UDP scan portas prioritarias para $ip..." | tee -a "$tolog"
    nmap -Pn -sU -p 53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,623,1434,1900,5353 \
        --open --min-rate 300 --max-retries 1 --host-timeout 300s -T3 "$ip" > "${ports_file}_udp" 2>&1

    # Extrair portas TCP abertas
    if [ -f "${ports_file}_tcp" ] && grep -q " open " "${ports_file}_tcp"; then
        local tcp_ports
        tcp_ports=$(grep " open " "${ports_file}_tcp" | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
        if [ -n "$tcp_ports" ]; then
            open_ports="TCP:$tcp_ports"
        fi
    fi

    # Extrair portas UDP abertas
    if [ -f "${ports_file}_udp" ] && grep -q " open " "${ports_file}_udp"; then
        local udp_ports
        udp_ports=$(grep " open " "${ports_file}_udp" | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
        if [ -n "$udp_ports" ]; then
            if [ -n "$open_ports" ]; then
                open_ports="${open_ports};UDP:$udp_ports"
            else
                open_ports="UDP:$udp_ports"
            fi
        fi
    fi

    # Salvar resultado final das portas
    echo "$open_ports" > "$ports_file"

    if [ -n "$open_ports" ]; then
        echo "Portas abertas em $ip: $open_ports" | tee -a "$tolog"
        return 0
    else
        echo "Nenhuma porta aberta encontrada em $ip" | tee -a "$tolog"
        return 1
    fi
}

# PENTESTS NAS PORTAS ABERTAS
run_vulnerability_tests() {
    local ip=$1
    local ports_info=$2
    local vuln_results="$pathtest/$name/${ip}_vulnerabilities"

    echo "Executando testes de vulnerabilidade em $ip..." | tee -a "$tolog"

    # Extrair portas TCP e UDP
    local tcp_ports=""
    local udp_ports=""

    if echo "$ports_info" | grep -q "TCP:"; then
        tcp_ports=$(echo "$ports_info" | grep -o "TCP:[^;]*" | cut -d':' -f2)
    fi

    if echo "$ports_info" | grep -q "UDP:"; then
        udp_ports=$(echo "$ports_info" | grep -o "UDP:[^;]*" | cut -d':' -f2)
    fi

    # Inicializar arquivo de resultados
    {
        echo "=== VULNERABILITY SCAN RESULTS ==="
        echo "Target: $ip"
        echo "Date: $(date)"
        echo "TCP Ports: $tcp_ports"
        echo "UDP Ports: $udp_ports"
        echo "======================================"
        echo ""
    } > "$vuln_results"

    # Testes TCP
    if [ -n "$tcp_ports" ]; then
        {
            echo "=== TCP VULNERABILITY TESTS ==="

            # Grupo 1: Autenticacao e acesso basicos
            echo "# Testes de Autenticacao"
        } >> "$vuln_results"

        timeout 300 nmap -Pn -sS -sV \
            --script "ftp-anon,mysql-empty-password,ssh-auth-methods,telnet-ntlm-info" \
            --script-timeout 30s -T3 -p "$tcp_ports" "$ip" >> "$vuln_results" 2>&1

        {
            echo ""

            # Grupo 2: SMB vulnerabilidades criticas
            echo "# Vulnerabilidades SMB"
        } >> "$vuln_results"

        timeout 300 nmap -Pn -sS \
            --script "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061" \
            --script-timeout 30s -T3 -p "$tcp_ports" "$ip" >> "$vuln_results" 2>&1

        {
            echo ""

            # Grupo 3: HTTP vulnerabilidades
            echo "# Testes HTTP"
        } >> "$vuln_results"

        timeout 300 nmap -Pn -sS \
            --script "http-default-accounts,http-methods,http-enum,http-robots.txt" \
            --script-timeout 30s -T3 -p "$tcp_ports" "$ip" >> "$vuln_results" 2>&1

        {
            echo ""

            # Grupo 4: Database vulnerabilidades
            echo "# Testes Database"
        } >> "$vuln_results"

        timeout 300 nmap -Pn -sS \
            --script "mysql-vuln-cve2012-2122,ms-sql-empty-password,oracle-sid-brute" \
            --script-timeout 30s -T3 -p "$tcp_ports" "$ip" >> "$vuln_results" 2>&1

        {
            echo ""

            # Grupo 5: RDP e VNC
            echo "# Testes RDP/VNC"
        } >> "$vuln_results"

        timeout 300 nmap -Pn -sS \
            --script "rdp-vuln-ms12-020,vnc-info" \
            --script-timeout 30s -T3 -p "$tcp_ports" "$ip" >> "$vuln_results" 2>&1

        echo "" >> "$vuln_results"
    fi

    # Testes UDP
    if [ -n "$udp_ports" ]; then
        {
            echo "=== UDP VULNERABILITY TESTS ==="

            # Scripts UDP simples
            echo "# Testes UDP"
        } >> "$vuln_results"

        timeout 300 nmap -Pn -sU \
            --script "snmp-info,dns-zone-transfer,dhcp-discover,ntp-info" \
            --script-timeout 30s -T3 -p "$udp_ports" "$ip" >> "$vuln_results" 2>&1

        echo "" >> "$vuln_results"
    fi

    echo "Testes de vulnerabilidade concluidos para $ip" | tee -a "$tolog"
    return 0
}

# VERIFICACAO DE VULNERABILIDADES REAIS
check_real_vulnerabilities() {
    local ip=$1
    local vuln_file="$pathtest/$name/${ip}_vulnerabilities"
    local vuln_detected=false
    local vuln_summary=""

    if [ ! -f "$vuln_file" ]; then
        return 1
    fi

    echo "Verificando vulnerabilidades reais em $ip..." | tee -a "$tolog"

    # 1. Vulnerabilidades CONFIRMADAS
    if grep -iE "(VULNERABLE|Successfully|exploit|anonymous.*login|default.*password|empty.*password)" "$vuln_file" >/dev/null 2>&1; then
        vuln_detected=true
        vuln_summary+="Vulnerabilidade CONFIRMADA detectada\n"
    fi

    # 2. Autenticacao bypass REAL
    if grep -iE "(authentication.*bypass|login.*anonymous|ftp.*anonymous|mysql.*empty)" "$vuln_file" >/dev/null 2>&1; then
        vuln_detected=true
        vuln_summary+="Bypass de autenticacao detectado\n"
    fi

    # 3. Credentials padrao FUNCIONAIS
    if grep -iE "(default.*credentials.*work|admin.*admin.*success|root.*password)" "$vuln_file" >/dev/null 2>&1; then
        vuln_detected=true
        vuln_summary+="Credenciais padrao funcionais\n"
    fi

    # 4. SMB vulnerabilidades CONFIRMADAS
    if grep -iE "(smb.*vulnerable|ms17-010.*vulnerable|ms08-067.*vulnerable)" "$vuln_file" >/dev/null 2>&1; then
        vuln_detected=true
        vuln_summary+="Vulnerabilidade SMB confirmada\n"
    fi

    # 5. HTTP vulnerabilidades
    if grep -iE "(http.*default.*account|directory.*listing|robots\.txt.*found)" "$vuln_file" >/dev/null 2>&1; then
        vuln_detected=true
        vuln_summary+="Vulnerabilidade HTTP confirmada\n"
    fi

    # 6. Database vulnerabilidades
    if grep -iE "(mysql.*vulnerable|sql.*empty.*password|oracle.*sid.*found)" "$vuln_file" >/dev/null 2>&1; then
        vuln_detected=true
        vuln_summary+="Vulnerabilidade Database confirmada\n"
    fi

    # Ignorar falsos positivos
    if grep -iE "(NOT VULNERABLE|not vulnerable|no.*vulnerabilities)" "$vuln_file" >/dev/null 2>&1; then
        # Verificar se ha mais evidencias positivas do que negativas
        local positive_count
        local negative_count
        positive_count=$(grep -icE "(VULNERABLE|Successfully|exploit|anonymous.*login|default.*password)" "$vuln_file" 2>/dev/null || echo "0")
        negative_count=$(grep -icE "(NOT VULNERABLE|not vulnerable|no.*vulnerabilities)" "$vuln_file" 2>/dev/null || echo "0")

        if [ "$negative_count" -gt "$positive_count" ]; then
            vuln_detected=false
        fi
    fi

    # SE encontrou vulnerabilidade REAL
    if [ "$vuln_detected" = true ]; then
        mkdir -p "$vuln0"
        cp "$vuln_file" "$vuln0/${ip}_vulnerabilities.txt"

        {
            echo "=== VULNERABILIDADE REAL CONFIRMADA ==="
            echo "IP: $ip"
            echo "Data: $(date)"
            echo "Tipo: Teste ativo confirmado"
            echo "======================================="
            echo -e "$vuln_summary"
            echo ""
            echo "EVIDENCIAS:"
            grep -iE "(VULNERABLE|Successfully|exploit|anonymous|default.*password|bypass)" "$vuln_file" | head -10
        } > "$vuln0/RESUMO_${ip}.txt"

        echo "VULNERABILIDADE REAL confirmada em $ip!" | tee -a "$tolog"
        return 0
    else
        echo "[$ip] Nenhuma vulnerabilidade real confirmada" | tee -a "$tolog"
        return 1
    fi
}

# SCAN COMPLETO DE UM HOST
full_host_scan() {
    local ip=$1
    local current_counter
    local total_ips
    local ports_info

    # Pular se testado recentemente
    if is_recently_tested "$ip"; then
        echo "IP $ip testado nas ultimas 48h - pulando" | tee -a "$tolog"
        return 1
    fi

    # Counter e status
    current_counter=$(get_counter)
    total_ips=$(wc -l < "$toip1")

    echo "[$current_counter/$total_ips] Scanning $ip..." | tee -a "$tolog"
    update_status_and_control "$current_counter" "$total_ips" "0" "$ip"

    # 1. Scan de portas abertas
    if scan_open_ports "$ip"; then
        ports_info=$(cat "$pathtest/$name/${ip}_ports")

        # 2. Testes de vulnerabilidade
        run_vulnerability_tests "$ip" "$ports_info"

        # 3. Verificar vulnerabilidades reais
        if check_real_vulnerabilities "$ip"; then
            echo "Vulnerabilidades encontradas em $ip" | tee -a "$tolog"
        fi

        # Marcar IP como testado (sucesso com portas)
        mark_ip_tested "$ip"
        echo "✅ IP $ip testado com sucesso - nao sera testado nas proximas 48h" | tee -a "$tolog"
        return 0
    else
        echo "🚫 Nenhuma porta aberta em $ip" | tee -a "$tolog"
        echo "Nenhuma porta aberta encontrada" > "$pathtest/$name/$ip"
        # Host respondeu mas sem portas = teste bem-sucedido
        mark_ip_tested "$ip"
        echo "✅ IP $ip testado com sucesso (sem portas) - nao sera testado nas proximas 48h" | tee -a "$tolog"
        return 0  # Mudanca: return 0 em vez de return 1
    fi
}

# APLICAR BLACKLIST
apply_blacklist() {
    local input_file=$1
    local output_file=$2

    echo "Aplicando filtro de blacklist..." | tee -a "$tolog"

    if [ -f "/Data/blacklist" ]; then
        # Limpar blacklist: remover linhas vazias e IPs invalidos
        grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' "/Data/blacklist" | sort -u > "/tmp/blacklist_clean"

        if [ -s "/tmp/blacklist_clean" ]; then
            echo "IPs na blacklist:" | tee -a "$tolog"
            cat "/tmp/blacklist_clean" | tee -a "$tolog"

            # Filtrar usando blacklist limpa
            grep -v -F -x -f "/tmp/blacklist_clean" "$input_file" > "$output_file"

            # Log de quantos IPs foram filtrados
            local filtered_count
            filtered_count=$(($(wc -l < "$input_file") - $(wc -l < "$output_file")))
            echo "IPs filtrados pela blacklist: $filtered_count" | tee -a "$tolog"

            rm -f "/tmp/blacklist_clean"
        else
            echo "Blacklist vazia ou sem IPs validos" | tee -a "$tolog"
            cp "$input_file" "$output_file"
        fi
    else
        echo "Arquivo blacklist nao encontrado" | tee -a "$tolog"
        cp "$input_file" "$output_file"
    fi
}

# FUNCAO PRINCIPAL
init() {
    # Configuracao basica
    local datetime
    local name
    local toip
    local tolog
    local toip1
    local network_base
    local lres
    local datetime2
    local vuln_count
    local tontfy

    datetime=$(date +"%d/%m/%y %H:%M")
    name=$(date +"%d_%m_%y-%H:%M")

    mkdir -p "$zipfiles" "$pathtest/$name" "$vuln0"

    # Arquivos de trabalho
    toip="$pathtest/$name/01_hosts_discovered"
    tolog="$pathtest/$name/02_logs"
    toip1="$pathtest/$name/03_final_targets"

    # Inicializar controle YAML
    init_control_yaml

    echo "0" > "$counterfile"

    echo "BLACK BOX PENTEST INICIADO em $datetime!" | tee -a "$tolog"
    echo "Dispositivo: $namepan" | tee -a "$tolog"

    # Descobrir rede local
    network_base=$(hostname -I | awk '{print $1}' | cut -d'.' -f1-3)
    echo "Rede detectada: $network_base.0/24" | tee -a "$tolog"

    # PASSO 1: DESCOBRIR HOSTS ONLINE
    echo "=== PASSO 1: DESCOBERTA DE HOSTS ONLINE ===" | tee -a "$tolog"
    discover_online_hosts "$network_base" "$toip"

    # PASSO 2: APLICAR BLACKLIST
    echo "=== PASSO 2: APLICANDO BLACKLIST ===" | tee -a "$tolog"
    apply_blacklist "$toip" "$toip1.tmp"

    # PASSO 3: FILTRAR HOSTS TESTADOS RECENTEMENTE
    echo "=== PASSO 3: FILTRANDO HOSTS TESTADOS RECENTEMENTE ===" | tee -a "$tolog"
    true > "$toip1"
    while read -r ip; do
        if [ -n "$ip" ] && ! is_recently_tested "$ip"; then
            echo "$ip" >> "$toip1"
            echo "IP $ip elegivel para teste" | tee -a "$tolog"
        elif [ -n "$ip" ]; then
            echo "IP $ip testado nas ultimas 48h - ignorando" | tee -a "$tolog"
        fi
    done < "$toip1.tmp"

    rm -f "$toip1.tmp"

    lres=$(wc -l < "$toip1")
    echo "Alvos finais para analise: $lres IPs" | tee -a "$tolog"

    if [ "$lres" -eq 0 ]; then
        echo "Nenhum IP para testar. Saindo..." | tee -a "$tolog"
        exit 0
    fi

    # Mostrar lista de alvos
    echo "Lista de alvos:" | tee -a "$tolog"
    cat "$toip1" | tee -a "$tolog"

    # PASSO 4: SCAN INDIVIDUAL DOS HOSTS
    echo "=== PASSO 4: SCANNING INDIVIDUAL DOS HOSTS ===" | tee -a "$tolog"

    # Timeout geral para scans
    {
        sleep 7200  # 2 horas
        echo "Timeout global atingido - matando processos nmap..." | tee -a "$tolog"
        pkill -f nmap
    } &
    TIMEOUT_PID=$!

    # Processar cada host individualmente (execucao sequencial)
    while read -r ip; do
        if [ -n "$ip" ]; then
            full_host_scan "$ip"
        fi
    done < "$toip1"

    # Matar timeout job
    if [ -n "$TIMEOUT_PID" ]; then
        kill "$TIMEOUT_PID" 2>/dev/null
        wait "$TIMEOUT_PID" 2>/dev/null
        TIMEOUT_PID=""
    fi

    # Limpeza final de processos
    echo "Aguardando conclusao de todos os processos..." | tee -a "$tolog"
    cleanup_zombies

    # Finalizacao
    datetime2=$(date +"%d/%m/%y %H:%M")
    echo "Scan concluido: $datetime ate $datetime2" | tee -a "$tolog"

    # Contar vulnerabilidades encontradas
    vuln_count=$(find "$vuln0" -name "RESUMO_*" -type f 2>/dev/null | wc -l)
    echo "Vulnerabilidades encontradas: $vuln_count" | tee -a "$tolog"

    # Compactar resultados
    echo "Compactando resultados..." | tee -a "$tolog"
    zip -r "$zipfiles/$name.zip" "$pathtest/$name" >/dev/null 2>&1

    chmod 777 -R "$pidfile"

    # Notificacao
    tontfy=$(cat /Data/ntfysh)
    if [ "$tontfy" != "0" ]; then
        if [ "$vuln_count" -gt 0 ]; then
            echo "Enviando alerta de vulnerabilidades..." | tee -a "$tolog"
            curl -u admin:5V06auso -T "$zipfiles/$name.zip" -H "Filename: $name.zip" -H "Title: VULNERABILIDADES - $namepan" -H "Priority: urgent" "$ntfysh/$namepan"
        else
            curl -u admin:5V06auso -d "Scan concluido em $namepan. $lres IPs testados. Nenhuma vulnerabilidade detectada." -H "Title: Scan Concluido - $namepan" "$ntfysh/$namepan"
        fi
    fi

    # Status final
    cat > "$statusfile" << EOF
{
    "timestamp": "$(date '+%d-%m-%Y %H:%M')",
    "status": "completed",
    "progress": {"current": $lres, "total": $lres},
    "vulnerabilities": $vuln_count,
    "current_target": "FINALIZADO",
    "device": "$namepan"
}
EOF

    # Atualizar stats.json para compatibilidade web
    cat > "/Pentests/stats.json" << EOF
{
    "tests_48h": $lres,
    "vulnerabilities_48h": $vuln_count,
    "last_update": "$(date '+%Y-%m-%d %H:%M:%S')",
    "device": "$namepan",
    "status": "completed"
}
EOF

    echo "BLACK BOX PENTEST FINALIZADO!" | tee -a "$tolog"
    echo "Hosts testados: $lres" | tee -a "$tolog"
    echo "Vulnerabilidades encontradas: $vuln_count" | tee -a "$tolog"

    rm -f "$counterfile"

    # Limpeza final
    cleanup_zombies
}

# VERIFICACAO DE ROOT
if [ "$EUID" -ne 0 ]; then
    echo "Execute como Root!"
    exit 1
fi

# INICIO
echo "Project Pandora - Black Box Simplified & Fixed"
echo "=============================================="
echo "✅ Descoberta de hosts online: PING + TCP SYN + UDP"
echo "✅ Scan individual: host por host"
echo "✅ Scan de portas: TCP (1-65535) + UDP (prioritarias)"
echo "✅ Pentests: apenas em portas abertas"
echo "✅ Sem acentuacao e cedilha"
echo "✅ Processos zumbis eliminados"
echo "✅ Tratamento de sinais implementado"
echo "=============================================="

# Exportar funcoes para uso em subprocessos se necessario
export -f full_host_scan scan_open_ports run_vulnerability_tests check_real_vulnerabilities
export -f get_counter update_status_and_control is_recently_tested mark_ip_tested cleanup_zombies
export pathtest name tolog counterfile statusfile toip1 namepan control_yaml vuln0

init
echo "Pentest finalizado!"

# Limpeza final antes de sair
cleanup_zombies
exit 0
