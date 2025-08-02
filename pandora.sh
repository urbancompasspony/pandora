#!/bin/bash
###################
# Project Pandora #
# Black Box Edition - SIMPLIFIED & FIXED
################################################################################

# CONFIGURAÇÕES BÁSICAS
namepan=$(cat /Data/hostname)
ntfysh=$(cat /Data/ntfysh)
RUNA=$(cat /Data/runa)
pidfile="/Pentests"
vuln0="$pidfile/Ataque_Bem-Sucedido"
pathtest="$pidfile/Todos_os_Resultados"
zipfiles="$pidfile/Historico"
statusfile="$pidfile/status.json"
counterfile="$pidfile/counter.txt"
control_yaml="$pidfile/controle.yaml"

################################################################################

# FUNÇÃO UNIFICADA DE STATUS E CONTROLE
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

# FUNÇÃO SIMPLIFICADA DE COUNTER
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

# FUNÇÕES DE CONTROLE YAML
init_control_yaml() {
    if [ ! -f "$control_yaml" ]; then
        cat > "$control_yaml" << 'EOF'
IPs_Identificados: {}
IPs_testados: {}
EOF
    fi
}

# VERIFICAR SE IP FOI TESTADO NAS ÚLTIMAS 48H
is_recently_tested() {
    local ip=$1
    local current_time
    local test_time
    local diff_hours

    current_time=$(date +%s)

    # Verificar se IP existe no YAML e pegar epoch time
    if yq eval ".IPs_testados.\"$ip\"" "$control_yaml" | grep -q "null"; then
        return 1  # IP não foi testado
    fi

    test_time=$(yq eval ".IPs_testados.\"$ip\"" "$control_yaml")
    diff_hours=$(( (current_time - test_time) / 3600 ))

    if [ "$diff_hours" -lt 48 ]; then
        return 0  # Foi testado há menos de 48h
    else
        return 1  # Pode ser testado novamente
    fi
}

# MARCAR IP COMO TESTADO COM SUCESSO
mark_ip_tested() {
    local ip=$1
    local current_time

    current_time=$(date +%s)

    # Atualizar ambos os blocos
    yq eval ".IPs_Identificados.\"$ip\" = \"sim\"" -i "$control_yaml"
    yq eval ".IPs_testados.\"$ip\" = $current_time" -i "$control_yaml"
}

# ATUALIZAR LISTA DE IPs IDENTIFICADOS
update_identified_ips() {
    local ip_list_file=$1

    # Primeiro, marcar todos os IPs descobertos como identificados
    while read -r ip; do
        if [ -n "$ip" ]; then
            # Se IP não foi testado nas últimas 48h, marcar como "nao"
            if is_recently_tested "$ip"; then
                yq eval ".IPs_Identificados.\"$ip\" = \"sim\"" -i "$control_yaml"
            else
                yq eval ".IPs_Identificados.\"$ip\" = \"nao\"" -i "$control_yaml"
            fi
        fi
    done < "$ip_list_file"
}

# FUNÇÃO DE TESTE DE CONECTIVIDADE SEM ICMP
test_connectivity() {
    local ip=$1
    local tcp_reachable=false

    echo "Testando conectividade TCP para $ip..." | tee -a "$tolog"

    # Teste TCP em portas comuns (sem ICMP)
    for test_port in 22 23 25 53 80 135 139 443 445 993 995 3389; do
        if timeout 3 bash -c "</dev/tcp/$ip/$test_port" 2>/dev/null; then
            tcp_reachable=true
            echo "Host $ip alcançável via TCP porta $test_port" | tee -a "$tolog"
            break
        fi
    done

    if [ "$tcp_reachable" = false ]; then
        echo "Host $ip não acessível via TCP nas portas testadas" | tee -a "$tolog"
        return 1
    fi

    return 0
}

# SCAN SIMPLIFICADO - FUNÇÃO PRINCIPAL (SEM ICMP)
simple_black_box_scan() {
    local ip=$1
    local final_results="$pathtest/$name/$ip"
    local current_counter
    local total_ips
    local tcp_results
    local udp_results
    local tcp_open
    local udp_open
    local open_tcp_ports
    local open_udp_ports

    # Pular se testado recentemente
    if is_recently_tested "$ip"; then
        echo "IP $ip testado nas últimas 48h - pulando" | tee -a "$tolog"
        return 1
    fi

    # Counter e status
    current_counter=$(get_counter)
    total_ips=$(wc -l < "$toip1")

    echo "[$current_counter/$total_ips] Scanning $ip..." | tee -a "$tolog"
    update_status_and_control "$current_counter" "$total_ips" "0" "$ip"

    # REMOVIDO: Verificação ICMP ping - agora testa diretamente com TCP
    if ! test_connectivity "$ip"; then
        echo "Host $ip não acessível" > "$final_results"
        return 1
    fi

    # TCP scan completo TODAS AS PORTAS (1-65535)
    echo "TCP scan completo $ip (1-65535)..." | tee -a "$tolog"
    tcp_results="$pathtest/$name/${ip}_tcp"

    # Scan TCP completo - TODAS as portas
    timeout 900 nmap -Pn -sS -p 1-65535 --min-rate 500 --max-retries 2 \
        --host-timeout 600s -T2 "$ip" > "$tcp_results" 2>&1

    local tcp_exit_code=$?
    if [ "$tcp_exit_code" -eq 124 ]; then
        echo "TCP scan timeout para $ip - host pode estar filtrado" | tee -a "$tolog"
        echo "TCP scan timeout - possível firewall bloqueando" > "$final_results"
        rm -f "$tcp_results"
        return 1
    fi

    # UDP scan COMPLETO (1-65535) - CORRIGIDO
    echo "UDP scan completo $ip (1-65535)..." | tee -a "$tolog"
    udp_results="$pathtest/$name/${ip}_udp"

    # SCAN UDP COMPLETO - Dividido em partes para otimizar
    # Parte 1: Portas críticas mais rápido
    timeout 600 nmap -Pn -sU -p 1-1000 --min-rate 300 --max-retries 1 \
        --host-timeout 300s -T2 "$ip" > "${udp_results}_part1" 2>&1 &

    # Parte 2: Resto das portas
    timeout 1200 nmap -Pn -sU -p 1001-65535 --min-rate 200 --max-retries 1 \
        --host-timeout 600s -T1 "$ip" > "${udp_results}_part2" 2>&1 &

    # Aguardar conclusão
    wait

    # Combinar resultados UDP
    cat "${udp_results}_part1" "${udp_results}_part2" > "$udp_results" 2>/dev/null
    rm -f "${udp_results}_part1" "${udp_results}_part2"

    # Verificar portas abertas
    if grep -q "open" "$tcp_results"; then
        tcp_open="true"
    else
        tcp_open="false"
    fi

    if grep -q "open" "$udp_results"; then
        udp_open="true"
    else
        udp_open="false"
    fi

    if [ "$tcp_open" = "true" ] || [ "$udp_open" = "true" ]; then
        echo "Serviços encontrados em $ip - analisando vulnerabilidades..." | tee -a "$tolog"

        # Criar resultado final
        {
            echo "=== BLACK BOX SCAN RESULTS ==="
            echo "Target: $ip"
            echo "Date: $(date)"
            echo "=============================="
            echo ""
        } > "$final_results"

        # Scan de vulnerabilidades OBJETIVAS apenas em portas abertas
        if [ "$tcp_open" = "true" ]; then
            open_tcp_ports=$(grep "open" "$tcp_results" | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
            if [ -n "$open_tcp_ports" ]; then
                {
                    echo "=== TCP VULNERABILITY SCAN ==="
                    echo "Portas TCP abertas: $open_tcp_ports"
                    echo ""
                } >> "$final_results"

                # Scripts OBJETIVOS que testam vulnerabilidades reais - TODAS AS PORTAS ABERTAS
                timeout 1800 nmap -Pn -sS -sV --script \
                    "auth-bypass or auth-spoof or ftp-anon or ftp-bounce or \
                     http-default-accounts or http-method-tamper or http-put or \
                     mysql-empty-password or smb-vuln-ms17-010 or smb-vuln-cve-2017-7494 or \
                     smb-vuln-ms08-067 or smb-vuln-cve2009-3103 or smb-double-pulsar-backdoor or \
                     smb2-vuln-uptime or samba-vuln-cve-2012-1182 or \
                     ssl-poodle or ssl-heartbleed or ssl-ccs-injection or \
                     http-sql-injection or http-shellshock or http-fileupload-exploiter or \
                     rdp-vuln-ms12-020 or ssh-auth-methods or ssh2-enum-algos or \
                     ldap-rootdse or ldap-search or ms-sql-empty-password or \
                     smb-enum-shares or smb-ls or smb-enum-users or \
                     http-backup-finder or http-config-backup or http-git" \
                    --script-timeout 90s -T3 -p "$open_tcp_ports" "$ip" >> "$final_results" 2>&1
            fi
        fi

        if [ "$udp_open" = "true" ]; then
            open_udp_ports=$(grep "open" "$udp_results" | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
            if [ -n "$open_udp_ports" ]; then
                {
                    echo "=== UDP VULNERABILITY SCAN ==="
                    echo "Portas UDP abertas: $open_udp_ports"
                    echo ""
                } >> "$final_results"

                # Scripts UDP objetivos - TODAS AS PORTAS ABERTAS
                timeout 900 nmap -Pn -sU --script \
                    "snmp-brute or snmp-info or dns-zone-transfer or ntp-info or \
                     dhcp-discover or tftp-enum or netbios-nb-stat or \
                     ms-sql-info or ldap-brute or kerberos-enum-users" \
                    --script-timeout 90s -T3 -p "$open_udp_ports" "$ip" >> "$final_results" 2>&1
            fi
        fi

        rm -f "$tcp_results" "$udp_results"

        # Marcar IP como testado com sucesso
        mark_ip_tested "$ip"
        return 0
    else
        echo "Nenhum serviço encontrado em $ip" > "$final_results"
        rm -f "$tcp_results" "$udp_results"

        # Marcar IP como testado com sucesso (mesmo sem serviços)
        mark_ip_tested "$ip"
        return 1
    fi
}

# VERIFICAÇÃO OBJETIVA DE VULNERABILIDADES
check_vulnerabilities() {
    echo "Verificando vulnerabilidades REAIS..." | tee -a "$tolog"
    local vuln_found=1

    while read -r ip; do
        if [ -f "$pathtest/$name/$ip" ]; then
            # Buscar APENAS vulnerabilidades confirmadas e exploráveis
            local vuln_detected=false
            local vuln_summary=""

            # 1. Vulnerabilidades CONFIRMADAS (não apenas CVEs listados)
            if grep -E "(VULNERABLE|Successfully|exploit|anonymous|default.*password|empty.*password)" "$pathtest/$name/$ip" >/dev/null 2>&1; then
                vuln_detected=true
                vuln_summary+="Vulnerabilidade CONFIRMADA detectada\n"
            fi

            # 2. Autenticação bypass REAL
            if grep -E "(authentication.*bypass|login.*anonymous|ftp.*anonymous)" "$pathtest/$name/$ip" >/dev/null 2>&1; then
                vuln_detected=true
                vuln_summary+="Bypass de autenticacao detectado\n"
            fi

            # 3. Credentials padrão FUNCIONAIS
            if grep -E "(default.*credentials.*work|admin.*admin.*success|root.*password)" "$pathtest/$name/$ip" >/dev/null 2>&1; then
                vuln_detected=true
                vuln_summary+="Credenciais padrao funcionais\n"
            fi

            # 4. Testes específicos para Samba/AD CONFIRMADOS
            if grep -E "(smb.*vulnerable|ldap.*anonymous|kerberos.*enum.*success)" "$pathtest/$name/$ip" >/dev/null 2>&1; then
                vuln_detected=true
                vuln_summary+="Vulnerabilidade Samba/AD confirmada\n"
            fi

            # 5. Backdoors e malware (WannaCry, DoublePulsar)
            if grep -E "(double.*pulsar|wannacry|backdoor.*detected|malware)" "$pathtest/$name/$ip" >/dev/null 2>&1; then
                vuln_detected=true
                vuln_summary+="Backdoor ou malware detectado\n"
            fi

            # 6. Enumeração bem-sucedida (usuários, shares, etc)
            if grep -E "(users.*enumerated|shares.*accessible|domain.*enumerated)" "$pathtest/$name/$ip" >/dev/null 2>&1; then
                vuln_detected=true
                vuln_summary+="Enumeracao de recursos bem-sucedida\n"
            fi

            # Ignorar falsos positivos e listas de CVE
            if grep -E "(NOT VULNERABLE|not vulnerable|CVE.*list|database.*lookup)" "$pathtest/$name/$ip" >/dev/null 2>&1; then
                vuln_detected=false
            fi

            # SE encontrou vulnerabilidade REAL
            if [ "$vuln_detected" = true ]; then
                mkdir -p "$vuln0"
                cp "$pathtest/$name/$ip" "$vuln0/${ip}_scan.txt"

                {
                    echo "=== VULNERABILIDADE REAL CONFIRMADA ==="
                    echo "IP: $ip"
                    echo "Data: $(date)"
                    echo "Tipo: Teste ativo confirmado"
                    echo "======================================="
                    echo -e "$vuln_summary"
                    echo ""
                    echo "EVIDENCIAS:"
                    grep -E "(VULNERABLE|Successfully|exploit|anonymous|default.*password|bypass)" "$pathtest/$name/$ip" | head -5
                } > "$vuln0/RESUMO_${ip}.txt"

                vuln_found=0
                echo "VULNERABILIDADE REAL confirmada em $ip!" | tee -a "$tolog"
            else
                echo "[$ip] Nenhuma vulnerabilidade real confirmada" | tee -a "$tolog"
            fi
        fi
    done < "$toip1"

    return $vuln_found
}

# FUNÇÃO PRINCIPAL SIMPLIFICADA
init() {
    # Configuração básica
    local datetime
    local name
    local toip
    local tolog
    local toip1
    local network_range
    local lres
    local datetime2
    local vuln_result
    local tontfy

    datetime=$(date +"%d/%m/%y %H:%M")
    name=$(date +"%d_%m_%y-%H:%M")

    mkdir -p "$zipfiles" "$pathtest/$name" "$vuln0"

    # Arquivos de trabalho
    toip="$pathtest/$name/01_A_IP"
    tolog="$pathtest/$name/02_Logs"
    toip1="$pathtest/$name/03_WBIP"

    # Inicializar controle YAML
    init_control_yaml

    echo "0" > "$counterfile"

    echo "BLACK BOX PENTEST INICIADO em $datetime!" | tee -a "$tolog"
    echo "Dispositivo: $namepan" | tee -a "$tolog"

    # Descoberta de rede SEM ping - apenas nmap host discovery
    echo "Descobrindo hosts ativos (sem ping ICMP)..." | tee -a "$tolog"
    network_range=$(hostname -I | awk '{print $1}')

    # Host discovery usando nmap (sem ping ICMP) - mais agressivo
    nmap -Pn -sn --min-rate 2000 "${network_range}/24" | grep "Nmap scan report" | awk '{print $5}' > "$toip"

    # Filtrar blacklist
    if [ -f "/Data/blacklist" ]; then
        grep -v -F -x -f "/Data/blacklist" "$toip" > "$toip1.tmp"
    else
        cp "$toip" "$toip1.tmp"
    fi

    # Atualizar controle YAML com IPs descobertos
    update_identified_ips "$toip1.tmp"

    # Filtrar IPs testados nas últimas 48h usando YAML
    true > "$toip1"
    while read -r ip; do
        if ! is_recently_tested "$ip"; then
            echo "$ip" >> "$toip1"
            echo "IP $ip elegível para teste" | tee -a "$tolog"
        else
            echo "IP $ip testado nas últimas 48h - ignorando" | tee -a "$tolog"
        fi
    done < "$toip1.tmp"

    rm -f "$toip1.tmp"

    lres=$(wc -l < "$toip1")
    echo "Alvos para análise: $lres IPs" | tee -a "$tolog"

    # Criar diretório com timestamp para compatibilidade web
    echo "Criando estrutura de diretórios para interface web..." | tee -a "$tolog"

    # Garantir que existe arquivo de contagem para interface web
    echo "$lres" > "$pathtest/$name/total_targets.txt"

    if [ "$lres" -eq 0 ]; then
        echo "Nenhum IP para testar. Saindo..." | tee -a "$tolog"
        exit 0
    fi

    # Ajustar jobs paralelos
    [ "$RUNA" -gt 3 ] && RUNA=3
    [ "$RUNA" -lt 1 ] && RUNA=1

    echo "Utilizando $RUNA jobs paralelos" | tee -a "$tolog"

    # Timeout geral aumentado devido ao scan UDP completo
    sleep 7200 && pkill nmap &

    # Exportar funções para parallel
    export -f simple_black_box_scan get_counter update_status_and_control is_recently_tested mark_ip_tested test_connectivity
    export pathtest name tolog counterfile statusfile toip1 namepan control_yaml

    # Executar scans
    echo "Iniciando scans..." | tee -a "$tolog"
    cat "$toip1" | parallel -j "$RUNA" "simple_black_box_scan {}"

    # Finalização
    datetime2=$(date +"%d/%m/%y %H:%M")
    echo "Scan concluído: $datetime até $datetime2" | tee -a "$tolog"

    # Verificar vulnerabilidades
    check_vulnerabilities
    vuln_result=$?

    # Compactar resultados
    echo "Compactando resultados..." | tee -a "$tolog"
    zip -r "$zipfiles/$name.zip" "$pathtest/$name" >/dev/null 2>&1

    chmod 777 -R "$pidfile"

    # Notificação
    tontfy=$(cat /Data/ntfysh)
    if [ "$tontfy" != "0" ]; then
        if [ "$vuln_result" -eq 0 ]; then
            echo "Enviando alerta de vulnerabilidades..." | tee -a "$tolog"
            curl -u admin:5V06auso -T "$zipfiles/$name.zip" -H "Filename: $name.zip" -H "Title: VULNERABILIDADES - $namepan" -H "Priority: urgent" "$ntfysh/$namepan"
        else
            curl -u admin:5V06auso -d "Scan concluído em $namepan. $lres IPs testados. Nenhuma vulnerabilidade detectada." -H "Title: Scan Concluído - $namepan" "$ntfysh/$namepan"
        fi
    fi

    # Status final
    local final_vuln_count
    final_vuln_count=$(find "$vuln0" -name "RESUMO_*" -type f 2>/dev/null | wc -l)

    cat > "$statusfile" << EOF
{
    "timestamp": "$(date '+%d-%m-%Y %H:%M')",
    "status": "completed",
    "progress": {"current": $lres, "total": $lres},
    "vulnerabilities": $final_vuln_count,
    "current_target": "FINALIZADO",
    "device": "$namepan"
}
EOF

    # Atualizar stats.json para compatibilidade web
    cat > "/Pentests/stats.json" << EOF
{
    "tests_48h": $lres,
    "vulnerabilities_48h": $final_vuln_count,
    "last_update": "$(date '+%Y-%m-%d %H:%M:%S')",
    "device": "$namepan",
    "status": "completed"
}
EOF

    echo "BLACK BOX PENTEST FINALIZADO!" | tee -a "$tolog"
    rm -f "$counterfile"
}

# VERIFICAÇÃO DE ROOT
if [ "$EUID" -ne 0 ]; then
    echo "Execute como Root!"
    exit 1
fi

# INÍCIO
echo "Project Pandora - Black Box Simplified & Fixed"
echo "=============================================="
echo "✅ ICMP ping removido completamente"
echo "✅ TCP scan: TODAS as portas (1-65535)"
echo "✅ UDP scan: TODAS as portas (1-65535)"
echo "✅ Testes de vulnerabilidade em TODAS as portas abertas"
echo "=============================================="
init
echo "Pentest finalizado!"
exit 0
