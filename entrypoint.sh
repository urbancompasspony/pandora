#!/bin/bash

# Configure cron jobs
echo "@reboot /pandora.sh >> /var/log/cron.log 2>&1
0 12,19 * * * /pandora.sh >> /var/log/cron.log 2>&1
# This extra line makes it a valid cron!" > scheduler.txt

crontab scheduler.txt

# Create necessary directories and set permissions
mkdir -p /var/www/pentests/Todos_os_Resultados
mkdir -p /var/www/pentests/Historico
mkdir -p /var/www/pentests/Ataque_Bem-Sucedido

# Update symlinks to point to the actual pentest directories
if [ -d "/Pentests" ]; then
    ln -sf /Pentests/Todos_os_Resultados /var/www/pentests/Todos_os_Resultados
    ln -sf /Pentests/Historico /var/www/pentests/Historico
    ln -sf /Pentests/Ataque_Bem-Sucedido /var/www/pentests/Ataque_Bem-Sucedido
fi

# Set proper permissions
chown -R www-data:www-data /var/www/pentests
chmod -R 755 /var/www/pentests

# APACHE SERVER com Samba CGI
service apache2 start &

# Function to check Apache2 status
check_apache() {
    # Verifica se Apache2 está rodando
    if ! pgrep apache2 > /dev/null; then
        echo "Apache2 não encontrado. Iniciando..."
        
        # Limpa sockets órfãos
        find /var/run/apache2/ -name "cgisock*" -exec unlink {} \; 2>/dev/null || true
        
        # Inicia Apache2
        service apache2 start
        sleep 2
        
        # Verifica se iniciou corretamente
        if ! pgrep apache2 > /dev/null; then
            echo "Falha ao iniciar. Tentando restart..."
            service apache2 restart
            sleep 2
        fi
    else
        echo "Apache2 já está em execução (PID: $(pgrep apache2 | head -1))"
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
        cat > /var/www/pentests/stats.json << EOF
{
    "tests_executed": $test_count,
    "vulnerabilities_found": $vuln_count,
    "last_update": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
    fi
}

# Background process to monitor Apache and update stats
(
    while true; do
        check_apache
        update_web_stats
        sleep 300  # Check every 5 minutes
    done
) &

echo "🔰 Project Pandora iniciado!"
echo "🌐 Interface web disponível na porta 80"
echo "👤 Usuário: admin | Senha: pandora123"
echo "📊 Acesse /stats.json para estatísticas em JSON"

# Start cron and keep container running
exec cron -f
