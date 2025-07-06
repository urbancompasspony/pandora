FROM ubuntu:rolling
LABEL maintainer="UrbanCompassPony <urbancompasspony@NOSPAM.NO>"

ENV DEBIAN_FRONTEND=noninteractive
ENV APACHE_RUN_USER=www-data
ENV APACHE_RUN_GROUP=www-data
ENV APACHE_LOG_DIR=/var/log/apache2
ENV APACHE_LOCK_DIR=/var/lock/apache2
ENV APACHE_PID_FILE=/var/run/apache2.pid

# Install packages
RUN apt update && \
    apt upgrade -y && \
    apt install -y pkg-config && \
    apt install -y nano wget curl parallel arp-scan nmap cron zip unzip bc && \
    apt install -y apache2 apache2-utils && \
    apt autoremove && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Configure Apache2
RUN a2enmod rewrite && \
    a2enmod ssl && \
    a2enmod auth_basic && \
    a2enmod authz_user

# Create web directory and set permissions
RUN mkdir -p /var/www/pentests && \
    chown -R www-data:www-data /var/www/pentests && \
    chmod -R 755 /var/www/pentests

# Create htpasswd file with default credentials (user: admin, pass: pandora123)
RUN htpasswd -cb /etc/apache2/.htpasswd admin pandora123

# Create Apache virtual host configuration
RUN echo '<VirtualHost *:80>' > /etc/apache2/sites-available/pentests.conf && \
    echo '    ServerName pentests' >> /etc/apache2/sites-available/pentests.conf && \
    echo '    DocumentRoot /var/www/pentests' >> /etc/apache2/sites-available/pentests.conf && \
    echo '    <Directory /var/www/pentests>' >> /etc/apache2/sites-available/pentests.conf && \
    echo '        AuthType Basic' >> /etc/apache2/sites-available/pentests.conf && \
    echo '        AuthName "Project Pandora - Pentest Results"' >> /etc/apache2/sites-available/pentests.conf && \
    echo '        AuthUserFile /etc/apache2/.htpasswd' >> /etc/apache2/sites-available/pentests.conf && \
    echo '        Require valid-user' >> /etc/apache2/sites-available/pentests.conf && \
    echo '        Options Indexes FollowSymLinks' >> /etc/apache2/sites-available/pentests.conf && \
    echo '        AllowOverride All' >> /etc/apache2/sites-available/pentests.conf && \
    echo '        IndexOptions FancyIndexing HTMLTable SuppressDescription' >> /etc/apache2/sites-available/pentests.conf && \
    echo '        IndexIgnore *.tmp *.log' >> /etc/apache2/sites-available/pentests.conf && \
    echo '    </Directory>' >> /etc/apache2/sites-available/pentests.conf && \
    echo '    ErrorLog ${APACHE_LOG_DIR}/pentests_error.log' >> /etc/apache2/sites-available/pentests.conf && \
    echo '    CustomLog ${APACHE_LOG_DIR}/pentests_access.log combined' >> /etc/apache2/sites-available/pentests.conf && \
    echo '</VirtualHost>' >> /etc/apache2/sites-available/pentests.conf

# Enable the pentest site and disable default
RUN a2ensite pentests.conf && \
    a2dissite 000-default.conf

# Create a Black Box themed index.html for the web interface
RUN echo '<!DOCTYPE html>' > /var/www/pentests/index.html && \
    echo '<html><head>' >> /var/www/pentests/index.html && \
    echo '<title>🔰 Project Pandora - Black Box Results</title>' >> /var/www/pentests/index.html && \
    echo '<meta charset="UTF-8">' >> /var/www/pentests/index.html && \
    echo '<meta name="viewport" content="width=device-width, initial-scale=1.0">' >> /var/www/pentests/index.html && \
    echo '<style>' >> /var/www/pentests/index.html && \
    echo 'body { font-family: "Courier New", monospace; margin: 20px; background: #0a0a0a; color: #00ff00; }' >> /var/www/pentests/index.html && \
    echo '.header { background: linear-gradient(135deg, #ff0000 0%, #cc0000 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px; border: 2px solid #ff0000; }' >> /var/www/pentests/index.html && \
    echo '.card { background: #1a1a1a; border: 1px solid #333; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 0 10px rgba(255,0,0,0.3); }' >> /var/www/pentests/index.html && \
    echo '.status { padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 3px solid #00ff00; }' >> /var/www/pentests/index.html && \
    echo '.vulnerable { background-color: #2d0000; border-left: 5px solid #ff4444; color: #ff6666; }' >> /var/www/pentests/index.html && \
    echo '.safe { background-color: #002d00; border-left: 5px solid #44ff44; color: #66ff66; }' >> /var/www/pentests/index.html && \
    echo '.warning { background-color: #2d2d00; border-left: 5px solid #ffff44; color: #ffff66; }' >> /var/www/pentests/index.html && \
    echo '.info { background-color: #001a2d; border-left: 5px solid #4488ff; color: #66aaff; }' >> /var/www/pentests/index.html && \
    echo 'a { color: #00ffff; text-decoration: none; font-weight: bold; }' >> /var/www/pentests/index.html && \
    echo 'a:hover { color: #ff00ff; text-decoration: underline; }' >> /var/www/pentests/index.html && \
    echo '.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }' >> /var/www/pentests/index.html && \
    echo '.blackbox-badge { background: #ff0000; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; animation: pulse 2s infinite; }' >> /var/www/pentests/index.html && \
    echo '.terminal { background: #000; color: #00ff00; padding: 15px; border-radius: 5px; font-family: "Courier New", monospace; border: 1px solid #00ff00; }' >> /var/www/pentests/index.html && \
    echo '@keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }' >> /var/www/pentests/index.html && \
    echo '.scope-info { background: #1a0a1a; border: 1px solid #ff00ff; padding: 10px; border-radius: 5px; color: #ff88ff; }' >> /var/www/pentests/index.html && \
    echo '</style>' >> /var/www/pentests/index.html && \
    echo '</head><body>' >> /var/www/pentests/index.html && \
    echo '<div class="header">' >> /var/www/pentests/index.html && \
    echo '<h1>🔰 Project Pandora</h1>' >> /var/www/pentests/index.html && \
    echo '<h2>Black Box Penetration Testing Results</h2>' >> /var/www/pentests/index.html && \
    echo '<span class="blackbox-badge">DOUBLE BLIND BLACK BOX</span>' >> /var/www/pentests/index.html && \
    echo '</div>' >> /var/www/pentests/index.html && \
    echo '<div class="grid">' >> /var/www/pentests/index.html && \
    echo '<div class="card">' >> /var/www/pentests/index.html && \
    echo '<h3>🎯 Resultados Black Box</h3>' >> /var/www/pentests/index.html && \
    echo '<p><a href="/Todos_os_Resultados/">📁 Todos os Resultados</a></p>' >> /var/www/pentests/index.html && \
    echo '<p><a href="/Historico/">📦 Arquivos Compactados</a></p>' >> /var/www/pentests/index.html && \
    echo '<p><a href="/Ataque_Bem-Sucedido/">🚨 Vulnerabilidades Críticas</a></p>' >> /var/www/pentests/index.html && \
    echo '</div>' >> /var/www/pentests/index.html && \
    echo '<div class="card scope-info">' >> /var/www/pentests/index.html && \
    echo '<h3>🔬 Escopo de Scanning</h3>' >> /var/www/pentests/index.html && \
    echo '<div class="terminal">' >> /var/www/pentests/index.html && \
    echo 'TCP: 1-65535 (Full Range)<br>' >> /var/www/pentests/index.html && \
    echo 'UDP: Top 30 Critical Corporate<br>' >> /var/www/pentests/index.html && \
    echo 'Scripts: vuln,safe,discovery,auth,brute<br>' >> /var/www/pentests/index.html && \
    echo 'Methodology: Double Blind Assessment' >> /var/www/pentests/index.html && \
    echo '</div>' >> /var/www/pentests/index.html && \
    echo '</div>' >> /var/www/pentests/index.html && \
    echo '</div>' >> /var/www/pentests/index.html && \
    echo '<div class="grid">' >> /var/www/pentests/index.html && \
    echo '<div class="card">' >> /var/www/pentests/index.html && \
    echo '<h3>🔄 Status em Tempo Real</h3>' >> /var/www/pentests/index.html && \
    echo '<div id="status-info">Carregando status...</div>' >> /var/www/pentests/index.html && \
    echo '</div>' >> /var/www/pentests/index.html && \
    echo '<div class="card warning">' >> /var/www/pentests/index.html && \
    echo '<h3>⚠️ Aviso Legal</h3>' >> /var/www/pentests/index.html && \
    echo '<p><strong>Este é um teste de penetração automatizado.</strong></p>' >> /var/www/pentests/index.html && \
    echo '<p>Resultados são baseados em scanning automático e podem não refletir todos os vetores de ataque possíveis.</p>' >> /var/www/pentests/index.html && \
    echo '<p><em>Testes manuais adicionais são recomendados.</em></p>' >> /var/www/pentests/index.html && \
    echo '</div>' >> /var/www/pentests/index.html && \
    echo '</div>' >> /var/www/pentests/index.html && \
    echo '<script>' >> /var/www/pentests/index.html && \
    echo 'function updateStatus() {' >> /var/www/pentests/index.html && \
    echo '  fetch("/Todos_os_Resultados/")' >> /var/www/pentests/index.html && \
    echo '    .then(response => response.text())' >> /var/www/pentests/index.html && \
    echo '    .then(data => {' >> /var/www/pentests/index.html && \
    echo '      const statusDiv = document.getElementById("status-info");' >> /var/www/pentests/index.html && \
    echo '      const testCount = (data.match(/href="/g) || []).length - 1;' >> /var/www/pentests/index.html && \
    echo '      const vulnCount = (data.match(/RESUMO_/g) || []).length;' >> /var/www/pentests/index.html && \
    echo '      let statusClass = "safe";' >> /var/www/pentests/index.html && \
    echo '      let statusIcon = "✅";' >> /var/www/pentests/index.html && \
    echo '      if (vulnCount > 0) { statusClass = "vulnerable"; statusIcon = "🚨"; }' >> /var/www/pentests/index.html && \
    echo '      statusDiv.innerHTML = `<div class="${statusClass}">${statusIcon} Testes: ${testCount} | Vulnerabilidades: ${vulnCount}</div>`;' >> /var/www/pentests/index.html && \
    echo '    })' >> /var/www/pentests/index.html && \
    echo '    .catch(err => {' >> /var/www/pentests/index.html && \
    echo '      document.getElementById("status-info").innerHTML = `<div class="warning">⚙️ Sistema executando scan...</div>`;' >> /var/www/pentests/index.html && \
    echo '    });' >> /var/www/pentests/index.html && \
    echo '}' >> /var/www/pentests/index.html && \
    echo 'updateStatus();' >> /var/www/pentests/index.html && \
    echo 'setInterval(updateStatus, 30000);' >> /var/www/pentests/index.html && \
    echo '</script>' >> /var/www/pentests/index.html && \
    echo '</body></html>' >> /var/www/pentests/index.html

# Add scripts
ADD pandora.sh /pandora.sh
ADD entrypoint.sh /entrypoint.sh

# Make scripts executable
RUN chmod 755 /pandora.sh /entrypoint.sh && \
    chmod +x /pandora.sh /entrypoint.sh

# Create symlinks for web access
RUN ln -sf /Pentests/Todos_os_Resultados /var/www/pentests/Todos_os_Resultados && \
    ln -sf /Pentests/Historico /var/www/pentests/Historico && \
    ln -sf /Pentests/Ataque_Bem-Sucedido /var/www/pentests/Ataque_Bem-Sucedido

# Expose Apache port
EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
