FROM ubuntu:rolling
LABEL maintainer="UrbanCompassPony <urbancompasspony@NOSPAM.NO>"

ENV DEBIAN_FRONTEND=noninteractive
ENV APACHE_RUN_USER=www-data
ENV APACHE_RUN_GROUP=www-data
ENV APACHE_LOG_DIR=/var/log/apache2
ENV APACHE_LOCK_DIR=/var/lock/apache2
ENV APACHE_PID_FILE=/var/run/apache2.pid

# Install packages (removed cron since it's managed by host)
RUN apt update && \
    apt upgrade -y && \
    apt install -y pkg-config && \
    apt install -y nano wget curl parallel arp-scan nmap zip unzip bc && \
    apt install -y apache2 apache2-utils && \
    apt autoremove && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Configure Apache2
RUN a2enmod rewrite && \
    a2enmod ssl && \
    a2enmod auth_basic && \
    a2enmod authz_user

# Create htpasswd file with default credentials (user: admin, pass: pandora123)
RUN htpasswd -cb /etc/apache2/.htpasswd admin pandora123

# Create Apache virtual host configuration - serving directly from /Pentests
RUN echo '<VirtualHost *:80>' > /etc/apache2/sites-available/pentests.conf && \
    echo '    ServerName pentests' >> /etc/apache2/sites-available/pentests.conf && \
    echo '    DocumentRoot /Pentests' >> /etc/apache2/sites-available/pentests.conf && \
    echo '    <Directory /Pentests>' >> /etc/apache2/sites-available/pentests.conf && \
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

# Create /Pentests directory structure
RUN mkdir -p /Pentests/Todos_os_Resultados && \
    mkdir -p /Pentests/Historico && \
    mkdir -p /Pentests/Ataque_Bem-Sucedido && \
    chown -R www-data:www-data /Pentests && \
    chmod -R 755 /Pentests

# Add scripts
ADD pandora.sh /pandora.sh
ADD entrypoint.sh /entrypoint.sh

# Make scripts executable
RUN chmod 755 /pandora.sh /entrypoint.sh && \
    chmod +x /pandora.sh /entrypoint.sh

# Expose Apache port
EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
