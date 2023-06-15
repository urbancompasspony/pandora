FROM ubuntu:rolling
MAINTAINER UrbanCompassPony <urbancompasspony@NOSPAM.NO>
ENV DEBIAN_FRONTEND noninteractive

RUN apt update && \
apt upgrade -y && \
apt install -y pkg-config && \
apt install -y nano wget curl parallel arp-scan nmap cron zip unzip && \
apt autoremove && \
apt clean && \
rm -rf /var/lib/apt/lists/*

ADD pandora.sh /pandora.sh
ADD entrypoint.sh /entrypoint.sh

RUN chmod 755 /pandora.sh /entrypoint.sh
RUN chmod +x /pandora.sh /entrypoint.sh

ENTRYPOINT /entrypoint.sh
