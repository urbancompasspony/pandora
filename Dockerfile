FROM ubuntu:23.04
# Remove this line plz! Keep distro-upgraded because of NMAP Version. Latest: 7.94
MAINTAINER UrbanCompassPony <urbancompasspony@NOSPAM.NO>

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt upgrade -y && apt install -y pkg-config && apt install -y nano wget curl parallel arp-scan nmap cron zip unzip

ADD LINKS /root/Links/LINKS
ADD pandora.sh /pandora.sh
ADD entrypoint.sh /entrypoint.sh
ADD clamav-exec.nse /usr/share/nmap/scripts/

RUN wget -i /root/Links/LINKS -P /root/Links/ && mv /root/Links/* /usr/share/nmap/scripts/
RUN chmod 755 /pandora.sh /entrypoint.sh && chmod +x /pandora.sh /entrypoint.sh

ENTRYPOINT /entrypoint.sh
