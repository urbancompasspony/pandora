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
vuln0="$pidfile/Ataques_Bem-sucedidos"

# Custom path for PENTESTS results
pathtest="$pidfile/Todos_os_Resultados"

# Custom path for ZIPPED files from results.
zipfiles="$pidfile/Historico"

# Status
statustest=".teste.em.andamento"

################################################################################

function init {
  # Set some vars
  datetime=$(date +"%d/%m/%y %H:%M")
  name=$(date +"%d_%m_%y-%H:%M")
  
  # Create main dir, if it does not exist
  mkdir -p "$zipfiles"
  mkdir -p "$pathtest"/"$name"

  # Kill nmap after 1800 seconds (30 min) if hang!
  sleep 1800 && pkill nmap & echo $! | tee "$pidfile"/"$statustest"

  # Generate some Files and Vars
  touch "$pathtest"/"$name"/01IP; toip="$pathtest"/"$name"/01IP
  touch "$pathtest"/"$name"/02Log; tolog="$pathtest"/"$name"/02Log

  # Some logs
  echo "Pentest iniciado em $datetime!" | tee -a "$tolog"

  # Generate IPs to analyze:
  nmap -e "$rede" -n -sn $(hostname -I | awk '{print $1}')"/24" | grep report | awk '{print $5}' | tee "$toip"

  # Calculate remaining time:
  lres=$( wc -l < "$toip" )
  echo "Encontramos "$lres" IPs para analisar." | tee -a "$tolog"

  # Do RUNA jobs at time!
  # Exclude 9100 because of printers!
  cat "$toip" | parallel -j "$RUNA" -k "nmap -Pn --script vuln --exclude-ports 9100,9101,9102,9103,9104,9105,9106,9107,9108,9109,9110,9111,9112,9113,9114,9115,9116,9117,9118,9119,9120 -p 1-9099,9121-65535 {} | tee -a $pathtest/$name/{}"

  # When finished
  datetime2=$(date +"%d/%m/%y %H:%M")

  # Just some last logs to finish this.
  echo "Esse teste executou de $datetime ate $datetime2." | tee -a "$tolog"

  # Kill NMAP killer!
  pidsleep=$(cat $pidfile/$statustest)
  echo "Killing PID $pidsleep of sleep_&_auto_kill nmap process" | tee -a "$tolog" 
  kill -9 "$pidsleep"
  pkill sleep
  rm "$pidfile"/"$statustest"

  # Identify if there is any VULNERABLE system!
  while read line
  do
    grep -Fq "Exploitable" "$pathtest/$name/$line" && mkdir -p "$vuln0" && cp "$pathtest/$name/$line" "$vuln0" || echo "Nothing found!" > /dev/null
  done < "$toip"
  sleep 1

  # Register some logs
  echo "Os testes estao em $pathtest/$name" | tee -a "$tolog"
  sleep 1

  # Zip files!
  sleep 1
  zip -r "$zipfiles/$name.zip" "$pathtest/$name"

  sleep 1

  # Change permissions
  chmod 777 -R "$pidfile"

  # Remove old Files
  find "$vuln0" -type f -mtime +3 -delete

  find "$pathtest" -type d -mtime +3 -exec rm -rf {} \;
  find "$pathtest" -type d -empty -delete
  
  find "$zipfiles" -type f -mtime +15 -delete

  # Send message with attachments
  sleep 1

  tontfy=$(cat /Data/ntfysh)
  [ "$tontfy" == "0" ] && {
    echo "." > /dev/null
  } || {
    [ -d "$vuln0" ] && {
      curl -u admin:5V06auso -T "$zipfiles"/$name.zip -H "Filename: $name.zip" "$ntfysh"/"$namepan"
    } || {
      echo "Nenhuma vulnerabilidade encontrada!" > /dev/null
    }
  }

exit 1
}

# SUDO check!?
[ "$EUID" -ne 0 ] && {
  echo "Execute esse script como Root! Saindo..."
  exit
  } || {
    echo "." > /dev/null
    }

# Start all here
init

exit 1
