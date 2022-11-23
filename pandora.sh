#!/bin/bash

# Project Pandora ##############################################################
############################################################## By Nathan Drake #

################################################################################
#                                                                              #
# Dependencies:                                                                #
# parallel nmap metasploit mutt ntp cyrus-common iproute2 zip sendmail         #
# apt purge postfix                                                            #
# Do not forget about /root/.mutt!                                             #
#                                                                              #
################################################################################

# Name for this Pandora device.
namepan=$(cat /Data/hostname)

# How much parallel jobs will run at time.
RUNA=$(cat /Data/runa)

# ntfy server:
ntfysh=$(cat /Data/ntfysh)

################################################################################

# Custom path for PENTESTS results
pathtest="/Pentests/PENTESTS"

# Custom path for ZIPPED files from results.
zipfiles="/Pentests/ZIP"

# SUDO check!?
[ "$EUID" -ne 0 ] && {
  echo "Run this script as Root! Exiting..."
  exit
  } || {
    echo "Nothing" > /dev/null
    }

function init {
  # Kill nmap after X seconds if hang!
  sleep 1800 && pkill nmap & echo $! | tee /Pentests/.pndr.pid

  # Set some vars
  datetime=$(date +"%d/%m %H:%M")
  name=$(date +"%d%m%y-%H%M%S")
  vuln0="$pathtest/$name/VULN"

  # Create main dir, if it does not exist
  mkdir -p "$zipfiles/$name/VULN"
  mkdir -p "$pathtest/$name"

  # Generate some Files and Vars
  touch "$pathtest/$name/01IP"; toip="$pathtest/$name/01IP"
  touch "$pathtest/$name/02Log"; tolog="$pathtest/$name/02Log"

  # Some logs
  echo "Test started at $datetime!" | tee -a "$tolog"

  # Generate IPs to analyze:
  nmap -e "$rede" -n -sn $(hostname -I | awk '{print $1}')"/24" | grep report | awk '{print $5}' | tee "$toip"

  # Calculate remaining time:
  lres=$( wc -l < "$toip" )
  echo "We found "$lres" IPs to analyze." | tee -a "$tolog"

  # Do RUNA jobs at time!
  cat "$toip" | parallel -j "$RUNA" -k "nmap -Pn --script vuln {} | tee -a $pathtest/$name/{}"

  # When finished
  datetime2=$(date +"%d/%m %H:%M")

  # Just some last logs to finish this.
  echo "This test ran from $datetime to $datetime2." | tee -a "$tolog"

  # Kill NMAP killer!
  pidsleep=$(cat /Pentests/.pndr.pid)
  echo "Killing PID $pidsleep of sleep_&_auto_kill nmap process" | tee -a "$tolog" 
  kill -9 "$pidsleep"
  pkill sleep
  rm "/Pentests/.pndr.pid"

  # Identify if there is any VULNERABLE!
  while read line
  do
    grep -Fq "VULNERABLE" "$pathtest/$name/$line" && mkdir -p "$vuln0" && mv "$pathtest/$name/$line" "$vuln0" || echo "Nothing found!" > /dev/null
  done < "$toip"
  sleep 1

  # Register some logs
  echo "Changed permissions." | tee -a "$tolog"
  echo "Zipped files." | tee -a "$tolog"
  echo "Files are stored under $pathtest/$name" | tee -a "$tolog"
  sleep 1

  # Zip files!
  sleep 1
  zip -r "$zipfiles/$name.zip" "$pathtest/$name"

  [ -d "$vuln0" ] && {
    mkdir -p "$zipfiles/$name"
    zip -r "$zipfiles/$name/VULN.zip" "$vuln0"
  } || {
    echo "No VULN found!" | tee -a "$tolog"
  }

  sleep 1

  # Change permissions
  chmod 777 -R "$pathtest"

  # Send message with attachments
  sleep 1

  curl -u admin:5V06auso -T $zipfiles/$name.zip -H "Filename: $name.zip" "$ntfysh"/"$namepan"

exit 1
}

# Start all here
init

exit 0
