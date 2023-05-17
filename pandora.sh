#!/bin/bash

###################
# Project Pandora #
################################################################################

# Name for this Pandora device.
namepan=$(cat /Data/hostname)

# ntfy server:
ntfysh=$(cat /Data/ntfysh)

# How much parallel jobs will run at time.
RUNA=$(cat /Data/runa)

# PID FILE
pidfile="/Pentests"

################################################################################

function init {
  # Kill nmap after X seconds if hang!
  sleep 1800 && pkill nmap & echo $! | tee "$pidfile"/.pndr.pid

  # Set some vars
  datetime=$(date +"%d/%m/%y %H:%M")
  name=$(date +"%d_%m_%y-%H:%M")

  # Create main dir, if it does not exist
  mkdir -p "$zipfiles"
  mkdir -p "$pathtest"/"$name"

  # Generate some Files and Vars
  touch "$pathtest"/"$name"/01IP; toip="$pathtest"/"$name"/01IP
  touch "$pathtest"/"$name"/02Log; tolog="$pathtest"/"$name"/02Log

  # Some logs
  echo "Test started at $datetime!" | tee -a "$tolog"

  # Generate IPs to analyze:
  nmap -e "$rede" -n -sn $(hostname -I | awk '{print $1}')"/24" | grep report | awk '{print $5}' | tee "$toip"

  # Calculate remaining time:
  lres=$( wc -l < "$toip" )
  echo "We found "$lres" IPs to analyze." | tee -a "$tolog"

  # Do RUNA jobs at time!
  # Exclude 9100 because of printers!
  cat "$toip" | parallel -j "$RUNA" -k "nmap -Pn --script vuln --exclude 9100 -p1-9099,9101-65535 {} | tee -a $pathtest/$name/{}"

  # When finished
  datetime2=$(date +"%d/%m/%y %H:%M")

  # Just some last logs to finish this.
  echo "This test ran from $datetime to $datetime2." | tee -a "$tolog"

  # Kill NMAP killer!
  pidsleep=$(cat $pidfile/.pndr.pid)
  echo "Killing PID $pidsleep of sleep_&_auto_kill nmap process" | tee -a "$tolog" 
  kill -9 "$pidsleep"
  pkill sleep
  rm "$pidfile"/.pndr.pid

  # Identify if there is any VULNERABLE system!
  while read line
  do
    grep -Fq "VULNERABLE" "$pathtest/$name/$line" && mkdir -p "$vuln0" && cp "$pathtest/$name/$line" "$vuln0" || echo "Nothing found!" > /dev/null
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

  sleep 1

  # Change permissions
  chmod 777 -R "$pathtest"

  # Remove old Files
  find "$zipfiles" -type d -mtime +30 -exec rm -rf {} \;
  find "$zipfiles" -type f -mtime +30 -delete
  find "$zipfiles" -type d -empty -delete

  find "$pathtest" -type d -mtime +30 -exec rm -rf {} \;
  find "$pathtest" -type f -mtime +30 -delete
  find "$pathtest" -type d -empty -delete

  # Send message with attachments
  sleep 1

  tontfy=$(cat /Data/ntfysh)
  [ "$tontfy" == "0" ] && {
    echo "The End!" > /dev/null
  } || {
    [ -d "$vuln0" ] && {
      curl -u admin:5V06auso -T "$zipfiles"/$name.zip -H "Filename: $name.zip" "$ntfysh"/"$namepan"
    } || {
      echo "There's none VULNERABLE detected!" > /dev/null
    }
  }

exit 1
}

# SUDO check!?
[ "$EUID" -ne 0 ] && {
  echo "Run this script as Root! Exiting..."
  exit
  } || {
    echo "Nothing" > /dev/null
    }

# Vulnerable Systems!
vuln0="$pidfile/VULNERABLE_SYSTEMS"

# Custom path for PENTESTS results
pathtest="$pidfile/PENTESTS"

# Custom path for ZIPPED files from results.
zipfiles="$pidfile/ZIP"

# Start all here
init

exit 1
