#!/bin/bash
echo "@reboot /pandora.sh >> /var/log/cron.log 2>&1
0 12,19 * * * /pandora.sh >> /var/log/cron.log 2>&1
# This extra line makes it a valid cron!" > scheduler.txt
crontab scheduler.txt
cron -f
