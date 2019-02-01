#!/bin/bash
# source <(curl -s https://raw.githubusercontent.com/aerissecure/nse/master/install.sh)

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

git clone https://github.com/aerissecure/nse /tmp/nse

install -m 644 "/tmp/nse/*.nse" /usr/share/nmap/scripts
install -m 644 "/tmp/nse/data/*" /usr/share/nmap/nselib/data

nmap --script-updatedb
