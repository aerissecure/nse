#!/bin/bash
# source <(curl -s https://raw.githubusercontent.com/aerissecure/nse/master/install.sh)

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

DIR=$(mktemp -d)

git clone https://github.com/aerissecure/nse "$DIR"

install -m 644 "$DIR"/*.nse  /usr/share/nmap/scripts
install -m 644 "$DIR"/data/* /usr/share/nmap/nselib/data

nmap --script-updatedb

rm -rf "$DIR"