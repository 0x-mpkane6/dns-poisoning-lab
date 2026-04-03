#!/bin/bash

if [ "$1" == "on" ]; then
cat > /etc/unbound/unbound.conf << EOL
server:
    interface: 0.0.0.0
    access-control: 0.0.0.0/0 allow

    use-caps-for-id: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    qname-minimisation: yes
EOL
echo "[+] Defense ON"
else
cat > /etc/unbound/unbound.conf << EOL
server:
    interface: 0.0.0.0
    access-control: 0.0.0.0/0 allow

    use-caps-for-id: no
    harden-glue: no
    harden-dnssec-stripped: no
    qname-minimisation: no
EOL
echo "[+] Defense OFF"
fi

pkill unbound
unbound -d &
