#!/bin/bash
set -euo pipefail

# v0.9.39: Docker entrypoint with fail-closed egress enforcement
EGRESS_MODE="${PHANTOM_EGRESS_ENFORCEMENT:-strict}"

if [ "$EGRESS_MODE" = "strict" ]; then
    echo "[PHANTOM] Applying fail-closed egress rules..."

    # Verify iptables is available
    if ! command -v iptables &>/dev/null; then
        echo "[FATAL] iptables not available — cannot enforce egress policy"
        exit 1
    fi

    # Flush existing OUTPUT rules
    iptables -F OUTPUT 2>/dev/null || true

    # Default: DROP all outbound
    iptables -P OUTPUT DROP

    # Allow loopback (tool server ↔ tools)
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established connections
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow DNS to Docker internal resolver only
    DOCKER_DNS=$(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}')
    iptables -A OUTPUT -d "$DOCKER_DNS" -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d "$DOCKER_DNS" -p tcp --dport 53 -j ACCEPT

    # Block external DNS
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP

    # Allow HTTP/HTTPS (scanning)
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

    # Allow common service ports for scanning
    iptables -A OUTPUT -p tcp --dport 21:25 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 3306 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 5432 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 8080:8090 -j ACCEPT

    # Allow ICMP
    iptables -A OUTPUT -p icmp -j ACCEPT

    # Log and drop everything else
    iptables -A OUTPUT -j LOG --log-prefix "[PHANTOM_EGRESS_DENIED] " --log-level 4
    iptables -A OUTPUT -j DROP

    echo "[PHANTOM] Egress enforcement: ACTIVE"
else
    echo "[PHANTOM] Egress enforcement: PERMISSIVE"
fi

# Execute the actual command
exec "$@"
