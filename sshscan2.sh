#!/bin/sh

# Prueba servicio ssh y extrea la version
# Lee IPs de ip.txt y ejecuta nxc ssh
# hackingyseguridad.com 2026

while IFS= read -r IP; do
    if [ -n "$IP" ]; then
        nxc ssh "$IP"
    fi
done < ip.txt
