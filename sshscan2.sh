#!/bin/sh

# Prueba servicio ssh y extrea la version
# Lee IPs de ip.txt y ejecuta nxc ssh
# hackingyseguridad.com 2026

for n in `cat ip.txt`; do echo; timeout 22 nxc ssh $n ; done
