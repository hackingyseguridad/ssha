#!/bin/bash
# nmap a traves de una maquina de salto
# MiPC ----- PCSALTO ----- OBJETIVO
# configuramos en local en etc/proxychains.conf socks4  127.0.0.1 9050
# SALTO = IP maquina de salto
# OBJETIVO = IP maquina objetivo a traves de salto

ssh -N -f admin@SALTO -L 127.0.0.1:9050:OBJETIVO:22 -N
sudo nmap OBJETIVO -Pn -v --proxy socks4://127.0.0.1:9050 -sTV -F -reason
sudo proxychains nmap OBJETIVO -q -Pn -sTV -reason
