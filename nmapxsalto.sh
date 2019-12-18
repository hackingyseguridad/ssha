#!/bin/bash
#nmap a traves de una maquina de salto
#MiPC----PCSALTO----OBJETIVO
# configuramos en local en etc/proxychains.conf socks4  127.0.0.1 9050

ssh -f admin@SALTO -L 9050:localhost:222 -N 
sudo nmap OBJETIVO -Pn -v --proxy socks4://127.0.0.1:9050 -sTV -F -reason
sudo proxychains -q nmap -Pn OBJETIVO -sTV -reason
