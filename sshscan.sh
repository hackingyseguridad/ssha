# 
#
#EXTRAER VERSION DE SSH EN LOCAL Y REMOTO
#
#En local:
#
#ssh -V 
#sshd -V
#
#En remoto:
#nmap -Pn -p 22 -sV --script=ssh-run IP
#
#sleep 1 telnet IP 22
#
#python ssh-audit.py -1 IP #https://github.com/arthepsy/ssh-audit
#
# Extrae fingerprint version SSH, en fichero ip.txt
# hackingyseguridad.com 
# sleep 1 telnet IP puerto 
#
#!/bin/sh

for n in `cat ip.txt`; do echo $n; timeout --signal=9 2 telnet $n 22 |grep SSH; done
