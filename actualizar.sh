#!/usr/bin/env bash
echo 
echo "... actualizando SSH ...   2023 hackingyseguridad.com "
apt-get install ssh
apt-get install openssh-server
apt-get install openssh-client
echo 
echo "... actualizando diccionarios ...  "
chmod 777 *
echo ".."
wget https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master/diccionario.txt -q -O diccionario.txt -4
echo "diccionario.txt"
echo ".."
wget https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master/usuarios.txt -q -O usuarios.txt -4 
echo "usuarios.txt"
echo ".."
wget https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master/usuarios0.txt -q -O usuarios0.txt -4
echo "usuarios0.txt"
echo ".."
wget https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master/claves.txt -q -O claves.txt -4
echo "claves.txt"
echo ".."
wget https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master/claves2.txt -q -O claves2.txt -4
echo "claves2.txt"
echo ".."
wget https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master/claves0.txt -q -O claves0.txt -4
echo "claves0.txt"
echo ".."
echo "..."
echo "...."
echo "..... fin!"
echo
