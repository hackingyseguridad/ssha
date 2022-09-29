#!/usr/bin/env bash
echo 
echo "... actualizando diccionarios ...   2022 hackingyseguridad.com "
chmod 777 *
echo ".."
wget https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master/diccionario.txt -q -O diccionario.txt
echo "diccionario.txt"
echo ".."
wget https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master/usuarios.txt -q -O usuarios.txt
echo "usuarios.txt"
echo ".."
wget https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master/usuarios0.txt -q -O usuarios0.txt
echo "usuarios0.txt"
echo ".."
wget https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master/claves.txt -q -O claves.txt
echo "claves.txt"
echo ".."
wget https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master/claves2.txt -q -O claves2.txt
echo "claves2.txt"
echo ".."
wget https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master/claves0.txt -q -O claves0.txt
echo "claves0.txt"
echo ".."
echo "..."
echo "...."
echo "..... fin!"
echo
