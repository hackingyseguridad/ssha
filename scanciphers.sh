#!/bin/bash 
 echo "Uso.: ./scanciphers.sh IP_ssh"
 nmap $1 -Pn -p 22 --script ssh2-enum-algos
