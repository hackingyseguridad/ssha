#!/bin/bash
# Fuerza bruta con diccionarios a Telnet
nmap -p 23 --script telnet-brute --script-args userdb=usuarios.txt,passdb=claves.txt,telnet-brute.timeout=8s $1
