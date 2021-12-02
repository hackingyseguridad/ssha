#!/bin/bash
echo $1 "<======================"
ncrack $1 -p 22 -U usuarios.txt -P claves.txt
