#!/bin/sh

# Genera para fuerza bruta listado con credenciales en base64

USERNAME_WORDLIST="usuarios.txt"
PASSWORD_WORDLIST="claves.txt"

while IFS= read -r user
do
    while IFS= read -r password
    do
        printf "%s:%s" "$user" "$password" |base64
    done < "$PASSWORD_WORDLIST"
done < "$USERNAME_WORDLIST"
