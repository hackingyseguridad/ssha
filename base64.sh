#!/bin/sh

# Genera listado con credenciales en base64,  para ataques de fuerza bruta

USERNAME_WORDLIST="usuarios.txt"
PASSWORD_WORDLIST="claves.txt"

while IFS= read -r user
do
    while IFS= read -r password
    do
            credencial=$(printf "%s:%s" "$user" "$password" |base64 )
    echo $credencial
    done < "$PASSWORD_WORDLIST"
done < "$USERNAME_WORDLIST"
