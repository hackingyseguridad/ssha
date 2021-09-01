#!/bin/sh

if [ "$#" -ne 2 ]; then
    printf "Usage: %s usuarios.txt claves.txt\n" "$0" >&2
    exit 1
fi

if ! [ -f "$1" ]; then
    printf "%s file not found.\n\n" "$1" >&2
    printf "Usage: %s claves.txt s.txt\n" "$0" >&2
    exit 1
fi

if ! [ -f "$2" ]; then
    printf "%s file not found.\n\n" "$2" >&2
    printf "Usage: %s usuarios.txt claves.txt\n" "$0" >&2
    exit 1
fi

USERNAME_WORDLIST="$1"
PASSWORD_WORDLIST="$2"
USERNAME_WORDLIST_SIZE=$(wc -l "$USERNAME_WORDLIST" |awk '{print $1;}')
PASSWORD_WORDLIST_SIZE=$(wc -l "$PASSWORD_WORDLIST" |awk '{print $1;}')
OUTPUT_WORDLIST_SIZE=$((USERNAME_WORDLIST_SIZE * PASSWORD_WORDLIST_SIZE))

printf "\nGenerating HTTP basic authentication strings. This can take a while depending on the length of user and password lists.\n\n" >&2
printf "Usernames: %s\n" "$USERNAME_WORDLIST_SIZE" >&2
printf "Passwords: %s\n" "$PASSWORD_WORDLIST_SIZE" >&2
printf "Total combinations: %s\n\n" "$OUTPUT_WORDLIST_SIZE" >&2

while IFS= read -r user
do
    while IFS= read -r password
    do
        printf "%s:%s" "$user" "$password" |base64
    done < "$PASSWORD_WORDLIST"
done < "$USERNAME_WORDLIST"
