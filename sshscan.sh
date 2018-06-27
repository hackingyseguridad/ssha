# 
# Extrae fingerprint version SSH, en fichero ip.txt
# hackingyseguridad.com 
# sleep 1 telnet IP puerto 
#
#!/bin/sh

for n in `cat ip.txt`; do echo $n; timeout --signal=9 2 telnet $n 22 |grep SSH; done
