
#!/bin/bash
#
# conectar a SSH en una sola linea con sshpass
#
# apt install sshpass
#
# hackingyseguridad.com (2025)
#

user=admin
pass=Password01

IP=192.168.1.200
PORT=22

sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p $PORT $user@$IP


