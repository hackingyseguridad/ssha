
#!/bin/sh
# hacking y seguridad .COM 2023
echo "Instalando .."
echo
apt-get install ncrack
apt-get install medusa
apt-get install nmap
cp ssha /sbin
chmod 777 /sbin/ssha
cp sshb /sbin
chmod 777 /sbin/sshb
cp sshc /sbin
chmod 777 /sbin/sshc

