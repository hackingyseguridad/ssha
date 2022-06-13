# ejecutar comando en remoto!
# ssh admin@localhost -p 22 "/usr/bin/uname"
# ssh admin@localhost -p 22 "sudo -S /usr/bin/uname"

ssh usuario@IP -echo "nameserver 127.0.0.1" > /etc/resolv.conf
