


# configuramos en local en etc/proxychains.conf socks4  127.0.0.1 9050

ssh -f admin@SALTO -L 9050:localhost:222 -N 

sudo nmap 192.168.1.1 -Pn -v --proxy socks4://127.0.0.1:9050 -sTV -F -reason
