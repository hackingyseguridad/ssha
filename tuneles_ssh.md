

/usr/bin/ssh -y -y 

# Opciones de conexion

-o ExitOnForwardFailure=yes		# Si falla el reenvío de puertos la conexión SSH se cerrara

-o UserKnownHostsFile=/dev/null		# Se ignopra el fichero donde se guardan las claves publicas

-o StrictHostKeyChecking=no		# Desactiva la verificación estricta de las claves del host

# Conexion

usuario@host.com -p 65535 -i /root/.ssh/id_dropbear  # El puerto en el servidor remoto al que se conecta y La clave privada SSH utilizada para autenticarse en el servidor remoto

-L8181:localhost:44444		# el tráfico que llega al puerto 8181 de tu máquina local se reenvía al puerto 44444 del servidor remoto

-R 38001:localhost:80		# el puerto 38001 del servidor remoto se reenvía al puerto 80 de tu máquina local

-R 38002:localhost:22		#

-R 38003:192.168.250.100:443	#

-R 38004:192.168.250.100:22	#

-L 4444:localhost:27080  	# tráfico del puerto 4444 local se reenvía al 27080 del servidor
