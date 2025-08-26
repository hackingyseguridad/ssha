
## Vulnerabilidades SSH 

La primera vulnerabilidad, la que permite un ataque Man-in-the-Middle, ha sido registrada como CVE-2025-26465. Es muy antigua, puesto que está presente desde finales de 2014, hace ya más de 10 años. Apareció con el lanzamiento de OpenSSH 6.8p1. Hasta ahora no ha sido detectado el problema. Si la opción VerifyHostKeyDNS está habilitada, permite a un atacante lanzar este tipo de ataque.

CVE-2025-26466 OpenSSH 9.5p1, agosto de 2023. Fallo de denegación de servicio. Ocurre durante el intercambio de claves, debido a una asignación de memoria sin restricciones. 

## Utilidades de explotacion SSH 

<img style="float:left" alt="netspy logo" src="https://github.com/hackingyseguridad/ssha/blob/master/ssh.png">

## sshd_config

Configuracion segura del servidor SSHd

https://raw.githubusercontent.com/hackingyseguridad/ssha/master/configuracion.txt

## ssha.sh

ssha usuario@IP  opciones del cliente para cifrados obsoletos, single method diffie-hellman-group1-sha1

sshb opciones del cliente para cifrados obsoletos

sshc opciones del cliente para cifrados obsoletos

https://www.openssh.com/legacy.html

## sshscan.sh

Escanea puertos SSH accesibles

## Comandos SSH habituales

1. Conexión SSH estándar

ssh -p 3000 usuario@hostIP

2. Autenticación mediante clave SSH

ssh -i/path/to/private-key usuario@hostIP

3. Ejecución de comandos remotos

ssh usuario@hostIP "ls -la"

4. Reenvío de puertos

ssh -L <local-port>:<hostIP1>:<remote-port> usuario@hostIP2

5. Conexión a través de un servidor intermedio

ssh -J bob@hostIP1:port1 usuario@hostIP2

6. Copia de la clave pública SSH

ssh-copy-id -i /path/to/public-key usuario@hostIP

7. Conexión con opciones personalizadas

ssh -F /path/to/ssh_config usuario@hostIP

8. Reenvío de puertos con direcciones locales

ssh -FN -R <remote-port>:localhost:22 usuario@hostIP

9. Transferencia de directorios mediante SSH

scp -rP 3000  /path/to/local-dir usuario@hostIP:/path/to/remote-dir

## scanciphers.sh

Muestra los cifrados ofrecidos

<img style="float:left" alt="netspy logo" src="https://github.com/hackingyseguridad/ssha/blob/master/SSH.png">

## usuariossh.py

Comprueba existencia de usuario en ip con SSH activo.
Explotar vulnerabilidad 2018-15473 OpenSSH 2.3 < 7.7 Username Enumeration.

## sshusers.sh

Muestra usuarios existentes en SSH, con diccionario usuarios.txt. 
Explotar vulnerabilidad 2018-15473 OpenSSH 2.3 < 7.7 Username Enumeration

## brutessh.sh

sh brutessh.sh IP 

Test para intentar obtener credenciales de acceso a SSH con diccionario usuarios.txt y claves.txt


http://www.hackingyseguridad.com/





