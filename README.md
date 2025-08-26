
## top 10 vulnerabilidades SSH 

### 1. CVE-2024-6387 - "regreSSHion" ( OpenSSH 8.5p1 - 9.7p1) 9.8 (Crítico) 
Ejecución remota de código, permite RCE como root. Explotación relativamente sencilla.

### 2. CVE-2018-15473 (OpenSSH 7.7 y anteriores) 5.3 (Medio)
Filtración de información. Revela nombres de usuario válidos. Muy fácil de explotar. 

### 3. CVE-2016-0777 (OpenSSH 5.4 - 7.1) 4.0 (Medio)
Filtración de información. Filtra hasta 64KB de memoria del cliente.  Explotación sencilla

### 4. CVE-2020-15778 (OpenSSH hasta 8.3p1)  6.8 (Medio) 
Ejecución de código. Ejecución arbitraria en el cliente. Moderadamente fácil de explotar

### 5. CVE-2019-6111 (OpenSSH hasta 7.9) 5.7 (Medio)
Sobrescritura de archivos. Permite sobrescribir archivos arbitrarios. Requiere interacción del usuario

### 6. CVE-2023-38408 (OpenSSH versiones específicas) 5.9 (Medio)
Elevación de privilegios. Impacto: Privesc en sistemas específicos. Facilidad: Compleja de explotar

### 7. CVE-2021-41617 (OpenSSH 8.5p1) 7.8 (Alto) 
Elevación de privilegios. Privesc a través de sshd. Compleja de explotar

### 8. CVE-2019-16905 (OpenSSH 7.7 - 7.9) 6.8 (Medio)
Denegación de servicio. Crash del servicio SSH. Fácil de explotar

### 9. CVE-2020-14145 (OpenSSH hasta 8.3) 4.3 (Medio)
Filtración de información. Revela información del servidor. Fácil

### 10. CVE-2018-15919 (OpenSSH 7.8) 5.3 (Medio) 
Denegación de servicio. Crash del servicio SSH.  Moderadamente fácil de explotar
 
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





