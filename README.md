
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

### 6. 


## 7. CVE-2021-41617 (OpenSSH 8.5p1) 7.8 (Alto) 
Elevación de privilegios. Privesc a través de sshd. Compleja de explotar

## 8. CVE-2019-16905 (2019)
- **CVSS:** 6.8 (Medio)
- **Tipo:** Denegación de servicio
- **Impacto:** Crash del servicio SSH
- **Facilidad:** Fácil de explotar
- **Afecta:** OpenSSH 7.7 - 7.9

## 9. CVE-2020-14145 (2020)
- **CVSS:** 4.3 (Medio)
- **Tipo:** Filtración de información
- **Impacto:** Revela información del servidor
- **Facilidad:** Fácil
- **Afecta:** OpenSSH hasta 8.3

## 10. CVE-2018-15919 (2018)
- **CVSS:** 5.3 (Medio)
- **Tipo:** Denegación de servicio
- **Impacto:** Crash del servicio SSH
- **Facilidad:** Moderadamente fácil
- **Afecta:** OpenSSH 7.8


¿Necesitas detalles específicos sobre alguna de estas vulnerabilidades o medidas de mitigación particulares?



CVE-2025-26465. Es muy antigua, de finales de 2014, OpenSSH 6.8p1. Si la opción VerifyHostKeyDNS está habilitada, permite a un atacante lanzar este tipo de ataque.

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





