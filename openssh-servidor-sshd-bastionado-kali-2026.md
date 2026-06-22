# Guía Completa de Bastionado Seguro del Servidor OpenSSH (sshd) en Kali Linux (2026)

*Mantenida por [hackingyseguridad.com](https://hackingyseguridad.com) — Pentesting y seguridad ofensiva, Madrid.*
*Referencia canónica: https://github.com/hackingyseguridad/ssha*

---

## Índice

1. [Modelo de seguridad del servidor sshd en Kali Linux](#1-modelo-de-seguridad-del-servidor-sshd-en-kali-linux)
2. [Gestión de claves del servidor: Ed25519 y eliminación de RSA/DSA débiles](#2-gestión-de-claves-del-servidor-ed25519-y-eliminación-de-rsadsa-débiles)
3. [Autenticación: solo clave pública, prohibir contraseñas](#3-autenticación-solo-clave-pública-prohibir-contraseñas)
4. [Cifrados, KEX y MACs seguros: auditoría y configuración](#4-cifrados-kex-y-macs-seguros-auditoría-y-configuración)
5. [Control de acceso: usuarios, grupos, TCP Wrappers y cortafuegos (UFW)](#5-control-de-acceso-usuarios-grupos-tcp-wrappers-y-cortafuegos-ufw)
6. [Bastionado del servicio: puerto, port knocking, banner, timeouts y límites](#6-bastionado-del-servicio-puerto-port-knocking-banner-timeouts-y-límites)
7. [Protección contra fuerza bruta: sshguard y fail2ban en Kali](#7-protección-contra-fuerza-bruta-sshguard-y-fail2ban-en-kali)
8. [Opciones avanzadas: chroot, rhosts y desactivación del servidor en el cliente](#8-opciones-avanzadas-chroot-rhosts-y-desactivación-del-servidor-en-el-cliente)
9. [Caso práctico: CVE-2024-6387 regreSSHion — verificación y mitigación](#9-caso-práctico-cve-2024-6387-regresshion--verificación-y-mitigación)
10. [Verificación del bastionado con ssh-audit y herramientas del repositorio ssha](#10-verificación-del-bastionado-con-ssh-audit-y-herramientas-del-repositorio-ssha)
11. [Lista de verificación: 20 directivas para sshd_config](#11-lista-de-verificación-20-directivas-para-sshd_config)
12. [Preguntas frecuentes](#12-preguntas-frecuentes)

---

## Introducción

SSH es el primer servicio que atacan los escáneres automáticos en cualquier máquina expuesta a Internet. La conversación habitual sobre bastionado SSH se centra en el cliente (`ssh_config`), pero **el lado servidor es el objetivo real**. Un `sshd_config` mal configurado es la diferencia entre una máquina de pentesting y una máquina comprometida.

En Kali Linux, el servidor SSH tiene particularidades importantes frente a Ubuntu o Debian:

- **Kali instala `openssh-server` con credenciales heredadas** (`kali/kali`) que deben cambiarse antes de cualquier exposición en red.
- **El servicio sshd está desactivado por defecto** en Kali — hay que activarlo explícitamente.
- **Kali actualiza OpenSSH con mayor frecuencia** al ser una distribución *rolling release*, lo que facilita mantener versiones parcheadas.

Los tres errores más habituales en auditorías de servidores SSH son:

- Autenticación por contraseña activa, incluyendo para root.
- Algoritmos de intercambio de claves y cifrado heredados que aceptan conexiones de clientes obsoletos.
- Sin protección activa contra fuerza bruta.

**Kali Linux 2024.x incluye OpenSSH 9.7p1 o superior**, con soporte para intercambio de claves post-cuántico, algoritmos modernos y parches frente a CVE-2024-6387 (regreSSHion) desde el 1 de julio de 2024.

---

## 1. Modelo de seguridad del servidor sshd en Kali Linux

El servidor OpenSSH en Kali Linux pertenece al paquete `openssh-server`. A diferencia de Ubuntu, en Kali el servicio no arranca automáticamente tras la instalación:

```bash
# Comprobar versión instalada
ssh -V
# OpenSSH_9.x, OpenSSL x.x.x

# Ver la configuración activa del servidor
cat /etc/ssh/sshd_config

# Activar y arrancar el servicio
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl status ssh
```

### Ficheros de configuración relevantes

| Fichero | Descripción |
|---|---|
| `/etc/ssh/sshd_config` | Configuración principal del servidor |
| `/etc/ssh/sshd_config.d/*.conf` | Fragmentos de configuración (incluidos desde sshd_config) |
| `/etc/ssh/ssh_host_*` | Claves del bastión (host keys) |
| `/etc/issue.net` | Banner legal mostrado antes de la autenticación (SSH remoto) |
| `/etc/issue` | Banner legal mostrado en consola local |
| `/etc/hosts.allow` | Acceso permitido — TCP Wrappers |
| `/etc/hosts.deny` | Acceso denegado — TCP Wrappers |
| `/etc/sshguard/sshguard.conf` | Configuración de sshguard |
| `/etc/knockd.conf` | Configuración de port knocking |

### La cadena de seguridad del servidor

La seguridad del servidor SSH es una cadena con cinco eslabones. Romper cualquiera invalida el conjunto:

| Eslabón | Descripción |
|---|---|
| **Claves del bastión** | Algoritmos y longitud de las host keys del servidor |
| **Autenticación** | Métodos permitidos: clave pública, contraseña, Kerberos... |
| **Criptografía del transporte** | KEX, cifrados y MACs negociados |
| **Control de acceso** | Usuarios, grupos, IPs, puertos y TCP Wrappers |
| **Protección activa** | fail2ban, sshguard, UFW, port knocking, límites de intentos |

---

## 2. Gestión de claves del servidor: Ed25519 y eliminación de RSA/DSA débiles

### Claves del bastión generadas por defecto

Al instalar `openssh-server`, Kali genera automáticamente las host keys:

```bash
ls -la /etc/ssh/ssh_host_*
# ssh_host_ecdsa_key      ssh_host_ecdsa_key.pub
# ssh_host_ed25519_key    ssh_host_ed25519_key.pub
# ssh_host_rsa_key        ssh_host_rsa_key.pub
```

> **Regla de 2026:** La clave RSA sigue generándose por compatibilidad, pero en un entorno controlado solo se necesitan Ed25519 y ECDSA (nistp256 mínimo). DSA ha sido eliminado de OpenSSH 10.0+.

### Regenerar las claves del bastión

Si el sistema lleva tiempo en producción o se sospecha que las host keys han sido expuestas:

```bash
# Eliminar claves existentes
sudo rm /etc/ssh/ssh_host_*

# Regenerar solo los algoritmos modernos
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
sudo ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N ""
# RSA solo si se necesita compatibilidad con clientes heredados
sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""

# Ajustar permisos
sudo chmod 600 /etc/ssh/ssh_host_*_key
sudo chmod 644 /etc/ssh/ssh_host_*_key.pub

# Reiniciar para cargar las nuevas claves
sudo systemctl restart ssh
```

### Restricción de tipos de clave en sshd_config

```
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key
# HostKey /etc/ssh/ssh_host_rsa_key  ← comentar si no se necesita compatibilidad
```

### Publicar huellas dactilares en DNS (registros SSHFP)

Para que los clientes puedan verificar la autenticidad del servidor sin pasar por TOFU:

```bash
# Generar los registros DNS SSHFP
ssh-keygen -r $(hostname)

# Salida ejemplo:
# host.dominio.com IN SSHFP 4 2 <huella_ed25519_sha256>
# host.dominio.com IN SSHFP 3 2 <huella_ecdsa_sha256>
```

---

## 3. Autenticación: solo clave pública, prohibir contraseñas

Esta es la medida de bastionado con mayor impacto. La autenticación por contraseña es el vector de entrada de prácticamente todos los ataques de fuerza bruta automatizados.

### Criterio para contraseñas seguras

Aunque el objetivo es eliminar la autenticación por contraseña, las cuentas del sistema deben tener contraseñas robustas como segunda línea de defensa. Criterio mínimo recomendado:

- **Longitud mínima: 10 caracteres** — ideal 16 o más
- Al menos una letra en mayúscula
- Al menos dos caracteres numéricos
- Ejemplo aceptable: `PonFerrada563245`

```bash
# Cambiar contraseña del usuario kali (obligatorio antes de exponer el servicio)
passwd kali
```

### Crear y distribuir claves de usuario

```bash
# En el CLIENTE — generar clave Ed25519
ssh-keygen -t ed25519 -C "pentest@hackingyseguridad.com" -f ~/.ssh/id_ed25519

# Copiar la clave pública al servidor
ssh-copy-id -i ~/.ssh/id_ed25519.pub usuario@<IP_SERVIDOR>

# O manualmente en el servidor
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-ed25519 AAAA..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### Directivas de autenticación en sshd_config

```
# Solo autenticación por clave pública
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Prohibir autenticación por contraseña
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# Prohibir autenticación vacía
PermitEmptyPasswords no

# Prohibir login directo de root
PermitRootLogin no

# Deshabilitar ficheros .rhosts — ver sección 8
IgnoreRhosts yes

# Deshabilitar autenticación basada en host
HostbasedAuthentication no

# Desactivar métodos no usados
GSSAPIAuthentication no
UsePAM yes
```

> **Importante en Kali:** Antes de desactivar la autenticación por contraseña, verificar que el acceso por clave funciona correctamente. Abrir una segunda sesión SSH por clave antes de cerrar la sesión actual.

---

## 4. Cifrados, KEX y MACs seguros: auditoría y configuración

### Auditar qué algoritmos ofrece el servidor actualmente

OpenSSH incluye el subcomando `-Q` para consultar los algoritmos disponibles en la instalación local:

```bash
# Ver cifrados disponibles
ssh -Q cipher

# Ver cifrados con autenticación integrada (AEAD)
ssh -Q cipher-auth

# Ver algoritmos MAC disponibles
ssh -Q mac

# Ver algoritmos de intercambio de claves (KEX)
ssh -Q kex

# Ver tipos de clave soportados
ssh -Q key
```

Estos comandos muestran todos los algoritmos compilados en OpenSSH. La configuración en `sshd_config` restringe cuáles se ofrecen realmente a los clientes.

Para ver la configuración activa del servidor (incluyendo valores por defecto no escritos en el fichero):

```bash
sudo sshd -T | grep -E "kexalgorithms|ciphers|macs|hostkeyalgorithms|pubkeyacceptedalgorithms"
```

### Intercambio de claves (KEX)

```
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
```

> **Nota sobre post-cuántico:** OpenSSH 9.x en Kali incluye `sntrup761x25519-sha512@openssh.com`. Si todos los clientes lo soportan, añadirlo al principio de la lista.

**Algoritmos KEX prohibidos en 2026:**

| Algoritmo | Motivo |
|---|---|
| `diffie-hellman-group1-sha1` | Logjam — roto en práctica |
| `diffie-hellman-group14-sha1` | SHA1 obsoleto |
| `diffie-hellman-group-exchange-sha1` | SHA1 obsoleto |

### Cifrados (Ciphers)

```
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
```

**Cifrados prohibidos:**

| Cifrado | Motivo |
|---|---|
| `aes128-cbc`, `aes256-cbc`, `3des-cbc` | Modos CBC vulnerables a BEAST y padding oracles |
| `arcfour`, `rc4` | RC4 roto criptográficamente |
| `blowfish-cbc`, `cast128-cbc` | Obsoletos, tamaño de bloque pequeño |

### Códigos de autenticación de mensaje (MACs)

```
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
```

**Preferir siempre los variantes `-etm`** (Encrypt-then-MAC). Los MACs sin `-etm` calculan el MAC sobre texto plano, lo que puede filtrar información.

**MACs prohibidos:**

| MAC | Motivo |
|---|---|
| `hmac-md5`, `hmac-md5-96` | MD5 roto |
| `hmac-sha1`, `hmac-sha1-96` | SHA1 obsoleto |
| `umac-64` | Longitud de tag insuficiente |

### Algoritmos de clave pública aceptados

```
PubkeyAcceptedAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256
```

Esto elimina `ssh-rsa` (SHA1) y `ssh-dss` (DSA).

---

## 5. Control de acceso: usuarios, grupos, TCP Wrappers y cortafuegos (UFW)

### Restringir qué usuarios pueden autenticarse

```
# Solo usuarios específicos
AllowUsers antonio admin pepe

# Bloquear usuarios específicos aunque tengan clave válida
DenyUsers root user administrador

# O gestionar por grupos (recomendado a escala)
# AllowGroups sshusers sudo
# DenyGroups nointeractive
```

### TCP Wrappers — `/etc/hosts.allow` y `/etc/hosts.deny`

TCP Wrappers es un sistema ACL de red basado en host que funciona como capa adicional independiente de `sshd_config`:

```bash
# Editar la lista de IPs permitidas
sudo vim /etc/hosts.allow
```

Contenido de `/etc/hosts.allow`:
```
# Solo estas IPs pueden conectar al servicio SSH
sshd: 192.168.1.2 172.16.23.12
sshd: 10.10.10.0/24
```

```bash
sudo vim /etc/hosts.deny
```

Contenido de `/etc/hosts.deny`:
```
# Denegar el resto
sshd: ALL
```

> **Nota:** TCP Wrappers evalúa `hosts.allow` primero. Si la IP no aparece en `hosts.allow`, se aplica `hosts.deny`. La combinación `hosts.allow` + `hosts.deny: ALL` es el patrón de listas blancas más seguro.

### Cortafuegos con UFW

UFW (Uncomplicated Firewall) permite restringir el acceso SSH por IP de origen a nivel de kernel, antes de que el tráfico llegue siquiera a sshd:

```bash
# Instalar UFW si no está presente
sudo apt install ufw -y

# Permitir SSH solo desde un rango de IPs de confianza
sudo ufw allow from 80.58.0.0/15 to any port 22

# O para un puerto personalizado
sudo ufw allow from 192.168.1.0/24 to any port 2222

# Denegar el resto de accesos SSH
sudo ufw deny 22

# Activar UFW
sudo ufw enable
sudo ufw status verbose
```

### Restricción por escucha en interfaz específica

```
# Escuchar solo en interfaz específica (no exponer en todas)
ListenAddress 192.168.1.10
# Para IPv4 e IPv6 específicas:
# ListenAddress 0.0.0.0
# ListenAddress ::
```

### Restricciones por bloque Match

La directiva `Match` permite aplicar configuraciones diferentes según usuario, grupo, IP o tipo de clave:

```
# Acceso completo solo desde red de gestión
Match Address 10.10.10.0/24
    PermitRootLogin prohibit-password
    AllowTcpForwarding yes

# Usuarios de solo SFTP, sin shell interactiva (chroot — ver sección 8)
Match Group sftp-only
    ChrootDirectory /data/sftp/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
```

---

## 6. Bastionado del servicio: puerto, port knocking, banner, timeouts y límites

### Puerto no estándar

Cambiar el puerto reduce drásticamente el ruido de bots en los registros, aunque **no es una medida de seguridad real** frente a un atacante que realice reconocimiento activo:

```
# Puerto no estándar — puede ser hasta 65535
Port 65535
```

> **Nota en Kali para pentesting:** Si la máquina actúa también como plataforma de ataque, mantener el puerto 22 facilita la interoperabilidad con scripts y herramientas del repositorio ssha. Valorar el contexto antes de cambiar el puerto.

### Port Knocking con knockd

Port knocking oculta el puerto SSH de forma que solo responde si previamente el cliente envía una secuencia específica de paquetes a puertos cerrados. Es una capa de oscuridad eficaz frente a escaneos automatizados:

```bash
# Instalar knockd
sudo apt install knockd -y

# Editar configuración
sudo vim /etc/knockd.conf
```

Ejemplo de `/etc/knockd.conf`:

```ini
[options]
    UseSyslog

[openSSH]
    sequence    = 7000,8000,9000
    seq_timeout = 5
    command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    tcpflags    = syn

[closeSSH]
    sequence    = 9000,8000,7000
    seq_timeout = 5
    command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    tcpflags    = syn
```

```bash
# Activar knockd
sudo systemctl enable knockd
sudo systemctl start knockd

# Desde el cliente: secuencia de "llamada" para abrir el puerto
knock <IP_SERVIDOR> 7000 8000 9000
ssh usuario@<IP_SERVIDOR>

# Secuencia de cierre para volver a ocultar el puerto
knock <IP_SERVIDOR> 9000 8000 7000
```

> **Importante:** Con port knocking activo, el puerto SSH aparece como cerrado en Nmap (`filtered`) para cualquier escáner que no conozca la secuencia.

### Banner legal

El banner se muestra **antes de la autenticación**, lo que tiene valor legal en caso de acceso no autorizado:

```
# En sshd_config
Banner /etc/issue.net
```

Contenido de `/etc/issue.net` (banner remoto SSH):

```
***************************************************************************
** HACKINGYSEGURIDAD.COM — ACCESO RESTRINGIDO                            **
** Queda prohibido cualquier acceso no autorizado a este sistema.        **
** Necesita tener autorización antes de usarlo, estando estrictamente    **
** limitado al uso indicado en dicha autorización.                       **
** El acceso no autorizado o el uso indebido está prohibido y es         **
** contrario a la legislación vigente.                                   **
** El uso que realice de este sistema puede ser monitorizado.            **
***************************************************************************
```

Contenido de `/etc/issue` (banner de consola local):

```
AVISO LEGAL: ha accedido a un sistema propiedad de HackingySeguridad.COM.
Necesita tener autorización antes de usarlo, estando estrictamente limitado
al uso indicado en dicha autorización.
El acceso no autorizado a este sistema o el uso indebido del mismo está
prohibido y es contrario a la legislación vigente.
El uso que realice de este sistema puede ser monitorizado.
```

### Timeouts y límites de conexión

```
# Tiempo máximo para completar la autenticación (segundos)
LoginGraceTime 30

# Número máximo de intentos de autenticación por conexión
MaxAuthTries 3

# Número máximo de sesiones simultáneas por conexión
MaxSessions 5

# Conexiones en estado de handshake pendiente: 10 intentos, 30% drop, máximo 60
MaxStartups 10:30:60

# Cerrar sesiones inactivas — enviar paquete cada 300 seg, sin respuesta = cerrar
ClientAliveInterval 300
ClientAliveCountMax 0
```

> **Nota sobre `ClientAliveCountMax 0`:** El valor 0 significa que si el cliente no responde al primer paquete de keepalive, la sesión se cierra inmediatamente. Es la configuración más estricta del repositorio ssha. En entornos con conexiones inestables, `ClientAliveCountMax 2` es más tolerante.

### Deshabilitar funcionalidades no necesarias

```
# Deshabilitar reenvío de agente en el servidor
AllowAgentForwarding no

# Deshabilitar reenvío X11
X11Forwarding no

# Deshabilitar reenvío TCP genérico (túneles)
AllowTcpForwarding no

# Deshabilitar reenvío de puertos remotos
GatewayPorts no

# Deshabilitar túnel TUN/TAP (VPN sobre SSH)
PermitTunnel no

# No permitir que el usuario modifique variables de entorno
PermitUserEnvironment no

# Ocultar versión del SO en el banner SSH
VersionAddendum none

# Deshabilitar impresión MOTD
PrintMotd no
PrintLastLog yes

# No usar DNS (evita retardos y posibles ataques DNS)
UseDNS no

# Desactivar compresión (previene ataques CRIME/BREACH)
Compression no
```

---

## 7. Protección contra fuerza bruta: sshguard y fail2ban en Kali

### sshguard

sshguard es más eficiente que fail2ban para SSH al leer directamente el socket del journal sin necesitar parsear ficheros de registro:

```bash
# Instalar sshguard
sudo apt install sshguard -y

# Configuración recomendada
sudo vim /etc/sshguard/sshguard.conf
```

Contenido de `/etc/sshguard/sshguard.conf` — configuración completa basada en el repositorio ssha:
```ini
# Referencia: https://raw.githubusercontent.com/hackingyseguridad/ssha/master/sshguard.conf
THRESHOLD=30
BLOCK_TIME=120
DETECTION_TIME=1800
WHITELIST_FILE=/etc/sshguard/whitelist
BACKEND=/usr/lib/x86_64-linux-gnu/sshg-fw-iptables
```

```bash
# Añadir IPs de confianza a la lista blanca
echo "10.10.10.0/24" | sudo tee -a /etc/sshguard/whitelist
echo "192.168.1.0/24" | sudo tee -a /etc/sshguard/whitelist
echo "127.0.0.1" | sudo tee -a /etc/sshguard/whitelist

# Activar y arrancar
sudo systemctl enable sshguard
sudo systemctl start sshguard

# Verificar estado de bloqueos activos
sudo sshguard -l
```

### fail2ban (alternativa)

```bash
# Instalar fail2ban
sudo apt install fail2ban -y

# Crear configuración local
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo vim /etc/fail2ban/jail.local
```

Sección relevante en `/etc/fail2ban/jail.local`:

```ini
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
findtime = 600
bantime  = 3600
ignoreip = 127.0.0.1/8 192.168.1.0/24 10.0.0.0/8
```

```bash
# Activar y arrancar
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Ver estado de bloqueos
sudo fail2ban-client status sshd
```

### Verificar las reglas de iptables generadas

```bash
# Ver reglas generadas por sshguard o fail2ban
sudo iptables -L INPUT -n -v | grep -i ssh
sudo iptables -L sshguard -n -v
```

---

## 8. Opciones avanzadas: chroot, rhosts y desactivación del servidor en el cliente

### Deshabilitar ficheros .rhosts

Los ficheros `.rhosts` son un mecanismo heredado del comando `rsh` que permite acceso sin contraseña basándose solo en el nombre del host. Su uso es un riesgo grave de seguridad porque cualquier usuario puede crear su propio `.rhosts` sin intervención del administrador:

```
# En sshd_config
IgnoreRhosts yes
```

SSH puede emular el comportamiento del comando `rsh` obsoleto. La directiva `IgnoreRhosts yes` hace que sshd ignore completamente los ficheros `~/.rhosts` y `~/.shosts`, aunque existan.

El fichero `/etc/hosts.equiv` está bajo control del administrador y puede gestionarse, pero cualquier usuario puede crear un `.rhosts` que conceda acceso a quien elija sin conocimiento del administrador del sistema. Deshabilitarlo elimina ese vector.

### Deshabilitar autenticación basada en host

```
# En sshd_config
HostbasedAuthentication no
```

### Chroot OpenSSH — confinar usuarios en sus directorios

El chroot limita a usuarios específicos a su directorio de inicio, impidiéndoles acceder a `/etc`, `/bin`, `/sbin` u otras rutas del sistema:

```bash
# Crear estructura para usuario confinado
sudo mkdir -p /home/sftp_user
sudo chown root:root /home/sftp_user
sudo chmod 755 /home/sftp_user
sudo mkdir -p /home/sftp_user/uploads
sudo chown sftp_user:sftp_user /home/sftp_user/uploads

# Añadir usuario al grupo restringido
sudo groupadd sftp-only
sudo usermod -aG sftp-only sftp_user
```

En `sshd_config`, configurar el chroot para ese grupo:

```
Match Group sftp-only
    ChrootDirectory /home/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
    PasswordAuthentication no
```

```bash
# Verificar permisos del directorio chroot
# CRÍTICO: el directorio raíz del chroot debe ser propiedad de root
ls -la /home/sftp_user
# drwxr-xr-x root root /home/sftp_user  ← correcto
# drwxrwxrwx sftp_user ...              ← incorrecto, sshd rechazará el chroot
```

### Desactivar el servidor OpenSSH en la máquina cliente

Si Kali se usa exclusivamente como cliente de pentesting y no se necesita que otros se conecten a ella, el servidor puede desactivarse completamente:

```bash
# Detener el servicio inmediatamente
sudo systemctl stop ssh

# Desactivar el arranque automático
sudo systemctl disable ssh

# Verificar que no escucha en ningún puerto
sudo ss -tlnp | grep :22
# Salida esperada: vacía
```

---

## 9. Caso práctico: CVE-2024-6387 regreSSHion — verificación y mitigación

CVE-2024-6387 (regreSSHion) es una vulnerabilidad crítica (CVSS 9.8) en OpenSSH 8.5p1–9.7p1 que permite ejecución remota de código como root sin autenticación previa, explotando una condición de carrera en el manejador de señales `SIGALRM`.

### Verificar si la versión en Kali es vulnerable

```bash
# Comprobar versión instalada
ssh -V
# Si es OpenSSH 8.5p1 a 9.7p1 → vulnerable sin parchear

# Verificar con Nmap NSE (script del repositorio ssha)
nmap -p 22 --script CVE-2024-6387.nse <IP>

# Verificar con el POC Python del repositorio ssha
python3 CVE-2024-6387.py <IP>
```

### Actualizar OpenSSH en Kali

```bash
# Actualizar y parchear
sudo apt update && sudo apt upgrade openssh-server openssh-client -y

# Verificar versión actualizada (debe ser >= 9.8p1)
ssh -V

# Reiniciar el servicio
sudo systemctl restart ssh
```

### Mitigación temporal si no se puede actualizar

La vulnerabilidad explota la ventana creada por `LoginGraceTime`. Como mitigación de emergencia:

```
# En /etc/ssh/sshd_config — mitigación temporal
LoginGraceTime 0
```

> **Advertencia:** `LoginGraceTime 0` desactiva el timeout de autenticación, lo que puede facilitar ataques de conexiones pendientes (agotamiento de recursos). Es solo una mitigación temporal hasta actualizar.

### Verificar parche del núcleo — CVE-2026-46333 (robo de descriptores de fichero)

El servidor también es vulnerable al robo de descriptores de fichero mediante ptrace si el núcleo no está parcheado. El exploit afecta a `ssh-keysign`, que abre las claves privadas del bastión antes de eliminar privilegios:

```bash
# Verificar fecha de compilación del núcleo
uname -r
cat /proc/version
# Buscar fecha posterior al 14 de mayo de 2026

# Verificar que Yama LSM está activo (valor 1 = restricción activa)
cat /proc/sys/kernel/yama/ptrace_scope
```

---

## 10. Verificación del bastionado con ssh-audit y herramientas del repositorio ssha

### ssh-audit

ssh-audit es la herramienta de referencia para verificar la configuración criptográfica de un servidor SSH:

```bash
# Instalar ssh-audit en Kali
sudo apt install ssh-audit -y
# O desde pip
pip install ssh-audit --break-system-packages

# Auditar el servidor local
ssh-audit localhost
ssh-audit 127.0.0.1

# Auditar servidor remoto
ssh-audit <IP>
ssh-audit -p 2222 <IP>

# Salida en JSON para integración con informes
ssh-audit --json <IP>
```

**Interpretar los resultados de ssh-audit:**

| Etiqueta | Significado |
|---|---|
| `[info]` | Informativo, sin riesgo |
| `[warn]` | Aviso — algoritmo obsoleto o subóptimo |
| `[fail]` | Fallo de seguridad — algoritmo roto o prohibido |
| `[rec]` | Recomendación de mejora |

### Herramientas del repositorio ssha

```bash
# Clonar el repositorio de referencia
git clone https://github.com/hackingyseguridad/ssha.git
cd ssha

# Captura de banner y versión del servidor propio
bash versionssh.sh 127.0.0.1
bash verssh.sh 127.0.0.1

# Escaneo de cifrados ofrecidos por el servidor
bash scanciphers.sh 127.0.0.1
bash ssh-audit.sh 127.0.0.1

# Verificar vulnerabilidad Terrapin (CVE-2023-51767)
./Terrapin_Scanner_Linux_amd64 127.0.0.1
# Resultado esperado: "NOT VULNERABLE"

# Ver claves del servidor
bash verserverkeys.sh

# Monitorizar conexiones activas al servidor
bash verconexiones.sh

# Revisar registros de intentos de autenticación
bash verlogssh.sh
```

### Nmap para verificación externa

```bash
# Enumeración completa de la configuración SSH del servidor
nmap -p 22 --script ssh2-enum-algos,ssh-hostkey,banner 127.0.0.1

# Verificar que algoritmos débiles NO están disponibles
nmap -p 22 --script ssh2-enum-algos 127.0.0.1 \
  | grep -E "diffie-hellman-group1|diffie-hellman-group14-sha1|arcfour|aes.*cbc|hmac-md5|hmac-sha1"
# Salida esperada: vacía (ningún algoritmo débil disponible)
```

### Checklist de verificación post-bastionado

```bash
# 1. Verificar sintaxis de sshd_config sin reiniciar
sudo sshd -t
# Salida vacía = sin errores

# 2. Ver configuración activa completa
sudo sshd -T | grep -E "port|permitrootlogin|passwordauth|pubkeyauth|maxauthtries|kexalgorithms|ciphers|macs"

# 3. Verificar que solo Ed25519 y ECDSA se ofrecen como host keys
ssh-keyscan -t ed25519,ecdsa 127.0.0.1

# 4. Confirmar que la autenticación por contraseña está desactivada
ssh -o PasswordAuthentication=yes -o PubkeyAuthentication=no usuario@127.0.0.1
# Debe fallar: "Permission denied (publickey)"

# 5. Confirmar que root no puede acceder directamente
ssh root@127.0.0.1
# Debe fallar: "Permission denied"

# 6. Verificar que el banner legal aparece
nc -w 3 127.0.0.1 22

# 7. Comprobar que sshguard o fail2ban están activos
sudo systemctl status sshguard
sudo systemctl status fail2ban

# 8. Verificar reglas UFW activas
sudo ufw status verbose | grep ssh
```

---

## 11. Lista de verificación: 20 directivas para sshd_config

Referencia rápida de todas las directivas de bastionado recomendadas para Kali Linux 2024.x, basada en el repositorio hackingyseguridad/ssha:

| # | Directiva | Por defecto | Recomendado | Motivo |
|---|---|---|---|---|
| 1 | `Port` | 22 | **65535** (o diferente) | Reducir ruido de bots automatizados |
| 2 | `ListenAddress` | 0.0.0.0 | **IP específica** | No exponer en todas las interfaces |
| 3 | `HostKey` (ed25519) | generada | **Verificar/regenerar** | Algoritmo más robusto |
| 4 | `PermitRootLogin` | prohibit-password | **no** | Eliminar vector root directo |
| 5 | `PasswordAuthentication` | yes | **no** | Eliminar fuerza bruta de contraseñas |
| 6 | `PubkeyAuthentication` | yes | **yes** | Único método de autenticación |
| 7 | `PermitEmptyPasswords` | no | **no** | Mantener prohibido |
| 8 | `ChallengeResponseAuthentication` | no | **no** | Desactivar interactivo |
| 9 | `IgnoreRhosts` | yes | **yes** | Deshabilitar acceso heredado rsh |
| 10 | `HostbasedAuthentication` | no | **no** | Mantener desactivado |
| 11 | `AllowUsers` / `AllowGroups` | (todos) | **lista explícita** | Principio de mínimo privilegio |
| 12 | `LoginGraceTime` | 120 | **30** | Reducir ventana de autenticación |
| 13 | `MaxAuthTries` | 6 | **3** | Limitar intentos por conexión |
| 14 | `MaxStartups` | 10:30:100 | **10:30:60** | Limitar conexiones pendientes |
| 15 | `ClientAliveInterval` | 0 | **300** | Cerrar sesiones inactivas |
| 16 | `ClientAliveCountMax` | 3 | **0** | Cerrar al primer timeout sin respuesta |
| 17 | `X11Forwarding` | no | **no** | Eliminar superficie de ataque X11 |
| 18 | `AllowAgentForwarding` | yes | **no** | Prevenir robo de agente |
| 19 | `AllowTcpForwarding` | yes | **no** | Deshabilitar túneles no autorizados |
| 20 | `Banner` | none | **/etc/issue.net** | Banner legal antes de autenticación |

### Plantilla de `/etc/ssh/sshd_config` bastionada para Kali

```
# /etc/ssh/sshd_config — Bastionado seguro sshd
# hackingyseguridad.com — Kali Linux 2026
# Referencia: https://github.com/hackingyseguridad/ssha
# Referencia: https://raw.githubusercontent.com/hackingyseguridad/ssha/master/sshd_config

# ─── ESCUCHA Y PUERTO ────────────────────────────────────────────────────────
Port 65535
ListenAddress 0.0.0.0
AddressFamily inet

# ─── CLAVES DEL BASTIÓN ──────────────────────────────────────────────────────
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key
# HostKey /etc/ssh/ssh_host_rsa_key  # Solo si se requiere compatibilidad

# ─── CRIPTOGRAFÍA DEL TRANSPORTE ─────────────────────────────────────────────
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# ─── ALGORITMOS DE AUTENTICACIÓN ─────────────────────────────────────────────
PubkeyAcceptedAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384

# ─── AUTENTICACIÓN ───────────────────────────────────────────────────────────
PermitRootLogin no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
UsePAM yes

# ─── CONTROL DE ACCESO ───────────────────────────────────────────────────────
AllowUsers pentest
# AllowGroups sshusers
# DenyUsers root guest administrador

# ─── TIMEOUTS Y LÍMITES ──────────────────────────────────────────────────────
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 0

# ─── REENVÍOS (DESACTIVADOS) ─────────────────────────────────────────────────
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no

# ─── MISCELÁNEA ──────────────────────────────────────────────────────────────
Compression no
UseDNS no
PrintMotd no
PrintLastLog yes
Banner /etc/issue.net
VersionAddendum none

# ─── SUBSISTEMAS ─────────────────────────────────────────────────────────────
Subsystem sftp /usr/lib/openssh/sftp-server
```

### Validar la configuración antes de reiniciar

```bash
# Verificar sintaxis sin reiniciar el servicio
sudo sshd -t
# Salida vacía = sin errores

# Recargar (sin cortar sesiones activas)
sudo systemctl reload ssh

# O reiniciar completo
sudo systemctl restart ssh
```

---

## 12. Preguntas frecuentes

**¿Kali Linux tiene sshd activo por defecto?**

No. A diferencia de Ubuntu Server, Kali no arranca el servidor SSH automáticamente. Hay que activarlo explícitamente con `sudo systemctl enable --now ssh`. Esto es una medida de seguridad correcta para una distribución de pentesting.

**¿Cuál es el usuario por defecto en Kali y debo cambiar sus credenciales?**

Desde Kali 2020.1, el usuario por defecto es `kali` (antes era `root`). Las credenciales por defecto `kali/kali` deben cambiarse antes de cualquier exposición en red: `passwd kali`. Se recomienda un mínimo de 16 caracteres con mayúsculas y números.

**¿Puedo usar el mismo sshd_config en Ubuntu y en Kali?**

Casi, pero hay diferencias. En Kali el servicio se llama `ssh` (no `sshd`), la ruta del sftp-server puede variar y el paquete `fail2ban` puede no incluir la misma configuración preinstalada para SSH. Verificar siempre con `sudo sshd -t` tras copiar una configuración entre distribuciones.

**¿Cómo verifico que Terrapin (CVE-2023-51767) está mitigado?**

```bash
# Con el scanner del repositorio ssha
./Terrapin_Scanner_Linux_amd64 127.0.0.1

# Con ssh-audit
ssh-audit 127.0.0.1 | grep -i terrapin
```

La vulnerabilidad requiere `ChaCha20-Poly1305` o `CBC con EtM` activos con negociación específica. La configuración de esta guía no es vulnerable.

**¿Debo usar fail2ban o sshguard?**

Para Kali, **sshguard es preferible** porque trabaja directamente con journald sin parsear ficheros de texto. fail2ban es más flexible si se quieren proteger múltiples servicios simultáneamente (web, FTP, etc.).

**¿Cómo compruebo si CVE-2024-6387 (regreSSHion) está parcheado?**

```bash
ssh -V
# OpenSSH_9.8p1 o superior → parcheado
# OpenSSH_8.5p1 a 9.7p1 → vulnerable sin parchear

sudo apt update && sudo apt full-upgrade -y
```

**¿Qué hace exactamente `ssh -Q cipher`?**

El subcomando `ssh -Q` consulta los algoritmos compilados en el binario de OpenSSH instalado. No muestra qué algoritmos están activos en el servidor — para eso se usa `sudo sshd -T` o `ssh-audit`. La combinación de ambos permite auditar primero qué está disponible y luego qué está realmente configurado.

---

## Referencias

- [Repositorio hackingyseguridad/ssha](https://github.com/hackingyseguridad/ssha)
- [configuracion.txt — guía de bastionado original](https://github.com/hackingyseguridad/ssha/blob/master/configuracion.txt)
- [Guía del cliente SSH — openssh-cliente-seguridad-ubuntu-2026.md](https://github.com/hackingyseguridad/ssha/blob/master/openssh-cliente-seguridad-ubuntu-2026.md)
- [sshd_config de referencia del repositorio](https://raw.githubusercontent.com/hackingyseguridad/ssha/master/sshd_config)
- [sshguard.conf de referencia](https://raw.githubusercontent.com/hackingyseguridad/ssha/master/sshguard.conf)
- [CVE-2024-6387 — regreSSHion (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2024-6387)
- [CVE-2023-51767 — Terrapin (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-51767)
- [OpenSSH Release Notes](https://www.openssh.com/releasenotes.html)
- [ssh-audit — herramienta de auditoría](https://github.com/jtesta/ssh-audit)
- [OpenSSH legacy ciphers](https://www.openssh.com/legacy.html)

---

*Guía mantenida por [hackingyseguridad.com](https://hackingyseguridad.com) — Pentesting y seguridad ofensiva, Madrid.*
