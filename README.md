![banner](https://github.com/hackingyseguridad/ssha/raw/master/banner.png)

### ssha — Utilidades y herramientas de explotación y auditoría SSH

Colección de scripts en **Bash**, **Python**, **C** y **Lua (NSE)** para auditar, escanear y poner a prueba la seguridad de servicios SSH: explotación de CVEs conocidas, fuerza bruta de credenciales, enumeración de usuarios, auditoría de cifrados/configuración y utilidades de post-explotación (túneles, C2 sobre SSH).

---

### Tabla de contenidos

- [Requisitos e instalación](#requisitos-e-instalación)
- [Estructura del repositorio](#estructura-del-repositorio)
- [Tabla resumen: top vulnerabilidades SSH más fáciles de explotar](#tabla-resumen-top-vulnerabilidades-ssh-más-fáciles-de-explotar)
- [Scripts de explotación por CVE](#scripts-de-explotación-por-cve)
- [Scripts de fuerza bruta](#scripts-de-fuerza-bruta)
- [Scripts de enumeración de usuarios](#scripts-de-enumeración-de-usuarios)
- [Scripts de escaneo y auditoría](#scripts-de-escaneo-y-auditoría)
- [Utilidades de post-explotación y túneles](#utilidades-de-post-explotación-y-túneles)
- [Configuración segura de referencia](#configuración-segura-de-referencia)
- [Comandos SSH habituales](#comandos-ssh-habituales)
- [Más información sobre SSH](#más-información-sobre-ssh)

---

| Categoría | Scripts | Naturaleza |
|---|---|---|
| Auditoría de configuración/cifrados | `scanciphers.sh`, `ssh-audit.sh`, `sshaudit.sh`, `ssh_cifrados_vulnerables.md` | No intrusiva |
| Versión / fingerprint del servidor | `versionssh.sh`, `verssh.sh`, `verserverkeys.sh` | No intrusiva |
| Detección de Terrapin Attack | `terapinscan.sh`, `Terrapin_Scanner_Linux_amd64/i386` | No intrusiva (solo detecta) |
| Escaneo de hosts/puertos | `sshscan.sh`, `sshscan2.sh`, `nmapxsalto.sh` | Reconocimiento |
| Logs y monitorización (lado servidor propio) | `verlogssh.sh`, `verconexiones.sh` | Defensivo |
| Hardening / configuración segura | `sshd_config`, `configuracion.txt`, `sshguard.conf` | Defensivo |
| Enumeración de usuarios (CVE-2018-15473, CVE-2016-6210) | `usuariossh.py`, `sshusers.sh`, `usuarios_ssh.sh`, `sshuserslist.sh`, `ssh-username-enum.py`, `CVE-2016-6210.py` | Ofensivo — requiere autorización |
| Fuerza bruta de credenciales | `brutessh*.sh`, `brutesshmasivo.sh`, `sshpass.sh` | Ofensivo — requiere autorización |
| PoC de RCE / inyección de comandos | `CVE-2024-6387.py/.nse/.c`, `CVE-2020-15778_exploit.sh`, `cve_2020_15778.py`, otros `CVE-*.sh/.py` | Ofensivo — requiere autorización explícita y contexto de laboratorio/pentest contratado |
| Post-explotación (túneles/C2) | `tuneles_ssh.md`, `tunel_panel_c2.sh`, `claveprivada.sh`, `ssh_claveprivada.sh` | Ofensivo — solo en engagements con alcance definido |
| Clientes legacy | `ssha`, `sshb`, `sshc`, `sshd` (wrappers) | Compatibilidad, no ofensivo per se |

---

### Requisitos e instalación

```bash
git clone https://github.com/hackingyseguridad/ssha
cd ssha
chmod 777 *
sh instalar.sh
pip3 install -r requirements.txt --break-system-packages
```

Dependencias habituales usadas por los scripts:

| Herramienta | Uso |
|---|---|
| `openssh-client` / `ssh`, `scp`, `ssh-copy-id` | Cliente SSH base para la mayoría de scripts |
| `sshpass` | Automatizar autenticación por contraseña en scripts (`sshpass.sh`) |
| `python3` + `paramiko` | Scripts `.py` de explotación (enumeración de usuarios, CVEs) — ver `requirements.txt` |
| `nmap` | Escaneo de puertos y ejecución del script NSE `CVE-2024-6387.nse` (`nmapxsalto.sh`) |
| `ssh-audit` | Auditoría de algoritmos/cifrados del servidor (`ssh-audit.sh`, `sshaudit.sh`) |
| `gcc` | Compilar el PoC en C de regreSSHion (`cve-2024-6387.c`) |
| `Terrapin_Scanner_Linux_*` | Binario incluido para detectar la vulnerabilidad Terrapin (truncamiento de la secuencia de handshake SSH) |

Mantén el repositorio actualizado:

```bash
sh actualizar.sh
```

---

### Estructura del repositorio

```
ssha/
├── CVE-*.sh / *.py / *.c / *.nse     # exploits / PoC por CVE concreta
├── brutessh*.sh                      # fuerza bruta de credenciales SSH
├── brutesshmasivo.sh                 # fuerza bruta contra varios objetivos
├── usuariossh.py / usuariossh.sh     # enumeración de usuarios (CVE-2018-15473)
├── sshusers.sh / usuarios_ssh.sh / sshuserslist.sh / ssh-username-enum.py
├── sshscan.sh / sshscan2.sh          # escaneo de puertos/hosts SSH
├── scanciphers.sh                    # cifrados ofrecidos por el servidor
├── ssh-audit.sh / sshaudit.sh        # auditoría de configuración/algoritmos
├── versionssh.sh / verssh.sh         # detección de versión/banner SSH
├── verserverkeys.sh                  # huella de claves del servidor
├── verconexiones.sh / verlogssh.sh   # visibilidad de conexiones y logs (lado servidor)
├── terapinscan.sh + Terrapin_Scanner_Linux_*  # detección de la vulnerabilidad Terrapin
├── claveprivada.sh / ssh_claveprivada.sh       # gestión/prueba de claves privadas
├── tunel_panel_c2.sh                 # túnel SSH para panel C2 (post-explotación)
├── tuneles_ssh.md                    # documentación de técnicas de tunneling SSH
├── ssh_cifrados_vulnerables.md       # referencia de cifrados/KEX obsoletos
├── sshd_config / configuracion.txt   # plantilla de configuración segura del servidor
├── sshguard.conf                     # configuración de SSHGuard (protección anti fuerza bruta)
├── changedns.sh / contador.sh        # utilidades auxiliares
├── ssha / sshb / sshc / sshd         # wrappers de cliente SSH con opciones para cifrados obsoletos
└── instalar.sh / actualizar.sh       # instalación y actualización
```

---

### Tabla resumen: top vulnerabilidades SSH más fáciles de explotar

Basada en el ranking del propio repositorio, ordenada por severidad/CVSS. La columna **Facilidad** refleja la valoración original del proyecto.

| # | CVE | Componente / versión afectada | CVSS | Tipo | Impacto | Facilidad | Script relacionado |
|---|---|---|---|---|---|---|---|
| 1 | **CVE-2024-6387** ("regreSSHion") | OpenSSH 8.5p1 – 9.7p1 | 9.8 Crítico | Ejecución remota de código | RCE como root | Relativamente sencilla | `CVE-2024-6387.py`, `CVE-2024-6387.nse`, `cve-2024-6387.c` |
| 2 | **CVE-2018-15473** | OpenSSH ≤ 7.7 | 5.3 Medio | Filtración de información | Enumeración de nombres de usuario válidos | Muy fácil | `CVE-2018-15473.sh`, `usuariossh.py`, `sshusers.sh` |
| 3 | **CVE-2016-0777 / CVE-2016-0778** | OpenSSH 5.4 – 7.1 | 4.0 Medio | Filtración de información | Filtra hasta 64KB de memoria del cliente (roaming) | Sencilla | — (ver `ssh_cifrados_vulnerables.md`) |
| 4 | **CVE-2020-15778** | OpenSSH ≤ 8.3p1 | 6.8 Medio | Inyección de comandos | Ejecución arbitraria vía `scp` | Moderadamente fácil | `CVE-2020-15778_exploit.sh`, `cve_2020_15778.py` |
| 5 | **CVE-2019-6111** | OpenSSH ≤ 7.9 | 5.7 Medio | Sobrescritura de archivos | Sobrescribe ficheros arbitrarios vía `scp` | Requiere interacción del usuario | — |
| 6 | **CVE-2023-38408** | OpenSSH (agent forwarding, versiones específicas) | 5.9 Medio | Elevación de privilegios | RCE en sistemas con `ssh-agent` forwarding y ciertas bibliotecas PKCS#11 | Compleja | — |
| 7 | **CVE-2021-41617** | OpenSSH 8.5p1 (configuraciones con `AuthorizedKeysCommand`/`AuthorizedPrincipalsCommand` sin `User`) | 7.8 Alto | Elevación de privilegios | Privesc a través de `sshd` | Compleja | — |
| 8 | **CVE-2019-16905** | OpenSSH 7.7 – 7.9 (con libgcrypt / soporte XMSS) | 6.8 Medio | Denegación de servicio | Caída del servicio SSH | Fácil | — |
| 9 | **CVE-2020-14145** | OpenSSH ≤ 8.3 (cliente) | 4.3 Medio | Filtración de información | Revela información del servidor durante el intercambio de claves | Fácil | — |
| 10 | **CVE-2018-15919** | OpenSSH 7.8 (con GSS2) | 5.3 Medio | Denegación de servicio | Caída del servicio SSH | Moderadamente fácil | — |

**Otras vulnerabilidades relevantes cubiertas por scripts del repositorio** (no incluidas en el top 10 original, pero con PoC/herramienta disponible):

| CVE | Componente | Tipo | Script |
|---|---|---|---|
| CVE-2016-6210 | OpenSSH < 7.3 | Enumeración de usuarios por canal encubierto de tiempos (diferencia de latencia BLOWFISH vs SHA256/SHA512 al autenticar usuarios inexistentes) | `CVE-2016-6210.py` |
| CVE-2018-10933 | libssh (no OpenSSH) | Bypass de autenticación (spoofing del mensaje `SSH2_MSG_USERAUTH_SUCCESS`) | `CVE-2018-10933.py` |
| Terrapin Attack | Protocolo SSH (truncamiento de secuencia durante el handshake, afecta a ChaCha20-Poly1305/CBC+EtM en implementaciones sin mitigar) | Downgrade de seguridad en la negociación | `terapinscan.sh`, `Terrapin_Scanner_Linux_amd64/i386` |
| — | Cifrados/KEX obsoletos (`diffie-hellman-group1-sha1`, SSH-1, etc.) | Configuración insegura | `scanciphers.sh`, `ssh_cifrados_vulnerables.md`, `ssha`/`sshb`/`sshc`/`sshd` |
| CVE-2015-6564, CVE-2020-10188, CVE-2020-14721, CVE-2020-14871(-2), CVE-2023-34039 | Ver comentarios de cabecera de cada script | PoC históricos incluidos en el repositorio | ficheros homónimos |

> Antes de usar cualquiera de estos PoC contra un sistema real, verifica en la cabecera del propio script la versión exacta de software afectada — algunas de estas CVEs corresponden a componentes o demonios distintos de OpenSSH (p. ej. `telnetd`, `libssh`) y se incluyen en el repositorio como referencia histórica.

---

### Scripts de explotación por CVE

### `CVE-2024-6387.py` / `CVE-2024-6387.nse` / `cve-2024-6387.c` — regreSSHion

Explotan la condición de carrera en el manejador de señales de `sshd` (reintroducida por un cambio que revirtió la corrección de CVE-2006-5051) que permite ejecución remota de código como **root** en glibc-based Linux con OpenSSH 8.5p1–9.7p1.

```bash
python3 CVE-2024-6387.py <IP> <puerto>
nmap -p22 --script CVE-2024-6387.nse <IP>      # vía nmapxsalto.sh
gcc cve-2024-6387.c -o regresshion && ./regresshion <IP>
```

Por la naturaleza probabilística de la condición de carrera, suele requerir miles de intentos (horas de ejecución) para lograr una ejecución de código fiable.

### `CVE-2018-15473.sh` — enumeración de usuarios

Envía paquetes `SSH2_MSG_USERAUTH_REQUEST` manipulados y observa diferencias de respuesta/tiempo entre usuarios válidos e inválidos:

```bash
sh CVE-2018-15473.sh <IP> usuarios.txt
```

### `CVE-2020-15778_exploit.sh` / `cve_2020_15778.py` — inyección de comandos vía scp

Aprovechan un saneamiento insuficiente de nombres de fichero en `scp` para inyectar comandos adicionales en la sesión SSH subyacente:

```bash
sh CVE-2020-15778_exploit.sh usuario@IP
```

### `CVE-2016-6210.py` — enumeración de usuarios por canal de tiempos

Envía contraseñas de gran tamaño (~10-25 KB) y mide el tiempo de respuesta: los usuarios válidos tardan más porque el servidor calcula el hash real (SHA256/SHA512) en lugar de usar la estructura *dummy* basada en Blowfish.

```bash
python3 CVE-2016-6210.py <IP> -w usuarios.txt
```

### `terapinscan.sh` — Terrapin Attack

*Wrapper* sobre el binario oficial `Terrapin_Scanner` para detectar si el servidor es vulnerable al ataque de truncamiento de secuencia del handshake SSH (afecta a ChaCha20-Poly1305 y modos CBC-EtM sin la mitigación *strict KEX*):

```bash
sh terapinscan.sh <IP> <puerto>
```

---

### Scripts 

### `brutessh.sh`, `brutessh1.sh` … `brutessh8.sh`

Prueban combinaciones de usuario/contraseña contra un servidor SSH usando los diccionarios `usuarios.txt` y `claves.txt` (del repositorio hermano [`hackingyseguridad/diccionarios`](https://github.com/hackingyseguridad/diccionarios)):

```bash
sh brutessh.sh <IP>
```

Las variantes numeradas ajustan el número de hilos, el *delay* entre intentos o el subconjunto de diccionario usado, para adaptarse a distintos umbrales de bloqueo (fail2ban, SSHGuard).

### `brutesshmasivo.sh`

Extiende la fuerza bruta a una lista de múltiples objetivos (IPs/hosts) en lugar de uno solo:

```bash
sh brutesshmasivo.sh listado_ips.txt
```

### `sshpass.sh`

Utilidad de apoyo basada en `sshpass` para automatizar conexiones SSH con contraseña dentro de otros scripts (evita el prompt interactivo).

---

### Scripts de enumeración de usuarios

| Script | Descripción |
|---|---|
| `usuariossh.py` | Comprueba la existencia de un usuario concreto en un host con SSH activo, explotando CVE-2018-15473. |
| `sshusers.sh` | Enumera usuarios existentes contra un objetivo usando el diccionario `usuarios.txt`, explotando CVE-2018-15473. |
| `usuarios_ssh.sh` / `usuariossh.sh` | Variantes del mismo enfoque de enumeración. |
| `sshuserslist.sh` | Genera/gestiona la lista de usuarios candidatos a probar. |
| `ssh-username-enum.py` | Versión en Python dedicada a la enumeración de nombres de usuario. |

```bash
python3 usuariossh.py <IP> usuario_a_comprobar
sh sshusers.sh <IP> usuarios.txt
```

---

### Scripts de escaneo y auditoría

| Script | Descripción |
|---|---|
| `sshscan.sh` / `sshscan2.sh` | Escanean rangos de IP/puertos para localizar servicios SSH accesibles. |
| `scanciphers.sh` | Muestra los algoritmos de cifrado, KEX y MAC ofrecidos por el servidor objetivo — útil para detectar cifrados obsoletos (`ssh_cifrados_vulnerables.md`). |
| `ssh-audit.sh` / `sshaudit.sh` | Ejecutan [`ssh-audit`](https://github.com/jtesta/ssh-audit) para puntuar la configuración de seguridad del servidor (algoritmos débiles, versión, CVEs conocidas). |
| `versionssh.sh` / `verssh.sh` | Obtienen el banner/versión exacta del servidor SSH (primer paso para correlacionar con CVEs por versión). |
| `verserverkeys.sh` | Extrae/muestra la huella (*fingerprint*) de las claves del servidor. |
| `verconexiones.sh` | Muestra las conexiones SSH activas (uso en el lado servidor/administración). |
| `verlogssh.sh` | Revisa los logs de autenticación SSH (`/var/log/auth.log` o equivalente) — útil tanto para auditoría defensiva como para detectar intentos de fuerza bruta. |
| `nmapxsalto.sh` | Lanza Nmap con scripts NSE relacionados con SSH (incluye `CVE-2024-6387.nse`). |

```bash
sh sshscan.sh 192.168.1.0/24
sh scanciphers.sh <IP>
sh ssh-audit.sh <IP>
sh versionssh.sh <IP>
```

---

### Utilidades de post-explotación y túneles

- **`claveprivada.sh` / `ssh_claveprivada.sh`** — pruebas/gestión de autenticación mediante clave privada (por ejemplo, comprobar si una clave filtrada da acceso a un host).
- **`tuneles_ssh.md`** — documentación de técnicas de *tunneling* SSH (reenvío local, remoto y dinámico) aplicables tanto en auditoría como en post-explotación.
- **`tunel_panel_c2.sh`** — establece un túnel SSH para exponer/alcanzar un panel de mando y control (C2) en ejercicios de Red Team autorizados.
- **`changedns.sh`** — modifica la configuración DNS del sistema (utilidad auxiliar, no específica de SSH).
- **`ssha`, `sshb`, `sshc`, `sshd`** — *wrappers* del cliente `ssh` con juegos de opciones predefinidos para forzar cifrados/KEX obsoletos (p. ej. `diffie-hellman-group1-sha1`) al conectar contra equipos legacy que no soportan algoritmos modernos. Ver [openssh.com/legacy.html](https://www.openssh.com/legacy.html).

```bash
# Ejemplo: conectar a un equipo legacy que solo soporta diffie-hellman-group1-sha1
./ssha usuario@IP
```

---

### Configuración segura de referencia

- **`sshd_config`** y **`configuracion.txt`** — plantilla de configuración endurecida para el servidor `sshd` (deshabilitar login root, forzar autenticación por clave, limitar algoritmos a los modernos, etc.):

  ```bash
  wget https://raw.githubusercontent.com/hackingyseguridad/ssha/master/configuracion.txt
  ```

- **`sshguard.conf`** — configuración de [SSHGuard](https://www.sshguard.net/), herramienta que bloquea IPs tras repetidos intentos fallidos de autenticación (mitigación directa contra `brutessh*.sh`).

---

### Comandos SSH habituales

```bash
# 1. Conexión SSH estándar
ssh -p 3000 usuario@hostIP

# 2. Autenticación mediante clave SSH
ssh -i /path/to/private-key usuario@hostIP

# 3. Ejecución de comandos remotos
ssh usuario@hostIP "ls -la"

# 4. Reenvío de puertos (local)
ssh -L <puerto_local>:<destino>:<puerto_destino> usuario@hostIP

# 5. Conexión a través de un servidor intermedio (jump host)
ssh -J bob@hostIP1:port1 usuario@hostIP2

# 6. Copia de la clave pública SSH al servidor
ssh-copy-id -i /path/to/public-key usuario@hostIP

# 7. Conexión con fichero de configuración personalizado
ssh -F /path/to/ssh_config usuario@hostIP

# 8. Reenvío remoto con bind a localhost
ssh -FN -R <puerto>:localhost:22 usuario@hostIP

# 9. Transferencia de directorios mediante SCP
scp -rP 3000 /path/to/local-dir usuario@hostIP:/path/to/remote-dir
```

---

### referencias

[OpenSSH — Legacy Options](https://www.openssh.com/legacy.html)

[ssh-audit (jtesta)](https://github.com/jtesta/ssh-audit)

[Terrapin Attack — terrapin-attack.com](https://terrapin-attack.com/)

[NVD — National Vulnerability Database](https://nvd.nist.gov/)

[hackingyseguridad.com](http://www.hackingyseguridad.com/)

[Exploits Mataesploit](https://github.com/hackingyseguridad/ssha/blob/master/exploits_ssh_metasploit.md)


# 

<p align="center">
  <img src="https://github.com/hackingyseguridad/ssha/blob/master/autor.png" alt="@antonio_taboada">
</p>

#


<p align="center">
  <a href="https://www.hackingyseguridad.com/">https://www.hackingyseguridad.com/</a>
</p>

