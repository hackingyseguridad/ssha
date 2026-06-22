# Guía Completa de Seguridad del Cliente OpenSSH en Ubuntu (2026)

---

## Índice

1. [Modelo de seguridad del cliente OpenSSH en Ubuntu 26.04](#1-modelo-de-seguridad-del-cliente-openssh-en-ubuntu-2604)
2. [Gestión de claves: Ed25519, PKCS#8 y la eliminación de DSA](#2-gestión-de-claves-ed25519-pkcs8-y-la-eliminación-de-dsa)
3. [Superficie de ataque del ssh-agent](#3-superficie-de-ataque-del-ssh-agent)
4. [Verificación de bastiones: prevención de ataques man-in-the-middle](#4-verificación-de-bastiones-prevención-de-ataques-man-in-the-middle)
5. [Intercambio de claves post-cuántico: mlkem768x25519-sha256](#5-intercambio-de-claves-post-cuántico-mlkem768x25519-sha256)
6. [Reenvío en el cliente: riesgos de X11, agente y TCP](#6-reenvío-en-el-cliente-riesgos-de-x11-agente-y-tcp)
7. [Caso práctico: CVE-2026-46333 — Robo de descriptores de fichero](#7-caso-práctico-cve-2026-46333--robo-de-descriptores-de-fichero)
8. [Lista de verificación de bastionado: 15 directivas para el cliente SSH](#8-lista-de-verificación-de-bastionado-15-directivas-para-el-cliente-ssh)
9. [Preguntas frecuentes](#9-preguntas-frecuentes)

---

## Introducción

SSH es la primera puerta que intentan abrir los atacantes en servidores Ubuntu, pero la conversación habitualmente se centra en `sshd_config`. **El lado cliente es donde se produce el daño real.** Un socket del agente expuesto, una decisión incorrecta de confianza en la clave del bastión, o una regla de reenvío olvidada pueden entregar las credenciales de producción sin necesidad de tocar el servidor.

Los tres errores más habituales en auditorías son:

- Reenvío de agente activo por defecto.
- Claves RSA donde debería haber Ed25519.
- Administradores que nunca han verificado su núcleo frente a vulnerabilidades de robo de descriptores de fichero mediante ptrace.

**Ubuntu 26.04 LTS incluye OpenSSH 10.2p1** con intercambio de claves post-cuántico activo por defecto, DSA completamente eliminado y un núcleo compilado tras el parche de CVE-2026-46333. Los valores por defecto son mejores que nunca, pero no son suficientes por sí solos.

---

## 1. Modelo de seguridad del cliente OpenSSH en Ubuntu 26.04

El cliente OpenSSH en Ubuntu 26.04 pertenece al paquete `openssh-client`, versión `1:10.2p1-2ubuntu3.2`. Enlaza con OpenSSL 3.5.5 e incluye soporte para Ed25519, ECDSA, llaves de seguridad FIDO2 y el nuevo intercambio de claves híbrido post-cuántico ML-KEM768x25519.

El cliente lee la configuración en este orden:

1. Opciones de línea de comandos
2. `~/.ssh/config`
3. `/etc/ssh/ssh_config` (configuración global del sistema)

En una instalación limpia de Ubuntu 26.04, la configuración global está casi completamente comentada. Las únicas directivas activas son:

```
SendEnv LANG LC_* COLORTERM NO_COLOR
HashKnownHosts yes
GSSAPIAuthentication yes
```

Cualquier ajuste de seguridad relevante cae en su valor por defecto compilado. Hay que conocer esos valores antes de modificar nada.

### La cadena de seguridad del cliente

La seguridad del cliente SSH es una cadena con cinco eslabones. Romper cualquiera de ellos invalida el conjunto:

| Eslabón | Descripción |
|---|---|
| **Gestión de claves** | Qué claves se generan, dónde se almacenan y qué algoritmos se permiten |
| **Seguridad del agente** | Cómo gestiona `ssh-agent` las claves y quién puede acceder al socket |
| **Verificación del bastión** | Cómo se confirma que el servidor al que nos conectamos es el esperado |
| **Política de reenvío** | Qué tráfico se permite atravesar el túnel SSH |
| **Seguridad del transporte** | Qué algoritmos de intercambio de claves, cifrado y MAC se negocian |

---

## 2. Gestión de claves: Ed25519, PKCS#8 y la eliminación de DSA

> **Regla de 2026:** Si aún se generan claves RSA para SSH, se está haciendo mal.

OpenSSH 10.0 eliminó el soporte DSA por completo. Aunque RSA sigue funcionando, Ed25519 es más rápido, produce claves más cortas y es criptográficamente más robusto en cualquier tamaño de clave práctico. Ubuntu 26.04 confirma esto listando `id_ed25519` e `id_ed25519_sk` como ficheros de identidad por defecto, mientras que `id_dsa` no aparece:

```bash
fosslinux@ubuntu:~$ ssh -G ssh | grep identityfile
identityfile ~/.ssh/id_rsa
identityfile ~/.ssh/id_ecdsa
identityfile ~/.ssh/id_ecdsa_sk
identityfile ~/.ssh/id_ed25519
identityfile ~/.ssh/id_ed25519_sk
```

Intentar generar una clave DSA produce un error:

```bash
fosslinux@ubuntu:~$ ssh-keygen -t dsa -f /tmp/test_dsa -N ''
unknown key type dsa
```

### Generación de la clave Ed25519 principal

```bash
ssh-keygen -t ed25519 -C "usuario@produccion" -f ~/.ssh/id_ed25519
```

El parámetro `-C` añade un comentario que facilita la identificación posterior de la clave, especialmente al auditar ficheros `authorized_keys`.

> **Consejo:** Para entornos múltiples, usar claves separadas:
> ```bash
> ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_prod    -C "usuario@prod"
> ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_staging -C "usuario@staging"
> ```
> Así, revocar el acceso a staging no afecta a producción.

### Soporte de llaves de hardware FIDO2

OpenSSH 10.x tiene soporte maduro para FIDO2/WebAuthn. Con un YubiKey u otro token hardware se puede generar una clave residente que nunca abandona el dispositivo:

```bash
ssh-keygen -t ed25519-sk -O resident -O verify-required
```

- `-sk`: indica a OpenSSH que use la llave de seguridad hardware.
- `resident`: almacena el material criptográfico en el propio token.
- `verify-required`: exige presencia física (toque) en cada autenticación.

Esto elimina el robo remoto de claves por completo.

---

## 3. Superficie de ataque del ssh-agent

`ssh-agent` es un demonio que mantiene las claves privadas descifradas en memoria para evitar introducir la frase de paso en cada conexión. Se comunica a través de un socket de dominio Unix cuya ruta se almacena en la variable de entorno `SSH_AUTH_SOCK`.

**El riesgo:** cualquier proceso que se ejecute como el mismo usuario puede leer `SSH_AUTH_SOCK` y utilizar el agente para autenticarse sin acceder nunca al material de clave privada. Esto no es teórico: es un vector de ataque real en servidores de desarrollo compartidos donde un ejecutor de CI tiene un paso excesivo de variables de entorno.

### Reubicación del socket en OpenSSH 10.1

En OpenSSH 10.1, el socket del agente se movió de `/tmp/ssh-XXXX/agent.PID` a `~/.ssh/agent/`. Esto fue una mejora de seguridad significativa, ya que `/tmp` es legible por todos los usuarios del sistema. En Ubuntu 26.04:

```bash
fosslinux@ubuntu:~$ eval $(ssh-agent -s)
Agent pid 12345
fosslinux@ubuntu:~$ echo $SSH_AUTH_SOCK
/home/fosslinux/.ssh/agent/sock
```

### Por qué el reenvío de agente es casi siempre un error

`ForwardAgent yes` (en `ssh_config`) o `-A` (en la línea de comandos) permite usar el agente local a través de un servidor remoto. El problema es que cualquier usuario de ese servidor remoto puede potencialmente acceder al socket del agente reenviado.

**Alternativa segura: `ProxyJump`**

```bash
ssh -J bastion.interna servidor-web.interna
```

El flag `-J` es funcionalmente equivalente a `ProxyCommand ssh -W %h:%p`, pero integrado directamente en el protocolo SSH. Evita la necesidad de `nc` o `netcat` en el bastión y gestiona el multiplexado de conexiones de forma más limpia. Ningún socket del agente queda expuesto en saltos intermedios.

---

## 4. Verificación de bastiones: prevención de ataques man-in-the-middle

Al conectarse a un servidor SSH por primera vez aparece el aviso:

```
The authenticity of host ... can't be established.
```

Esto es el modelo TOFU (*Trust On First Use*). La huella dactilar de la clave del bastión se registra en `~/.ssh/known_hosts`, y cualquier conexión futura que presente una clave diferente genera una alerta.

TOFU funciona bien para servidores personales, pero tiene una debilidad crítica: si un atacante intercepta la primera conexión, puede presentar su propia clave y será aceptada. Esto es exactamente lo que explotó **CVE-2025-26465** — un error lógico en OpenSSH 6.8p1 a 9.9p1 que permitía a un atacante en ruta suplantar cualquier servidor cuando `VerifyHostKeyDNS` estaba activo.

### Registros SSHFP en DNS

Un enfoque más robusto es usar registros SSHFP en DNS, que publican la huella dactilar de la clave del bastión en el DNS. Con `VerifyHostKeyDNS yes` en `ssh_config`, el cliente verifica los registros SSHFP contra la clave presentada por el servidor, eliminando la ventana TOFU — siempre que el DNS esté firmado con DNSSEC.

En Ubuntu 26.04, `VerifyHostKeyDNS` toma el valor `no` por defecto. Configuración recomendada:

```
# ~/.ssh/config
Host servidor-produccion
    VerifyHostKeyDNS yes
    StrictHostKeyChecking accept-new
```

El valor `accept-new` para `StrictHostKeyChecking` acepta automáticamente una nueva clave en la primera conexión, pero rechaza cualquier cambio posterior. Es más seguro que `ask` para flujos de trabajo automatizados y más seguro que `no`, que desactiva la verificación por completo.

### Claves de bastión firmadas por CA

Para despliegues grandes, se puede usar una Autoridad Certificadora para firmar las claves de bastión. El servidor presenta un certificado firmado por la CA, y el cliente lo valida contra la clave pública de la CA almacenada en `known_hosts`. Esto elimina la necesidad de gestionar huellas dactilares individuales en cientos de servidores.

---

## 5. Intercambio de claves post-cuántico: mlkem768x25519-sha256

Este es el cambio más importante en OpenSSH desde la eliminación de DSA. A partir de OpenSSH 10.0, el algoritmo de intercambio de claves por defecto es `mlkem768x25519-sha256`, un esquema híbrido que combina:

- **ML-KEM** (Module-Lattice Key Encapsulation, estandarizado por NIST como FIPS 203)
- **X25519** (curva elíptica Diffie-Hellman)

Verificación en Ubuntu 26.04:

```bash
fosslinux@ubuntu:~$ ssh -G ssh | grep kexalgorithms
kexalgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,...,curve25519-sha256,...
```

`mlkem768x25519-sha256` aparece primero en la lista, lo que significa que es el algoritmo preferido. El diseño híbrido garantiza que:

- Si un futuro ordenador cuántico rompe ML-KEM → X25519 sigue proporcionando seguridad clásica.
- Si X25519 se ve comprometido → ML-KEM proporciona seguridad post-cuántica.
- Se necesitan ambos rotos simultáneamente para comprometer el intercambio de claves.

> **Por qué importa ahora:** El modelo de ataque *"almacenar ahora, descifrar después"* significa que un adversario que registre tu tráfico SSH cifrado hoy puede descifrarlo retroactivamente cuando disponga de un ordenador cuántico. El intercambio de claves post-cuántico cierra esta ventana. Si tus datos necesitan permanecer confidenciales más de 10 años, debes usar PQ KEX ya.

### Algoritmos obsoletos a vigilar en 2026

| Algoritmo | Motivo de riesgo |
|---|---|
| `diffie-hellman-group14-sha256` y anteriores | DH de campo finito, lento y costoso computacionalmente |
| `ssh-rsa` | Firmas basadas en SHA1, eliminado de algoritmos aceptados |
| `ssh-dss` | DSA, completamente eliminado de OpenSSH 10.0+ |
| `aes128-cbc`, `3des-cbc` | Modos de cifrado por bloques que filtran información mediante padding |
| `hmac-sha1` | MAC SHA1, sustituido por `hmac-sha2-256` y `hmac-sha2-512` |

---

## 6. Reenvío en el cliente: riesgos de X11, agente y TCP

El reenvío convierte SSH de un simple intérprete remoto en un túnel de red. Esa flexibilidad es también lo que lo hace peligroso. Cada regla de reenvío activada crea una ruta de exfiltración potencial.

### Reenvío X11

En Ubuntu 26.04, el valor por defecto del cliente es `ForwardX11 no` pero `ForwardX11Trusted yes`:

```bash
fosslinux@ubuntu:~$ ssh -G ssh | grep forwardx11
forwardx11 no
forwardx11trusted yes
```

Recomendación: dejar el reenvío X11 desactivado. Usar `ssh -X` solo cuando sea absolutamente necesario ejecutar una aplicación gráfica desde un servidor remoto, que en 2026 debería ser casi nunca.

### Reenvío TCP y mapeo de puertos locales

| Tipo | Flag | Descripción |
|---|---|---|
| Reenvío local | `-L` | Crea un socket de escucha local que tuneliza tráfico al destino remoto |
| Reenvío remoto | `-R` | Expone un puerto local en el servidor remoto |
| Reenvío dinámico | `-D` | Convierte el cliente SSH en un proxy SOCKS |

Cada uno es útil en escenarios específicos, pero crea una ruta de red que evita cortafuegos y sistemas de monitorización. Usar `PermitOpen` en el servidor para restringir los destinos accesibles.

> **Nota:** La directiva `GatewayPorts` en `sshd_config` controla si los enlaces de puertos remotos (`-R`) pueden escuchar en todas las interfaces o solo en localhost. El valor por defecto es `no`. No modificarlo a menos que se comprendan completamente las implicaciones.

---

## 7. Caso práctico: CVE-2026-46333 — Robo de descriptores de fichero

En mayo de 2026 se divulgó una vulnerabilidad que la mayoría de guías de bastionado SSH ignoran completamente: **robo de descriptores de fichero a nivel de núcleo mediante el subsistema ptrace**.

Esto no es un fallo de OpenSSH. Es una vulnerabilidad del núcleo Linux que afecta al helper `ssh-keysign` de OpenSSH.

### Cómo funciona el ataque

La vulnerabilidad existe en la función `__ptrace_may_access()` del núcleo. Cuando un proceso termina, el núcleo ejecuta `exit_mm()` antes de `exit_files()`. Esto crea una ventana en la que el proceso no tiene mapa de memoria (`task->mm == NULL`) pero todavía mantiene abiertos los descriptores de fichero.

La comprobación de volcado ptrace se omitía cuando `mm` era NULL, lo que permitía a un atacante local usar `pidfd_getfd(2)` para robar descriptores de fichero del proceso en fase de terminación.

**Impacto práctico:** `ssh-keysign` abre las claves privadas del bastión SSH (modo 0600) antes de llamar a `permanently_set_uid()`. Si falla la autenticación, termina con los descriptores de fichero aún abiertos. Un atacante que monitorice esa ventana de salida puede robar el descriptor del fichero de clave privada del bastión y leer su contenido. Con la clave privada del bastión puede suplantar el servidor en ataques MITM.

El exploit también funciona contra `chage`, que abre `/etc/shadow` antes de eliminar privilegios. Mismo patrón, misma ventana, misma clase de vulnerabilidad.

### Verificar que el núcleo está parcheado

El parche fue incluido por Linus Torvalds el 14 de mayo de 2026 (commit `31e62c2ebbfd`). Cualquier núcleo compilado después de esa fecha incluye el parche:

```bash
fosslinux@ubuntu:~$ uname -r
7.0.0-22-generic
fosslinux@ubuntu:~$ cat /proc/version
Linux version 7.0.0-22-generic ... #22-Ubuntu SMP PREEMPT_DYNAMIC Mon May 25 15:54:34 UTC 2026
```

Núcleo compilado el 25 de mayo de 2026 → parcheado. Si la fecha de compilación es anterior al 14 de mayo de 2026, actualizar inmediatamente.

### Mitigaciones adicionales más allá del parcheo

```bash
# Verificar que Yama LSM está activo (valor 1 = restringido, por defecto en Ubuntu)
cat /proc/sys/kernel/yama/ptrace_scope
```

| Medida | Acción |
|---|---|
| Desactivar `EnableSSHKeysign` | Establecer `EnableSSHKeysign no` en `/etc/ssh/ssh_config` (ya es el valor por defecto en Ubuntu 26.04, pero verificarlo explícitamente) |
| Restringir ptrace con Yama | `ptrace_scope = 1` limita ptrace solo a procesos padre |
| Auditar procesos en ejecución | `cat /proc/sys/kernel/yama/ptrace_scope` |
| Minimizar exposición de claves de bastión | Si no se usa autenticación basada en bastión, restringir los ficheros de clave a los que accede `ssh-keysign` |

---

## 8. Lista de verificación de bastionado: 15 directivas para el cliente SSH

Tabla de referencia rápida de todas las directivas de bastionado del lado cliente recomendadas para Ubuntu 26.04, verificadas contra los valores por defecto del sistema:

| Directiva | Por defecto | Recomendado | Motivo |
|---|---|---|---|
| `ForwardAgent` | no | **no** | Riesgo de robo del socket del agente |
| `ForwardX11` | no | **no** | Superficie de ataque X11 |
| `ForwardX11Trusted` | yes | **no** | X11 de confianza evita Xsecurity |
| `StrictHostKeyChecking` | ask | **accept-new** | Acepta automáticamente la primera vez, rechaza cambios |
| `VerifyHostKeyDNS` | no | **yes** | Validación de clave de bastión por DNS |
| `EnableSSHKeysign` | no | **no** | Previene el ataque de filtrado de fd |
| `IdentitiesOnly` | no | **yes** | Usar solo las claves explícitamente listadas |
| `PubkeyAcceptedAlgorithms` | (todos) | **ssh-ed25519,rsa-sha2-512** | Deshabilitar firmas débiles |
| `HostKeyAlgorithms` | (todos) | **ssh-ed25519,ecdsa-sha2-nistp256** | Solo claves de bastión robustas |
| `KexAlgorithms` | (PQ por defecto) | **mlkem768x25519-sha256,curve25519-sha256** | Post-cuántico + repliegue clásico |
| `Ciphers` | (todos) | **chacha20-poly1305,aes256-gcm** | Solo cifrados AEAD |
| `MACs` | (todos) | **hmac-sha2-512-etm,hmac-sha2-256-etm** | Solo ETM (cifrar-después-MAC) |
| `Compression` | no | **no** | Previene ataques de oráculo de compresión |
| `CheckHostIP` | no | **yes** | Verificar que la IP coincide con `known_hosts` |
| `HashKnownHosts` | yes | **yes** | Hashear nombres de bastiones en `known_hosts` |

### Plantilla de `~/.ssh/config` bastionada

```
# ~/.ssh/config — Configuración bastionada del cliente SSH
# hackingyseguridad.com

Host *
    # Seguridad del agente
    ForwardAgent no
    
    # Reenvío X11
    ForwardX11 no
    ForwardX11Trusted no
    
    # Verificación de bastiones
    StrictHostKeyChecking accept-new
    VerifyHostKeyDNS yes
    CheckHostIP yes
    HashKnownHosts yes
    
    # Claves
    IdentitiesOnly yes
    EnableSSHKeysign no
    PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512
    HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256
    
    # Criptografía
    KexAlgorithms mlkem768x25519-sha256,curve25519-sha256
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
    
    # Miscelánea
    Compression no

# Ejemplo de bastión con ProxyJump (en lugar de ForwardAgent)
Host servidor-web.interna
    ProxyJump bastion.interna
    IdentityFile ~/.ssh/id_ed25519_prod
```

---

## 9. Preguntas frecuentes

**¿Debo desactivar la autenticación por contraseña en el lado cliente?**

El cliente no controla esto — lo hace el servidor. En el servidor, se recomienda desactivar la autenticación por contraseña y usar exclusivamente autenticación de clave pública Ed25519. Solo después de confirmar que el acceso por clave funciona:

```bash
sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

**¿Cómo verifico si mi conexión usa intercambio de claves post-cuántico?**

```bash
ssh -vvv usuario@bastión 2>&1 | grep kex
```

Deberías ver `mlkem768x25519-sha256` en los algoritmos negociados. Si aparece solo `curve25519-sha256` o peor, `diffie-hellman-group14-sha256`, el servidor o el cliente necesita actualización.

**¿Es seguro usar ssh-agent en un servidor compartido?**

No. En un servidor compartido, cualquier proceso ejecutado como el mismo usuario puede acceder al socket del agente. Si es imprescindible usar ssh-agent en una máquina compartida:

```bash
# Arrancar el agente con confirmación para cada uso
ssh-add -c ~/.ssh/id_ed25519
```

Mejor alternativa: usar `ProxyJump` en lugar del reenvío de agente.

**¿Cuál es la diferencia entre `ssh-ed25519` y `sk-ssh-ed25519`?**

- `ssh-ed25519`: clave Ed25519 por software, almacenada en disco.
- `sk-ssh-ed25519`: variante de llave de seguridad FIDO2 donde la clave privada nunca abandona el token hardware.

La versión de llave de seguridad requiere toque físico para cada autenticación, lo que la hace resistente al robo remoto aunque ligeramente menos cómoda.

---

## Conclusión

La seguridad del cliente OpenSSH en Ubuntu 26.04 está mejor de fábrica que nunca. El intercambio de claves post-cuántico es el valor por defecto, DSA ha desaparecido y los parches del núcleo frente a vulnerabilidades de robo de descriptores de fichero están en su lugar.

Sin embargo, **los valores por defecto son un punto de partida, no un destino**. Hay que verificar que los sockets del agente no están expuestos, que la verificación de bastiones es estricta, que la política de reenvío se ajusta al modelo de amenaza y que los algoritmos no se degradan por debajo de lo que proporcionan los valores por defecto.

Cada elemento de esta lista de verificación representa un vector de ataque real observado en entornos de producción. Revisar la configuración, verificarla y no asumir que por ser Ubuntu 26.04 es automáticamente seguro.

---

## Referencias

- [OpenSSH 10.2 Release Notes](https://www.openssh.com/releasenotes.html)
- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [CVE-2026-46333](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-46333)
- [CVE-2025-26465](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-26465)
- [Repositorio hackingyseguridad/IA](https://github.com/hackingyseguridad/ssha)

---

*Guía mantenida por [hackingyseguridad.com](https://hackingyseguridad.com) — Pentesting y seguridad ofensiva, Madrid.*
