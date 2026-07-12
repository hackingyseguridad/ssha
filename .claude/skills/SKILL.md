---
name: ssh-auditoria-seguridad
description: Ayuda a orientarse en el repositorio hackingyseguridad/ssha (utilidades de auditoría, escaneo y explotación de vulnerabilidades SSH) para tareas de auditoría de seguridad SSH autorizada — identificar qué script corresponde a qué CVE o categoría (auditoría de cifrados, enumeración de usuarios, fuerza bruta, PoC de CVEs, hardening de sshd), verificar autorización antes de cualquier acción ofensiva y priorizar siempre las rutas de detección/auditoría/defensa. Úsala cuando el usuario pregunte por vulnerabilidades SSH, quiera auditar un servidor SSH propio, necesite entender qué hace un script del repositorio ssha, o pida ayuda para reforzar la configuración de sshd.
---

# ssh-auditoria-seguridad

Skill de orientación para el repositorio [`hackingyseguridad/ssha`](https://github.com/hackingyseguridad/ssha): utilidades de auditoría, escaneo y explotación de vulnerabilidades SSH.

## Antes de nada: verificación de autorización

Este repositorio mezcla dos tipos de contenido muy distintos:

- **Auditoría/detección** (no intrusivo): escaneo de versión, cifrados ofrecidos, `ssh-audit`, detección de Terrapin, revisión de logs, plantillas de `sshd_config` seguras.
- **Explotación/ofensivo** (intrusivo): PoC de RCE (regreSSHion), enumeración de usuarios, fuerza bruta de credenciales.

**Regla fija de esta skill:** antes de generar o explicar cómo ejecutar cualquier script del segundo grupo contra un host, confirma explícitamente con el usuario que:
1. el host objetivo es de su propiedad o cuenta con autorización escrita para la prueba, y
2. el contexto es un laboratorio, CTF o auditoría contratada — no un sistema de terceros sin permiso.

Si no hay confirmación clara, o el contexto sugiere un objetivo ajeno, no generes el comando ofensivo: explica el motivo y redirige hacia la parte de auditoría/detección (que es igualmente útil y no requiere las mismas garantías, aunque igualmente solo debe usarse contra sistemas propios o autorizados). Nunca generes exploits o técnicas de ataque nuevas más allá de citar qué script del repositorio ya existente cubre ese CVE.

## Mapa del repositorio

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

## Flujo recomendado ante una petición

1. **Clasifica la petición** usando la tabla anterior: ¿auditoría/defensa o explotación?
2. **Si es auditoría/defensa** (versión, cifrados, Terrapin, hardening, logs): ayuda directamente — indica el script correspondiente y qué interpretar del resultado. No requiere el mismo nivel de confirmación, pero recuerda que sigue debiendo ejecutarse solo contra sistemas propios.
3. **Si es ofensiva** (enumeración, fuerza bruta, PoC de RCE): aplica la verificación de autorización de arriba. Solo si el usuario confirma un contexto legítimo, indica qué script del repositorio corresponde a la CVE/técnica solicitada y su propósito general, dejando que sea el propio usuario quien revise la cabecera del script para los parámetros exactos — no generes tú instrucciones adicionales de explotación más allá de las ya documentadas en el proyecto.
4. **Prioriza siempre la vía defensiva como recomendación adicional**: si el usuario pregunta cómo explotar un CVE, añade también cómo mitigarlo (parche, configuración, SSHGuard/fail2ban).

## Selección rápida por síntoma

- "¿Qué versión de SSH corre este servidor?" → `versionssh.sh` / `verssh.sh`.
- "¿Usa cifrados obsoletos?" → `scanciphers.sh`, contrastar con `ssh_cifrados_vulnerables.md`.
- "¿Es vulnerable a Terrapin?" → `terapinscan.sh`.
- "Quiero una puntuación general de seguridad del servidor" → `ssh-audit.sh` / `sshaudit.sh`.
- "¿Cómo reviso quién se ha conectado / intentos fallidos?" → `verlogssh.sh`, `verconexiones.sh`.
- "Quiero endurecer mi propio `sshd_config`" → `sshd_config` / `configuracion.txt` + `sshguard.conf`.
- "¿Este servidor es vulnerable a regreSSHion (CVE-2024-6387)?" → primero contrastar versión con `versionssh.sh`; solo si hay autorización para probar, referenciar `CVE-2024-6387.nse` (vía `nmapxsalto.sh`) como comprobación menos intrusiva antes que el PoC de explotación completo.
- "Necesito hacer fuerza bruta / enumerar usuarios" → exige confirmación de autorización antes de mencionar `brutessh*.sh` / `sshusers.sh`.

## Buenas prácticas a recordar siempre

- Preferir la detección (escaneo de versión, `ssh-audit`, NSE) sobre la explotación activa cuando el objetivo sea simplemente saber si algo es vulnerable.
- Recomendar actualizar OpenSSH y aplicar `sshd_config` endurecido como cierre de cualquier hallazgo.
- No generar variantes nuevas de los PoC ni combinarlos de forma que amplíen su alcance más allá de lo ya publicado en el repositorio.

## Licencia del repositorio

GPL-3.0 — ver [`LICENSE`](https://github.com/hackingyseguridad/ssha/blob/master/LICENSE) en el repositorio original.
