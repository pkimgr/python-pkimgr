"""This module implement arguments for the wpki CLI"""
# Built-in imports
import sys
import argparse

OBJTYPES = ['cert', 'pki']
KEYTYPES = ['rsa', 'ec']


def command_args() -> argparse.Namespace:
    """Parse and return all arguments for CLI

    Returns:
        argparse.Namespace: The namespace of parsed from sys.arg
    """
    try:
        parser = argparse.ArgumentParser(prog='>>>', exit_on_error=False)
    except TypeError:
        parser = argparse.ArgumentParser(prog='>>>')

    subparsers = parser.add_subparsers(help='List of managed objects', dest='action')

    subparsers.add_parser('quit', help='quit the CLI')

    pki = subparsers.add_parser('pki', help='Set the type object to manage')
    pki.add_argument('domain', type=str, help='Domain for the PKI')
    pki.add_argument('-p', '--path', type=str, help='Path to store files')

    cert = subparsers.add_parser('cert', help='Manage new certs')
    subcert = cert.add_subparsers(help='Cert subcomands', dest='c_action')
    c_new = subcert.add_parser('new', help='Create new certificate')
    c_new.add_argument('cname', type=str, help='Common name for the Certificate')
    c_new.add_argument('key_type', type=str, help='Type of the key to use', choices=KEYTYPES)
    c_new.add_argument('key_value', type=str, help='Size or curve to use for the key')
    c_new.add_argument('-d', '--dir', type=str, help='Path where create files')
    c_new.add_argument('-a', '--is_auth', help='Certificate is authority', action='store_true')
    c_new.add_argument('-p', '--passphrase', type=str, help='Passphrase for the new certificate')
    c_new.add_argument('-A', '--auth', type=str, help='authority name to sign the certificate')
    c_new.add_argument('-P', '--auth_pass', type=str, help='Passphrase for authority certifcate')
    c_new.add_argument('-n', '--altnames', type=str, help='altnames separated by comma', default='')
    c_load = subcert.add_parser('load', help='Load an existing Certificate')
    c_load.add_argument('cname', type=str, help='Common name for the Certificate')
    c_load.add_argument('passphrase', type=str, help='Passphrase for the new certificate')
    c_load.add_argument('-p', '--path', type=str, help='The path where Certificate is stored')

    if 'help' in sys.argv:
        parser.print_help()
        return None
    try:
        return parser.parse_args()
    except SystemExit:
        return None
    except argparse.ArgumentError:
        parser.print_help()
        return None
