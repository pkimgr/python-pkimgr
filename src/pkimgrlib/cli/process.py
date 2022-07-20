"""CLI module for wpki"""
from logging import Logger
import sys
import shlex
import shutil

from pkimgrlib.pki.pki import Pki
from pkimgrlib.misc import verify_dict_keys
from pkimgrlib.cli import arguments
from pkimgrlib.cli.misc_x509 import create_cert

# Dict for modify the color output
COLORS = {
    'yellow': '\033[1;33m',
    'green': '\033[1;32m',
    'red': '\033[1;31m',
    'normal': '\033[0;00m',
}

# The best banner of the world
BANNER = rf"""{COLORS['yellow']}
       __                    __  ____      __         __
      / /__  ____ _____     /  |/  (_)____/ /_  ___  / /
 __  / / _ \/ __ `/ __ \   / /|_/ / / ___/ __ \/ _ \/ /
/ /_/ /  __/ /_/ / / / /  / /  / / / /__/ / / /  __/ /
\____/\___/\__,_/_/ /_/  /_/  /_/_/\___/_/ /_/\___/_/
    ____  __ __ ____
   / __ \/ //_//  _/___ ___  ____ ______
  / /_/ / ,<   / // __ `__ \/ __ `/ ___/
 / ____/ /| |_/ // / / / / / /_/ / /
/_/   /_/ |_/___/_/ /_/ /_/\__, /_/
                          /____/
{COLORS['normal']}"""
# Necessary keys for differents dicts
PKIFILE_KEY = ['domain', 'authority', 'certs']
AUTHORITY_KEY = ['name', 'key']
CERT_KEY = ['key']


####################################################################################################
#                                       Process file
####################################################################################################
def process_file(prefix: str, cconf: dict, dpki: dict, logger: Logger) -> None:
    """Function used to create PKI from YAML file

    Args:
        prefix (str): the prefix path to use
        cconf (dict): Certificate configuration to use
        dpki (dict): PKI dict loaded from yaml file
        logger (Logger): Logger to use
    """
    if (missing := verify_dict_keys(dpki, PKIFILE_KEY)):
        logger.error(f'Missing {missing} keys on PKI file')
        print("Error while reading pki file, see log", file=sys.stderr)
        sys.exit(1)
    if (missing := verify_dict_keys(dpki['authority'], AUTHORITY_KEY)):
        logger.error(f'Missing {missing} keys for authority on PKI file')
        print("Error while reading pki file, see log", file=sys.stderr)
        sys.exit(1)
    logger.debug("Verification succeed, begin generation")

    print(f'[{COLORS["green"]}+{COLORS["normal"]}] Begin PKI generation')
    pki = Pki(prefix, cconf, dpki['domain'])

    print(f'[{COLORS["green"]}+{COLORS["normal"]}] Generate authority')
    pki.add_authority({
        'cname': dpki['authority']['name'],
        'key_type': dpki['authority']['key']['type'],
        'key_value': str(dpki['authority']['key']['value']),
        'altnames': dpki['authority']['altnames'] if 'altnames' in dpki['authority'] else [],
        'passphrase': dpki['authority']['passphrase'] if 'passphrase' in dpki['authority'] else '',
    })
    logger.info("%s authority successfully generated", pki.authority.cname)

    def _recurse(authority: str, subcert: dict, pki: Pki, logger: Logger) -> None:
        for cert, datas, in subcert['certs'].items():
            print(f'[{COLORS["green"]}+{COLORS["normal"]}] Generate {cert}')
            pki.add_certificate({
                'cname': datas['name'] if 'name' in datas else cert,
                'key_type': datas['key']['type'],
                'key_value': str(datas['key']['value']),
                'passphrase': datas['passphrase'] if 'passphrase' in datas else '',
                'altnames': datas['altnames'] if 'altnames' in datas else [],
                'auth': authority,
                'is_auth': 'is_authority' in datas and datas['is_authority'] or 'certs' in datas
            })
            logger.info("%s successfully added", cert)
            subcert_cname = '.'.join([(datas['name'] if 'name' in datas else cert), pki.domain])
            if 'certs' in datas:
                _recurse(subcert_cname, datas, pki, logger)

    _recurse(pki.authority.cname, dpki, pki, logger)
    logger.info("Certificate generation OK")
    print(f'[{COLORS["green"]}+{COLORS["normal"]}] Export metadatas')
    pki.export_metadatas()
    logger.info("Metatadata exported")


####################################################################################################
#                                       Process Cli
####################################################################################################
def cli(prefix: str, cconf: dict, logger: Logger) -> None:
    """Entry point for the CLI"""
    logger.info("Starting CLI")
    pki = Pki(prefix, cconf, 'new_pki')
    while True:
        try:
            sys.argv = shlex.split(' '.join([__file__, input(f'{pki.domain} >>> ')]))
        except KeyboardInterrupt:
            if pki.authority is not None:
                pki.export_metadatas()
            else:
                shutil.rmtree(pki.path)
            print(f'{COLORS["yellow"]} Bye !{COLORS["normal"]}')
            sys.exit(0)
        args = arguments.command_args()
        if not args or not args.action:
            continue
        if args.action == 'quit':
            pki.export_metadatas()
            print(f'{COLORS["yellow"]} Bye !{COLORS["normal"]}')
            sys.exit(0)
        process_line(args, pki, logger)


def process_line(args: str, pki: Pki, logger: Logger) -> None:
    """Call the correct functions for one line

    Args:
            args (str): the line to manage
            domain (str, optional): the domain of the PKI. Defaults to ''.
            path (str, optional): the path where store files. Defaults to PREFIX.
    """
    try:
        if args.action == 'cert':
            if args.c_action.lower() == 'load':
                print("todo")
            else:
                ret = create_cert(args, pki, logger)
        if args.action == 'pki':
            pki.domain = args.domain
            ret = 'OK'
    except ValueError as error:
        print(f'{COLORS["red"]}Error{COLORS["normal"]} {str(error)}')
        return
    print(f'{COLORS["green"]}Success{COLORS["normal"]} ({ret})')
