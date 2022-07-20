"""Modules for CLI actions"""
import argparse
from logging import Logger

from pkimgrlib.pki.pki import Pki


def create_cert(args: argparse.Namespace, pki: Pki, logger: Logger) -> str:
    """Manage Certificate part for the CLI

    Args:
        args (argparse.Namespace): Arguments from CLI
        conf_d (dict): loaded configuration for Certificates

    Raises:
        ValueError: Cannot instanciate CertX509, message explain the error

    Returns:
        str: Text explaining the result of the function
    """
    # Transform altnames str on str list by splitting by comma
    args.altnames = args.altnames.split(',')

    # Root certificate here
    if args.is_auth and not args.auth:
        pki.add_authority(vars(args))
    else:
        if not pki.authority:
            raise ValueError('The certificate must be auth or auth must be created first')
        # load the auth cert
        if args.is_auth:
            # Need to create subauthority here
            pki.add_certificate(vars(args))
        else:
            try:
                pki.add_certificate(vars(args))
            except (FileNotFoundError, ValueError) as err:
                logger.error('Error while instanciate CertX509: %s', str(err))
                raise ValueError(f'Error while instanciate CertX509: {str(err)}') from err
    return 'OK'
