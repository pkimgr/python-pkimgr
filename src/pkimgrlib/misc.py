"""Misc functions for PKI manager"""
# imports
import os
import sys
import string
import logging
import logging.config
from random import choice

import yaml

# Global vars
PASSPHRASE_POLICY_KEYS = ['chars', 'length']


####################################################################################################
#                                   Logger management
####################################################################################################
def get_logger(name: str) -> logging.Logger:
    """ Create and return logger defined on configuration file
       The configuration file must be overwritten on /etc/pkimgr/logger.conf
    Args:
        name (str): The name of the logger needed
    """
    # Get the configuration file
    if os.path.exists('/etc/pkimgr/logger.conf'):
        logger_conf_file = '/etc/pkimgr/logger.yaml'
    else:
        logger_conf_file = os.path.join(sys.prefix, 'pkimgr/default_conf/logger.yaml')
        if not os.path.exists(logger_conf_file):
            raise ValueError(f'{logger_conf_file} is needed')
    try:
        with open(logger_conf_file, 'rb') as logconf_f:
            conf = yaml.safe_load(logconf_f.read())
    except yaml.YAMLError as err:
        print(f'Error: "{str(err)}" occurred when loading config file for logger', file=sys.stderr)

    logging.config.dictConfig(conf)
    return logging.getLogger(name)


####################################################################################################
#                                    Dict management
####################################################################################################
def verify_dict_keys(source_d: dict, key_l: list[str]) -> list[str]:
    """Verify if keys from key_l are present on dict and return the list of missing keys

    Args:
        source_d (dict): dict to verify
        key_l (list): list of key needed on dict.

    Returns:
        list: The list of the key not present on dict
    """
    return [key for key in key_l if key not in source_d.keys()]


####################################################################################################
#                                   Passphrase management
####################################################################################################
def generate_passphrase(policy: dict) -> str:
    """Generate new passphrase according to the policy

    Args:
        policy (dict): the policy to apply on the new passphrase

    Raises:
        ValueError: if the policy dict is not valid

    Returns:
        str: the generated passphrase
    """
    if (i := verify_dict_keys(policy, PASSPHRASE_POLICY_KEYS)):
        raise ValueError(f'verify_passphrase: missing {i} keys for the passphrase policy')
    # Switch case like for the char pool to use
    if policy['chars'].lower() == 'letters':
        chars = string.ascii_letters
    elif policy['chars'].lower() == 'numbers':
        chars = string.digits
    else:
        chars = string.ascii_letters + string.digits + string.punctuation

    return "".join(choice(chars) for i in range(policy['length']))


def verify_passphrase(policy: dict, passphrase: str) -> bool:
    """Verify that the passphrase respect the policy

    Args:
        policy (dict): The policy to apply on the passphrase
        passphrase (str): The passphrase to check

    Raises:
        ValueError: if the policy dict is not valid

    Returns:
        bool: True if the passphrase is conform to length and charpool, False, else
    """
    if (i := verify_dict_keys(policy, PASSPHRASE_POLICY_KEYS)):
        raise ValueError(f'verify_passphrase: missing {i} keys for the passphrase policy')
    if not passphrase:
        return False
    # Get vars locally
    length = policy['length']
    # Get all capitalized chars from password
    upper_chars = [c for c in passphrase if c.isupper()]
    # password must be greater or equal than policy length
    if len(passphrase) < length:
        return False
    # Test password according to configuration
    if policy['chars'] == 'letter':
        return str.isalpha(passphrase) and len(upper_chars) > 0
    if policy['chars'] == 'numeric':
        return str.isnumeric(passphrase)
    # Default return all chars are alphanumeric
    return str.isprintable(passphrase) and len(upper_chars) > 0
