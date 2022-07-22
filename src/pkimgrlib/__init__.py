"""
pkimgrlib module provides a set of objects to create and load PKI

author: Wampixel
Maintainer: Wampixel
Contact: Issue on https://gitlab.com/pkimgr/python-pkimgr
"""

__version__ = "1.3.0"

# Certs part
from pkimgrlib.pki.pki import Pki
# CLI part
from pkimgrlib.cli.process import BANNER, COLORS
from pkimgrlib.cli.process import cli, process_file
# Default prefix where we manage certs and pki
PREFIX = 'output'
