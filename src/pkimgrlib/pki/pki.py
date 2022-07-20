"""Module for PKI abstract class"""
import os
import shutil
from string import whitespace
from typing import Optional, List

import yaml

from pkimgrlib.misc import get_logger, verify_dict_keys
from pkimgrlib.pki.x509 import CertX509

SEPARATOR = '\t'
AUTHORITY_KEYS = ['cname', 'key_type', 'key_value']
CERTIFICATE_KEYS = ['cname', 'key_type', 'key_value', 'auth']
INDEX_TYPES_FIELDS = {
    'revoked': 'R',
    'expired': 'E',
    'valid': 'V',
}


class Pki:
    """PKI Class implementation"""
    def __init__(self, path: str, cert_conf: dict, domain: str='') -> None:
        """Class constructor

        Args:
            path (str): The path used to store the current PKI
            cert_conf (dict): Configuration used for Certificates
            domain (str, optional): The domain to use for the PKI. Defaults to ''.
        """
        self.logger = get_logger('pki')
        self._path = os.path.join(path, domain) if domain else path
        self.cconf = cert_conf
        self._domain = domain

        self._certs = {'authority': None, 'certs': {}}
        self._metadatas = {
            'serial': 1,
            'db': {},
        }
        if os.path.exists(self.path):
            self.logger.info("Loading the existing PKI %s from %s TODO", domain, self._path)
            #self._load_pki()
        else:
            self.logger.info("Creating path %s for the PKI", self._path)
            os.makedirs(self._path, exist_ok=True)

    @property
    def domain(self) -> str:
        """The domain used on this PKI

        when this value is set, if any certificate has been created before, all this certificate
        will be regenerated.
        """
        return self._domain

    @property
    def path(self) -> str:
        """The storage path of the current PKI

        when this value is set, all created certificates are be moved to new destination and the old
        is removed
        """
        return self._path

    @property
    def authority(self) -> Optional[CertX509]:
        """The cert authority of the current PKI"""
        return self._certs['authority']

    @property
    def sub_authorities(self) -> List[CertX509]:
        """Dict of sub authority of the current PKI"""
        acc = []

        def _recurs(certs, acc) -> List[CertX509]:
            for cert, datas in certs.items():
                if 'certs' in datas:
                    acc.append(cert)
                    _recurs(datas['certs'], acc)
        _recurs(self._certs['certs'], acc)
        return acc

    @property
    def certs(self) -> List[CertX509]:
        """Ceritifcates list of the current PKI"""
        def _recurs(certs, acc) -> List[str]:
            for cert, datas in certs.items():
                if 'certs' not in datas:
                    acc.append(cert)
                else:
                    _recurs(datas['certs'], acc)
        acc = []
        _recurs(self._certs['certs'], acc)
        return acc

    @property
    def database(self) -> dict:
        """The db metadatas of the current PKI"""
        return self._metadatas['db']

    @property
    def serial(self) -> int:
        """The serial of the current PKI"""
        return self._metadatas['serial']

    @domain.setter
    def domain(self, new_domain: str) -> None:
        # Replace all white spaces by '_' on new domain
        translate = new_domain.maketrans(whitespace, ''.join([len(whitespace) * '_']))
        # Apply the translation
        new_domain = new_domain.translate(translate)
        if self.domain:
            self._domain = new_domain
            self.path = os.path.dirname(self.path)
        else:
            self._domain = new_domain
            self.path = self.path
        # Regenerating all certificates
        if self.authority:
            self.logger.warning("All certificates will be regenerated now")
            self.logger.info("Regenerating authority %s for %s", self.authority.cname, new_domain)
            old_cname = self.authority.cname
            self.authority.cname = '.'.join([self.authority.cname.split('.')[0], new_domain])
            # Updating metadatas
            del self._metadatas['db'][old_cname]
            self.__update_metadatas(self.authority)
        for cert in self.sub_authorities + self.certs:
            self.logger.info("Regenerating %s for %s", cert.cname, new_domain)
            old_cname = cert.cname
            cert.cname = '.'.join([cert.cname.split('.')[0], new_domain])
            del self._metadatas['db'][old_cname]
            self.__update_metadatas(cert)

    @path.setter
    def path(self, new_path: str) -> None:
        if self.domain:
            new_path = os.path.join(new_path, self.domain)
        self.logger.debug("Copying files from %s to %s", self.path, new_path)
        shutil.copytree(self.path, new_path, dirs_exist_ok=True)
        # Modifying all certs and key paths
        if self.authority:
            self.authority.cert_path = os.path.join(
                new_path, f'certs/{os.path.basename(self.authority.cert_path)}'
            )
            self.authority.key_path = os.path.join(
                new_path, f'private/{os.path.basename(self.authority.key_path)}'
            )
            self.logger.info("Authority %s successfully updated", self.authority.cname)
        for cert in self.sub_authorities + self.certs:
            cert.cert_path = os.path.join(
                new_path, f'certs/{os.path.basename(cert.cert_path)}'
            )
            cert.key_path = os.path.join(
                new_path, f'private/{os.path.basename(cert.key_path)}'
            )
            self.logger.info("Certificate %s successfully updated", cert.cname)

        shutil.rmtree(self.path)
        self._path = new_path

    def add_authority(self, args: dict) -> None:
        """_summary_
        Args:
            -args (dict): a dict with keys:
                cname (str): The common name of this certificate
                key_type (str): The type of key used "rsa" or "ec"
                key_value(str): the value associated with key type (more infos on CertX509 class)
                altnames([str]): List of altnames used for this authority
                passphrase(str, optionnal): The passphrase used on key file

        Raises:
            ValueError: if missing key on dict while setting this value
        """
        if self.authority:
            self.logger.warning("Authority modified, all previous certs will be regenerated")
            del self._metadatas['db'][self.authority.cname]
            if self.authority.cert_path:
                os.remove(self.authority.cert_path)
            if self.authority.key_path:
                os.remove(self.authority.key_path)
        if (keys := verify_dict_keys(args, AUTHORITY_KEYS)):
            raise ValueError(f'Missing {", ".join(keys)} while creating authority')
        if args['key_type'].lower().strip() not in ['ec', 'rsa']:
            raise ValueError(f'Invalid key type {args["key_type"]} passed on certificate creation')
        # misc vars used after
        passphrase = args['passphrase'] if 'passphrase' in args else ''
        cname = '.'.join([args['cname'], self.domain]) if self.domain else args['cname']
        auth = CertX509(cname, self.cconf, self.path, True, passphrase=passphrase)
        # Generate key and certificate
        if args['key_type'].lower().strip() == 'ec':
            auth.generate_ec_key(args['key_value'].strip())
        else:
            auth.generate_rsa_key(int(args['key_value'].strip()))
        auth.generate_certificate([])
        self._certs['authority'] = auth
        self.logger.info("Authority %s generated, updating metadatas", auth.cname)
        self.__update_metadatas(auth)

    def add_certificate(self, args: dict) -> None:
        """Add new certificat on current PKI

        Args:
            args (dict): values for certificat creation, necessary keys are:
                cname (str): Then common name of the certificate
                key_type (str): The type of key used "ec" or "rsa"
                key_value (str): the value associated with the key (more info on CertX509 class)
                auth (str): The cname of the authority to use
                altnames (List[str], Optional): Altnames used for the certificat
                passphrase (str, Optional): Passphrase used for the certificate
                is_auth (bool, Optional): If the current certificate is authority

        Raises:
            AssertionError: if authority cannot be found
            ValueError: if arg is invalid or key_type is invalid
        """
        assert self.authority, "Add an authority before adding certificate on PKI"
        if (keys := verify_dict_keys(args, CERTIFICATE_KEYS)):
            raise ValueError(f'Missing {", ".join(keys)} while creating certificate')
        if args['key_type'].lower().strip() not in ['ec', 'rsa']:
            raise ValueError(f'Invalid key_type {args["key_type"]} passed on certificate creation')
        # Find the authority to use
        if args['auth'] == self.authority.cname:
            authority = self.authority
        elif (subcert := [s for s in self.sub_authorities if s.cname == args['auth']]):
            authority = subcert[0]
        else:
            raise ValueError("provide authority for the current cert")
        assert authority.is_authority, f'The cert {authority.cname} is not authority cannot sign'

        pphrase = args['passphrase'] if 'passphrase' in args else ''
        cname = '.'.join([args['cname'], self.domain]) if self.domain else args['cname']
        altnames = args['altnames'] if 'altnames' in args else [cname]
        # Create the certificate
        if 'is_auth' in args and args['is_auth']:
            # Create sub authority
            cert = CertX509(
                cname, self.cconf, self.path,
                authority=authority, passphrase=pphrase, is_authority=True
            )
        else:
            # Create simple certificate here
            cert = CertX509(
                cname, self.cconf, self.path, authority=authority, passphrase=pphrase
            )

        if args['key_type'].lower().strip() == 'ec':
            cert.generate_ec_key(args['key_value'].strip())
        else:
            cert.generate_rsa_key(int(args['key_value'].strip()))
        cert.generate_certificate(altnames)

        self.logger.info('Certificate %s generated, updating metadatas', cert.cname)
        if authority == self.authority:
            self._certs['certs'][cert] = {'passphrase': cert.passphrase.decode('utf-8')}
            if cert.is_authority:
                self._certs['certs'][cert]['certs'] = {}
        else:
            self._append_cert(cert, authority, self._certs['certs'])

        self.__update_metadatas(cert)

    def export_metadatas(self) -> None:
        """Write all metadatas on files for this PKI"""
        self.logger.info("Exports metadatas on '%s' dir", self.path)

        self.logger.info("Write '%s/index.txt'", self.path)
        with open(os.path.join(self.path, 'index.txt'), 'wb') as index_f:
            for line in self.database.values():
                index_f.write(f'{line}\n'.encode('utf-8'))
        self.logger.info("Write '%s/index.txt' OK", self.path)

        self.logger.info("Write '%s/serial'", self.path)
        with open(os.path.join(self.path, 'serial'), 'wb') as serial_f:
            serial_f .write(f'{self.serial}'.encode('utf-8'))
        self.logger.info("Write '%s/serial' OK", self.path)

        self.logger.info("Write '%s/passphrases.csv", self.path)
        with open(os.path.join(self.path, 'passphrases.yaml'), 'w', encoding='utf-8') as pphrase_f:
            acc: dict = {
                'authority': {
                    self.authority.cname: {'passphrase': self.authority.passphrase.decode('utf-8')}
                },
                'certs': {}
            }

            def _recurse(certs: dict, acc: dict) -> None:
                for cert, datas in certs.items():
                    acc[cert.cname] = {'passphrase': datas['passphrase']}
                    if cert.is_authority:
                        acc[cert.cname]['certs'] = {}
                    if cert.is_authority:
                        _recurse(datas['certs'], acc[cert.cname]['certs'])
            _recurse(self._certs['certs'], acc['certs'])
            yaml.safe_dump(acc, pphrase_f)

    def _append_cert(self, newcert: CertX509, authority: CertX509, cert_d: dict) -> None:
        for cert, datas in cert_d.items():
            if cert == authority:
                datas['certs'][newcert] = {'passphrase': newcert.passphrase.decode('utf-8')}
                if newcert.is_authority:
                    datas['certs'][newcert]['certs'] = {}
                return
            if cert.is_authority:
                self._append_cert(newcert, authority, datas['certs'])

    def __update_metadatas(self, cert: CertX509) -> None:
        """Modify the metadatas of the current PKI for the provided Cert

        Args:
            cert (CertX509): The certificat to add on metadatas
        """
        self.logger.debug("updating metadatas with %s cert", cert.cname)
        self._metadatas['db'][cert.cname] = SEPARATOR.join([
            INDEX_TYPES_FIELDS['valid'],
            cert.expiration_date,
            str(hex(self.serial)).zfill(2),
            cert.cert_path,
            cert.subject,
        ])
        self._metadatas['serial'] += 1
