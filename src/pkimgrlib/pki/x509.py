"""x509 Certificate modules"""
# System imports
import os
import shutil
import base64
import datetime
from typing import List
# Cryptography imports
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
# Local imports
from pkimgrlib.misc import get_logger
from pkimgrlib.misc import verify_dict_keys
from pkimgrlib.misc import generate_passphrase, verify_passphrase

# Global vars
# All necessary keys for the configuration file
CONFKEYS = ['passphrase_policy', 'cert_options']
# All necessary keys for the cert options
CERT_OPTIONS_KEYS = [
    'country', 'state', 'locality', 'organization', 'organizationalUnit', 'validity'
]
CURVE_LST = 'https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#elliptic-curves'


# Class implementation
class CertX509:
    """ Class implementing generation for X509 certs for PKI"""
    def __init__(self, cname: str, conf_d: dict, loadpath: str, is_authority: bool=False, **kwargs):
        """Class constructor
        If not is_authority, authority args must be set

        Args:
            cn (str): The common name for the current certificate
            conf_d (dict): The default configuration to use for the Certificate
            loadpath (str): The path where manage certs and key files
            is_authority (bool, optional): True if the current cert is authority. Default to False.
            authority (CertX509, optional): The authority certificate object
            passphrase (str, optional): Password to use for the current certificate

        Raises:
            ValueError: If an argument is not conform
            FileNotFoundError: If one file does not exist
        """
        if (i := verify_dict_keys(conf_d, CONFKEYS)):
            raise ValueError(f'Missing {",".join(i)} keys on configuration file')
        if (i := verify_dict_keys(conf_d['cert_options'], CERT_OPTIONS_KEYS)):
            raise ValueError(f'Missing {",".join(i)} keys on cert_options')
        if (not is_authority and 'authority' not in kwargs):
            raise ValueError('Missing authority arguments if this cert is not an authority')
        # Get the logger
        self.logger = get_logger('certs')
        # Create the target path
        os.makedirs(os.path.join(loadpath, 'certs'), exist_ok=True)
        os.makedirs(os.path.join(loadpath, 'private'), exist_ok=True)
        # Misc dict attributes
        self.conf_d = conf_d
        self._certdata = {
            'cname': cname,
            'cert': None,
            'cpath': os.path.join(loadpath, f'certs/{cname}.crt'),
            'key': None,
            'kpath': os.path.join(loadpath, f'private/{cname}.pem')
        }
        # Load the existing file if necessary
        if os.path.exists(self._certdata['cpath']) and os.path.exists(self._certdata['kpath']):
            if not kwargs['passphrase']:
                raise ValueError(f'{cname} exists, cannot be loaded, missing key passphrase')
            self.logger.info('Loading existing cert %s', cname)
            with open(self._certdata['cpath'], 'rb') as certfile:
                self._certdata['cert'] = x509.load_pem_x509_certificate(certfile.read())
            with open(self._certdata['kpath'], 'rb') as key_f:
                self._certdata['key'] = serialization.load_pem_private_key(
                    key_f.read(),
                    bytes(kwargs['passphrase'].encode('utf-8'))
                )
            self.logger.info('cert %s successfully loaded', cname)
        # str attributes
        if ('passphrase' in kwargs
                and verify_passphrase(self.conf_d['passphrase_policy'], kwargs['passphrase'])):
            self._passphrase = kwargs['passphrase'].encode('utf-8')
            self.logger.debug('use provided passphrase for %s', cname)
        else:
            self._passphrase = base64.b64encode(
                generate_passphrase(self.conf_d['passphrase_policy']).encode('utf-8')
            )
            self.logger.debug('Passphrase for %s: %s', cname, self.passphrase.decode('utf-8'))
        # bool attributes
        self.is_authority = is_authority
        if 'authority' in kwargs:
            if not isinstance(kwargs['authority'], CertX509):
                raise ValueError('The authority is not valid')
            self.authority = kwargs['authority']

    @property
    def cname(self) -> str:
        """Common name of the current certificate"""
        return self._certdata['cname']

    @property
    def altnames(self) -> List[str]:
        """Subject alternative names of the current certificate"""
        if self._certdata['cert'] and not self.is_authority:
            return self._certdata['cert'].extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        return []

    @property
    def passphrase(self) -> str:
        """Passphrase used for the current certificate"""
        return self._passphrase

    @property
    def subject(self) -> str:
        """Subject of the current certificate"""
        if self._certdata['cert']:
            return self._certdata['cert'].subject.rfc4514_string()
        return None

    @property
    def expiration_date(self) -> str:
        """Expiration date of the current certificate"""
        if self._certdata['cert'] and self._certdata['cert'].not_valid_after:
            return self._certdata['cert'].not_valid_after.isoformat()
        return None

    @property
    def cert_path(self) -> str:
        """Certificate absolute path"""
        return self._certdata['cpath']

    @property
    def key_path(self) -> str:
        """Key absolute path"""
        return self._certdata['kpath']

    @cname.setter
    def cname(self, new_cn: str) -> None:
        # Save olds paths to delete and move at the end
        old_cpath = self._certdata['cpath']
        old_kpath = self._certdata['kpath']
        # Set the new cn
        self.logger.info("Cert %s is changing his CN to %s", self.cname, new_cn)
        self._certdata['cname'] = new_cn
        # Set the new paths
        self.cert_path = os.path.join(os.path.dirname(old_cpath), f'{new_cn}.crt')
        self.key_path = os.path.join(os.path.dirname(old_kpath), f'{new_cn}.pem')
        # Regenerate new certificate
        self.generate_certificate(self.altnames)
        # Move and delete olds files
        shutil.move(old_kpath, self.key_path)
        os.remove(old_cpath)

    @passphrase.setter
    def passphrase(self, new_passphrase: str) -> None:
        if not verify_passphrase(self.conf_d['passphrase_policy'], new_passphrase):
            raise ValueError(f'{new_passphrase} does not respect the policy')
        self._passphrase = base64.b64encode(new_passphrase.encode('utf-8'))
        self.logger.info('Passphrase successfully set')
        self.logger.debug('Passphrase is now %s', self.passphrase)

    @cert_path.setter
    def cert_path(self, new_path: str) -> None:
        if not os.path.exists(os.path.dirname(new_path)):
            self.logger.info('%s does not exists, create it', new_path)
            os.makedirs(os.path.dirname(new_path))
        self._certdata['cpath'] = new_path
        self.logger.info('Cert path for %s successfully set to %s', self.cname, new_path)

    @key_path.setter
    def key_path(self, new_path: str) -> None:
        if not os.path.exists(os.path.dirname(new_path)):
            self.logger.info('%s does not exists, create it', new_path)
            os.makedirs(os.path.dirname(new_path))
        self._certdata['kpath'] = new_path
        self.logger.info('key path for %s successfully set to %s', self.cname, new_path)

    def generate_rsa_key(self, klen: int=3072) -> str:
        """Generate new RSA Key for the current Certificate

        Args:
            klen (int, optional): The len for the new key. Defaults to 3072.

        Raises:
            ValueError: If the key size is invalid

        Returns:
            str: The path of the created file for the new key
        """
        # According to the RGS (Référentiel général de sécurité from French ANSSI):
        # - The exponent must be greater than 65536, so we set to 65537
        # - The key must be greater or equal to 3072 if the key is used beyond 2030
        try:
            self._certdata['key'] = rsa.generate_private_key(public_exponent=65537, key_size=klen)
        except ValueError as err:
            self.logger.error('Cannot generate key: %s', str(err))
            raise ValueError(str(err)) from err
        with open(self.key_path, 'wb') as kfile:
            kfile.write(self._certdata['key'].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase)
            ))
        self.logger.info('Successfully generated RSA key %s', self.key_path)
        return self.key_path

    def generate_ec_key(self, curve_name: str='secp256r1') -> str:
        """Generate new Elliptic Curve key for the current certificate

        Args:
            curve_name (str, optional): The name of the curve to use. Defaults to 'SECP384R1'.

        Returns:
            str: The path of the created file for the new key

        Raises:
            ValueError: If the provided curve name does not exists on crypto ec object
        """
        # Trying retrieve the curve from the name on the ec object
        try:
            curve = getattr(ec, curve_name.upper())
        except AttributeError as err:
            self.logger.error('Invalid %s, see cryptography doc for available curves', curve_name)
            raise ValueError(f'{curve_name} is not valid curve see {CURVE_LST}') from err

        self._certdata['key'] = ec.generate_private_key(curve)

        with open(self.key_path, 'wb') as kfile:
            kfile.write(self._certdata['key'].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase)
            ))
        self.logger.info('Successfully generated EC key %s', self.key_path)
        return self.key_path

    def generate_certificate(self, altnames: List[str]) -> str:
        """Generate the Cert file for the current Certificate

        Args:
            altnames (List[str]): all altnames for the certificate (not used for authority)

        Returns:
            str: The path of the created certfile (.crt)
        """
        assert isinstance(altnames, List), 'Altnames must be list of str'
        # Check that the current cname is ont altnames, append it if necessary
        if self.cname not in altnames:
            altnames.append(self.cname)

        certs_opts = self.conf_d['cert_options']
        # Subjects for the current certificate, informations came frome default cert conf file
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, certs_opts['country']),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, certs_opts['state']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, certs_opts['locality']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, certs_opts['organization']),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, certs_opts['organizationalUnit']),
            x509.NameAttribute(NameOID.COMMON_NAME, self.cname)
        ])

        if not hasattr(self, 'authority'):
            self.__generate_authority(subject, certs_opts['validity'])
        else:
            csr = self.__gen_csr(subject, altnames)
            self._certdata['cert'] = self.authority.sign_csr(
                csr,
                certs_opts['validity'],
                self._certdata['key'].public_key()
            )
            self.logger.info('%s has been signed by %s', self.cname, self.authority.subject)
        # Write the certificate on disk
        with open(self.cert_path, 'wb') as cfile:
            cfile.write(self._certdata['cert'].public_bytes(serialization.Encoding.PEM))

        self.logger.info('Successfully generated Certificate %s', self.cert_path)
        return self.cert_path

    def sign_csr(
        self, csr: x509.CertificateSigningRequest, validity: int, public_key: rsa.RSAPublicKey
    ) -> None:
        """Use the auth to sign the CSR and return the certificate

        Args:
            csr (x509.CertificateSigningRequest): The certificate to sign
            validity (int): the validity time for the Certificate
        """
        assert self.is_authority, 'Only Authority can sign CSR'
        self.logger.info('%s signing %s certificate', self.cname, csr.subject)
        return x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self._certdata['cert'].subject
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity)
        ).add_extension(
            csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
            critical=False
        ).add_extension(
            csr.extensions.get_extension_for_class(x509.BasicConstraints).value,
            critical=True
        ).sign(self._certdata['key'], hashes.SHA256())

    def __generate_authority(self, subject: x509.Name, validity: int) -> None:
        """Generate new Root certificate (self signed)

        Args:
            subject (x509.Name): the subject and issuer for the current certificate (self signed)
            validity (int): number of days that the certificate is valid from now (utc time)
        """
        self._certdata['cert'] = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            self._certdata['key'].public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(self._certdata['key'], hashes.SHA256())

    def __gen_csr(self, subject: x509.Name, altnames: List[str]) -> x509.CertificateSigningRequest:
        """Generate new CSR for the current certificate, this CSR must be signed by the authority

        Args:
            subject (x509.Name): The subject for the current certificate
            altnames (list): all alternative names for the current Certificate

        Returns:
            x509.CertificateSigningRequest: The CSR to sign for the current Certificate
        """
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(altname) for altname in altnames
            ]),
            critical=False
        ).add_extension(
            x509.BasicConstraints(ca=self.is_authority, path_length=None), critical=True
        ).sign(self._certdata['key'], hashes.SHA256())

        # Write on disk beside the certificate with .csr extension if write_csr is True on conf file
        if 'write_csr' in self.conf_d and self.conf_d['write_csr']:
            path = os.path.dirname(self.cert_path)
            with open(os.path.join(path, f'{self.cname}.csr'), 'wb') as rfile:
                rfile.write(csr.public_bytes(serialization.Encoding.PEM))

        return csr
