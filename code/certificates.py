# Author: Francesc Lordan <francesc.lordan@gmail.com>.

"""
Key and Certificate creation library

This module builds on OpenSSL for:
- generating new keys
- create certificate signing request
- sign certificates

"""
__version__ = '1.1'

from OpenSSL import crypto


# ===============
# Loading, printing and generation of keys
# ===============
def create_key(algorithm="dsa", key_length=4096, file_name=None):
    """
        Creates a new Key pair

        Args:
            - algorithm: Algorithm used for creating the new key pair.
                + Type: string
            - key_length: Length of the generated key (# bits)
                + Type: int
            - file_name: Path where to store the newly generated key
                + Type: string


        Return:
            - keypair: New generated KeyPair
                + Type: crypto.Pkey

    """
    if algorithm.lower() == "dsa":
        key_type = crypto.TYPE_DSA
    elif algorithm.lower() == "rsa":
        key_type = crypto.TYPE_RSA

    key = crypto.PKey()
    key.generate_key(key_type, key_length)
    if file_name:
        key_file = open(file_name, "wb")
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    return key


def load_key(file_name):
    """
        Loads an existing key from a file

        Args:
            - file_name: Path where to load from the key
                + Type: string

        Return:
            - keypair: Loaded KeyPair
                + Type: crypto.Pkey

    """
    key_file = open(file_name, 'rt').read()
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file)
    return key


def print_key(key):
    """
        Returns the text of a given key

        Args:
            - key: private key
                + Type: crypto.Pkey

        Return:
            - key_text: private key value as a string
                + Type: str
    """
    return str(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))


# ===============
# Loading, printing and creation of certificate signing requests
# ===============
def _update_subject(target, subject={}):
    """
        Creates a certificate for a given key adding the subject information

        Args:
            - target: Target element of the modification (request or certificat).
                + Type: crypto.X509Req or crypto.X509

            - subject: Dictionary with the content to be added on the certificate subject possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
                + Type: String->String dictionary


    """
    if subject.get("CN"):
        target.get_subject().CN = subject["CN"]
    else:
        from socket import gethostname
        target.get_subject().CN = gethostname()

    if subject.get("C"):
        target.get_subject().C = subject["C"]
    if subject.get("ST"):
        target.get_subject().ST = subject["ST"]
    if subject.get("L"):
        target.get_subject().L = subject["L"]
    if subject.get("O"):
        target.get_subject().O = subject["O"]
    if subject.get("OU"):
        target.get_subject().OU = subject["OU"]
    if subject.get("emailAddress"):
        target.get_subject().emailAddress = subject["emailAddress"]


def create_certificate_request(
        key,
        digest="sha256",
        subject = {},
        file_name=None
        ):
    """
        Creates a certificate request for a given key

        Args:
            - key: Key requesting being certificate.
                + Type: crypto.Pkey
            - digest: digest method for signing (default sha256)
                + Type: String
            - subject: Dictionary with the content to be added on the certificate subject possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
                + Type: String->String dictionary
            - file_name: Path where to store the request
                + Type: String

        Return:
            - req: The self-signed certificate in an X509 object
                + Type: crypto.X509
    """
    req = crypto.X509Req()
    _update_subject(req, subject)
    req.set_pubkey(key)
    req.sign(key, digest)

    if file_name:
        req_file = open(file_name, "wb")
        req_file.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
    return req


def load_certificate_request(file_name):
    """
        Loads an existing certificate request from a file

        Args:
            - file_name: Path where to load from the certificate request
                + Type: string

        Return:
            - req: Loaded certificate request
                + Type: crypto.X509Req
    """
    req_file = open(file_name, 'rt').read()
    req = crypto.load_certificate_request(crypto.FILETYPE_PEM, req_file)
    return req


def print_certificate_request(req):
    """
        Returns the text of a given certificate request

        Args:
            - req: request
                + Type: crypto.X509Req

        Return:
            - key_text: certificate request value as a string
                + Type: str
    """
    return str(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))


# ===============
# Loading, printing and signing of certificates
# ===============
def sign_request(
        req,
        issuer_cert,
        issuer_key,
        serial_number=1,
        digest="sha256",
        length=None,
        file_name=None
        ):
    """
        Returns a certificate issued by the issuer for the request passed in

        Args:
            - req: request
                + Type: crypto.X509Req

        Return:
            - cert: certificate issued by the issuer for the request
                + Type: crypto.X509
    """
    cert = crypto.X509()
    cert.set_serial_number(serial_number)
    cert.gmtime_adj_notBefore(0)
    if length:
        cert.gmtime_adj_notAfter(length)
    else:
        cert.gmtime_adj_notAfter(60*60*24*365*100)
    cert.set_issuer(issuer_cert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuer_key, digest)
    if file_name:
        cert_file = open(file_name, "wb")
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    return cert


def selfsigned_certificate_for_key(
        key,
        subject={},
        serial_number=1,
        digest="sha256",
        length=None,
        file_name=None
        ):
    """
        Creates self-signed certificate for a given key

        Args:
            - key: Key to create and sign the certificate.
                + Type: crypto.Pkey
            - digest: digest method for signing (default sha256)
                + Type: String
            - subject: Dictionary with the content to be added on the certificate subject possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
                + Type: String->String dictionary
            - file_name: Path where to store the request
                + Type: String

        Return:
            - cert: The self-signed certificate in an X509 object
                + Type: crypto.X509

    """
    # create a self-signed cert
    cert = crypto.X509()
    _update_subject(cert, subject)
    cert.set_serial_number(serial_number)
    cert.gmtime_adj_notBefore(0)
    if length:
        cert.gmtime_adj_notAfter(length)
    else:
        cert.gmtime_adj_notAfter(60*60*24*365*100)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, digest)
    if file_name:
        cert_file = open(file_name, "wb")
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    return cert


def load_certificate(file_name):
    """
        Loads an existing certificate request from a file

        Args:
            - file_name: Path where to load from the certificate
                + Type: string

        Return:
            - cert: Loaded certificate
                + Type: crypto.X509
    """
    cert_file = open(file_name, 'rt').read()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file)
    return cert


def print_certificate(cert):
    """
        Returns the text of a given certificate

        Args:
            - cert: certificate
                + Type: crypto.X509

        Return:
            - key_text: certificate value as a string
                + Type: str
    """
    return str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
