# Author: Francesc Lordan <francesc.lordan@gmail.com>.
"""
    Main code obtaining the requests to create and sign new certificates.
"""
import argparse

from certificates import create_key
from certificates import load_key
from certificates import print_key

from certificates import create_certificate_request
from certificates import load_certificate_request
from certificates import print_certificate_request

from certificates import sign_request
from certificates import selfsigned_certificate_for_key
from certificates import load_certificate
from certificates import print_certificate


def get_subject_arguments():
    """
    Obtains from the input stream the necessary values for the certificate subject

    Returns:
        - subject: Dictionary with the subject attributes and their values
                + Type: dict
    """
    subject = {}
    common_name = input("Subject's common name:")
    if common_name != "":
        subject["CN"] = common_name

    email = input("Subject's e-mail:")
    if email != "":
        subject["emailAddress"] = email

    country = input("Subject's country:")
    if country != "":
        subject["C"] = country

    state = input("Subject's state:")
    if state != "":
        subject["ST"] = state

    city = input("Subject's city:")
    if city != "":
        subject["L"] = city

    organization = input("Subject's organization:")
    if organization != "":
        subject["O"] = organization

    organization_unit = input("Subject's organization unit:")
    if organization_unit != "":
        subject["OU"] = organization_unit

    return subject


def key_handler(args):
    """
    Handles the creation of a new

    Return:
        - key: Newly generated key
            + Type: crypto.Pkey
    """
    key = create_key(args.key_type, args.key_size, args.key_out)

    if not args.key_out:
        print(print_key(key))

    return key


def _get_key(args):
    """
    Tries to load the key passed in as input_key parameter; otherwise, it creates one

    Return:
        - key: Loaded or created key
            + Type: crypto.Pkey
    """

    input_key = args.input_key
    key = None
    if input_key:
        from pathlib import Path
        key_file = Path(input_key)
        if key_file.is_file():
            key = load_key(key_file)

    if not key:
        key = key_handler(args)

    return key


def req_handler(args):
    """
    Handles the creation of a new certificate singing request

    Return:
        - req: Newly generated certificate request
            + Type: crypto.Pkey
    """
    key = _get_key(args)
    subject = get_subject_arguments()
    req = create_certificate_request(key, subject=subject, file_name=args.req_out)
    if not args.req_out:
        print(print_certificate_request(req))
    return req


def _get_request(args):
    """
    Tries to load the request passed in as input_request parameter.
    Otherwise, it creates one using the key passed in as input_key.
    If input_key is not defined, it generates a new key

    Return:
        - key: Loaded or created key
            + Type: crypto.Pkey
    """
    input_request = args.input_request
    request = None
    if input_request:
        from pathlib import Path
        req_file = Path(input_request)
        if req_file.is_file():
            request = load_certificate_request(req_file)

    if not request:
        request = req_handler(args)

    return request


def sign_handler(args):
    """
    Handles the signing of a key
    """
    if not args.issuer_key and not args.issuer_cert:
        key = _get_key(args)
        subject = get_subject_arguments()

        cert = selfsigned_certificate_for_key(
            key,
            subject=subject,
            serial_number=int(args.serial_number),
            length=args.duration,
            file_name=args.cert_out
        )

    else:
        req = _get_request(args)
        issuer_cert = load_certificate(args.issuer_cert)
        issuer_key = load_key(args.issuer_key)
        cert = sign_request(
            req,
            issuer_cert=issuer_cert,
            issuer_key=issuer_key,
            length=args.duration,
            file_name=args.cert_out
        )

    if not args.cert_out:
        print(print_certificate(cert))


# MAIN OPTIONS
def add_certificate_arguments(parser):
    """
     Adds the arguments required to create a new certificate

     Args:
            - parser: Parser where to add the key parameters
                + Type: argparse.ArgumentParser

     Return:
            - group: Argument group containing all the certificate arguments
                + Type: argparse._ArgumentGroup
    """
    group = parser.add_argument_group("Certificate management")
    group.add_argument(
        "-sn", "--serial_number",
        help="Serial number for the certificate",
        type=int,
        default=1
    )
    group.add_argument(
        "-d", "--duration",
        help="Period of validity for certificate (seconds)",
        type=int,
        default=60*60*24*(365*100+25)
    )


def add_key_arguments(parser):
    """
     Adds the arguments required to create a new key to the parser given as a parameter

     Args:
            - parser: Parser where to add the key parameters
                + Type: argparse.ArgumentParser

     Return:
            - group: Argument group containing all the key arguments
                + Type: argparse._ArgumentGroup
    """
    group = parser.add_argument_group("Key management")
    group.add_argument(
        "-ks", "--key_size",
        help='Length of the new key',
        type=int,
        default=4096
    )
    group.add_argument(
        "-kt", "--key_type",
        help="Method used for generating the new key",
        choices=["dsa", "rsa"],
        default="rsa"
    )
    return group


def add_issuer_arguments(parser):
    """
     Adds the arguments required to sign a new certificate

     Args:
            - parser: Parser where to add the issuer parameters
                + Type: argparse.ArgumentParser

     Return:
            - group: Argument group containing all the issuer arguments
                + Type: argparse._ArgumentGroup
    """
    group = parser.add_argument_group("Issuer Information")
    group.add_argument(
        "-ik", "--issuer_key",
        help='Key used to certificate the key',
    )
    group.add_argument(
        "-ic", "--issuer_cert",
        help="Certificate used to certificate the key",
    )
    return group


def add_output_arguments(parser):
    """
     Adds the arguments to manage the output of the method

     Args:
            - parser: Parser where to add the issuer parameters
                + Type: argparse.ArgumentParser

     Return:
            - group: Argument group containing all the output arguments
                + Type: argparse._ArgumentGroup
    """
    group = parser.add_argument_group("Output")
    group.add_argument(
        "-ko", "--key_out",
        help="Name of the file where to leave the new key"
    )
    return group


# MAIN CODE
if __name__ == "__main__":
    general_parser = argparse.ArgumentParser(
        prog="main",
        description='Manage the creation and signing of new certificates and keys.'
    )

    # GENERATE DIFFERENT SUB-COMMANDS
    subparsers = general_parser.add_subparsers(help='Command to execute')
    key_parser = subparsers.add_parser(
        "key",
        description='Manage the creation of new keys.'
    )
    key_parser.set_defaults(func=key_handler)

    sign_parser = subparsers.add_parser(
        "sign",
        description='Manage the creation and signing of new certificates.'
    )
    sign_parser.set_defaults(func=sign_handler)

    req_parser = subparsers.add_parser(
        "request",
        description='Manage the creation of a new certificate request.'
    )
    req_parser.set_defaults(func=req_handler)

    # PARSER FOR KEY SUB-COMMAND
    add_key_arguments(key_parser)
    add_output_arguments(key_parser)

    # PARSER FOR REQUEST SUB-COMMAND
    key_group = add_key_arguments(req_parser)
    key_group.add_argument(
        "-k", "--input_key",
        help="Filepath where to get the key to certificate"
    )
    out_group = add_output_arguments(req_parser)
    out_group.add_argument(
        "-ro", "--req_out",
        help="Filepath where to store the certificate request"
    )

    # PARSER FOR SIGN SUB-COMMAND
    add_issuer_arguments(sign_parser)
    key_group = add_key_arguments(sign_parser)
    key_group.add_argument(
        "-k", "--input_key",
        help="Filepath where to get the key to certificate"
    )
    key_group.add_argument(
        "-r", "--input_request",
        help="Filepath where to get the request to certificate"
    )
    add_certificate_arguments(sign_parser)
    out_group = add_output_arguments(sign_parser)
    out_group.add_argument(
        "-ro", "--req_out",
        help="Filepath where to store the certificate request"
    )
    out_group.add_argument(
        "-co", "--cert_out",
        help="Filepath where to store the certificate"
    )

    arguments = general_parser.parse_args()
    arguments.func(arguments)
