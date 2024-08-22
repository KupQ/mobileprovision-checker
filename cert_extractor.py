import plistlib
import re
from cryptography import x509
from os import PathLike

def extract_cert_from_mobileprovision(mobileprovision_path: str | PathLike[str]) -> (x509.Certificate, dict):
    with open(mobileprovision_path, 'rb') as f:
        content = f.read()

    # Use regular expressions to find the plist section
    xml_regex = re.compile(rb'<\?xml.*?\</plist\>', re.DOTALL)
    binary_regex = re.compile(rb'bplist00.*', re.DOTALL)

    plist_match = xml_regex.search(content)
    if not plist_match:
        plist_match = binary_regex.search(content)

    if not plist_match:
        raise ValueError("Plist data not found in the .mobileprovision file.")

    plist_data = plist_match.group()

    plist = plistlib.loads(plist_data)
    cert_data = plist['DeveloperCertificates'][0]
    cert = x509.load_der_x509_certificate(cert_data)
    return cert, plist.get('Entitlements', {})
