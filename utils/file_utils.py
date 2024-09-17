import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

APPLE_ISSUER_CERT_URL = 'https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer'

def download_apple_issuer_cert(issuer_cert_path: str) -> None:
    response = requests.get(APPLE_ISSUER_CERT_URL)
    if response.status_code == 200:
        with open(issuer_cert_path, 'wb') as f:
            f.write(response.content)
    else:
        raise ValueError(f"Failed to download the Apple issuer certificate: {response.status_code}")

def create_cert_files(cert: x509.Certificate, cert_chain: list = None):
    with open("p12-cert.crt", 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    if cert_chain and cert_chain[0]:
        with open("full_chain.crt", 'wb') as f:
            f.write(cert_chain[0].public_bytes(serialization.Encoding.PEM))
    else:
        download_apple_issuer_cert("full_chain.crt")
