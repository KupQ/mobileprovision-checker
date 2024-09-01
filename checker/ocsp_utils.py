import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp


def _ocsp_check(p12_cert: x509.Certificate, ca_cert: x509.Certificate, ocsp_url: str) -> str:
    builder = ocsp.OCSPRequestBuilder().add_certificate(
        p12_cert, ca_cert, p12_cert.signature_hash_algorithm
    )
    req = builder.build()

    response = requests.post(
        ocsp_url, data=req.public_bytes(serialization.Encoding.DER),
        headers={'Content-Type': 'application/ocsp-request'}
    )
    ocsp_response = ocsp.load_der_ocsp_response(response.content)

    if ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
        status = ocsp_response.certificate_status
        return "Good" if status == ocsp.OCSPCertStatus.GOOD else "Revoked" if status == ocsp.OCSPCertStatus.REVOKED else "Unknown"
    else:
        return "OCSP check failed"
