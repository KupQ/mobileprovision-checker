import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp, Certificate

def _get_ocsp_url(cert: Certificate) -> str | None:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for desc in aia.value:
            if desc.access_method == x509.OID_OCSP:
                return desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None

def _ocsp_check(p12_cert: Certificate, ca_cert: Certificate, ocsp_url: str) -> str:
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(p12_cert, ca_cert, p12_cert.signature_hash_algorithm)
    req = builder.build()

    ocsp_req_data = req.public_bytes(serialization.Encoding.DER)

    response = requests.post(ocsp_url, data=ocsp_req_data, headers={'Content-Type': 'application/ocsp-request'})
    ocsp_response = ocsp.load_der_ocsp_response(response.content)

    if ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
        if ocsp_response.certificate_status == ocsp.OCSPCertStatus.GOOD:
            return "Good"
        elif ocsp_response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            return "Revoked"
        else:
            return "Unknown"
    else:
        return "OCSP check failed"
