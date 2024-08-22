import json
from cert_extractor import extract_cert_from_mobileprovision
from cert_info import get_certificate_info
from entitlements_checker import check_entitlements
from ocsp_checker import _ocsp_check
import requests
from cryptography import x509

def check(mobileprovision_path):
    p12_cert, entitlements = extract_cert_from_mobileprovision(mobileprovision_path)
    cert_info = get_certificate_info(p12_cert)
    entitlements_info = check_entitlements(entitlements)

    # OCSP check for certificate status
    ca_certs = ["AppleWWDRCA", "AppleWWDRCAG2", "AppleWWDRCAG3", "AppleWWDRCAG4", "AppleWWDRCAG5", "AppleWWDRCAG6"]
    ocsp_status = "Unknown"

    for cert in ca_certs:
        try:
            ca_req = requests.get(
                "https://developer.apple.com/certificationauthority/AppleWWDRCA.cer"
                if cert.endswith("A")
                else f"https://www.apple.com/certificateauthority/{cert}.cer"
            )
            ca_cert = x509.load_der_x509_certificate(ca_req.content)
            ocsp_status = _ocsp_check(p12_cert, ca_cert, cert_info["ocsp_url"])

            if ocsp_status in ["Good", "Revoked"]:
                break
        except Exception as e:
            ocsp_status = f"OCSP check failed: {str(e)}"

    result = {
        "certificate_info": cert_info,
        "certificate_status": ocsp_status,
        "entitlements": entitlements_info
    }

    # Print result instead of writing to JSON
    print(json.dumps(result, indent=4, ensure_ascii=False))
