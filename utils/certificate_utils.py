import plistlib
import re
import sys
import json
import os
from os import PathLike
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from utils.ocsp_utils import _ocsp_check_with_openssl, _get_ocsp_url
from utils.file_utils import create_cert_files
from utils.entitlements_utils import check_entitlements
from cryptography.hazmat.primitives.serialization import pkcs12

REVOCATION_REASON_MAPPING = {
    "0x0": "No specific reason provided for revocation.",
    "0x1": "The certificate's private key was compromised.",
    "0x2": "The issuing CA was compromised.",
    "0x3": "Ownership or affiliation changed.",
    "0x4": "Certificate replaced with a new one.",
    "0x5": "Certificate is no longer needed.",
    "0x6": "Certificate is temporarily on hold.",
    "0x8": "Certificate removed from the hold list.",
    "0x9": "Certificate's privileges were withdrawn.",
    "0xA": "Associated authority was compromised."
}

def extract_cert_from_mobileprovision(mobileprovision_path: str) -> tuple:
    with open(mobileprovision_path, 'rb') as f:
        content = f.read()
    plist_match = re.search(rb'<\?xml.*?\</plist\>', content, re.DOTALL) or re.search(rb'bplist00.*', content, re.DOTALL)
    if not plist_match:
        raise ValueError("Plist data not found in the .mobileprovision file.")
    plist_data = plist_match.group()
    plist = plistlib.loads(plist_data)
    cert_data = plist['DeveloperCertificates'][0]
    cert = x509.load_der_x509_certificate(cert_data)
    entitlements = plist.get('Entitlements', {})
    cert_type = "Enterprise Certificate" if plist.get("ProvisionsAllDevices", False) else "Personal Certificate"
    return cert, entitlements, cert_type

def extract_cert_from_p12(p12_path: str, password: str = "") -> tuple:
    try:
        with open(p12_path, 'rb') as f:
            p12_data = f.read()
        p12 = pkcs12.load_key_and_certificates(p12_data, password.encode('utf-8') or None)
        if p12 is None:
            raise ValueError("Incorrect password or unable to load the p12 file.")
        return p12[1], p12[2]
    except Exception as e:
        raise ValueError(f"Error loading PKCS12 file: {str(e)}")

def get_certificate_info(cert: x509.Certificate) -> dict:
    def process_name(name):
        value = name.value
        return {"original": value, "truncated": value[:61] + "..."} if len(value) > 64 else value
    subject_details = {name.oid._name: process_name(name) for name in cert.subject}
    issuer_details = {name.oid._name: process_name(name) for name in cert.issuer}
    cert_info = {
        "subject": {k: v["truncated"] if isinstance(v, dict) else v for k, v in subject_details.items()},
        "issuer": {k: v["truncated"] if isinstance(v, dict) else v for k, v in issuer_details.items()},
        "serial_number": str(cert.serial_number),
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "validity_period": {
            "valid_from": cert.not_valid_before_utc.isoformat(),
            "valid_to": cert.not_valid_after_utc.isoformat()
        },
        "public_key_size": cert.public_key().key_size,
        "fingerprints": {
            "sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "md5": cert.fingerprint(hashes.MD5()).hex(),
            "sha1": cert.fingerprint(hashes.SHA1()).hex(),
        },
        "ocsp_url": _get_ocsp_url(cert),
        "public_key_algorithm": cert.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')
    }
    return cert_info

def get_revocation_reason_description(reason_code: str) -> str:
    return REVOCATION_REASON_MAPPING.get(reason_code, "Unknown reason")

def check_certificates(mobileprovision_path: str = None, p12_path: str = None, password: str = ""):
    try:
        if mobileprovision_path:
            cert, entitlements, cert_type = extract_cert_from_mobileprovision(mobileprovision_path)
            cert_info = get_certificate_info(cert)
            create_cert_files(cert)
            ocsp_url = cert_info.get("ocsp_url")
            ocsp_status = {"status": "OCSP URL not available"} if not ocsp_url else _ocsp_check_with_openssl("p12-cert.crt", "full_chain.crt", ocsp_url)
            if ocsp_status.get("status") == "Revoked" and "reason" in ocsp_status:
                reason_code = ocsp_status["reason"].split('(')[-1].strip(')')
                ocsp_status["reason_details"] = get_revocation_reason_description(reason_code)
            result = {
                "certificate_info": cert_info,
                "certificate_status": ocsp_status,
                "entitlements": check_entitlements(entitlements),
                "type": cert_type
            }
        elif p12_path:
            cert, cert_chain = extract_cert_from_p12(p12_path, password)
            cert_info = get_certificate_info(cert)
            create_cert_files(cert, cert_chain)
            ocsp_url = cert_info.get("ocsp_url")
            ocsp_status = {"status": "OCSP URL not available"} if not ocsp_url else _ocsp_check_with_openssl("p12-cert.crt", "full_chain.crt", ocsp_url)
            if ocsp_status.get("status") == "Revoked" and "reason" in ocsp_status:
                reason_code = ocsp_status["reason"].split('(')[-1].strip(')')
                ocsp_status["reason_details"] = get_revocation_reason_description(reason_code)
            result = {
                "certificate_info": cert_info,
                "certificate_status": ocsp_status,
                "entitlements": "Entitlements are not applicable for p12 files",
                "type": "N/A"
            }
        print(json.dumps(result, indent=4, ensure_ascii=False))
        if os.path.exists("p12-cert.crt"):
            os.remove("p12-cert.crt")
        if os.path.exists("full_chain.crt"):
            os.remove("full_chain.crt")
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)
