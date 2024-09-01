import sys
import json
import argparse
import requests
import warnings
from os import PathLike
from cryptography import x509
from checker.certificate_utils import extract_cert_from_mobileprovision, extract_cert_from_p12, get_certificate_info
from checker.entitlement_utils import check_entitlements
from checker.ocsp_utils import _ocsp_check

warnings.filterwarnings("ignore", message="Attribute's length must be >= 1 and <= 64")

def check(mobileprovision_path: str | PathLike[str] = None, p12_path: str = None, password: str = ""):
    try:
        if mobileprovision_path:
            p12_cert, entitlements = extract_cert_from_mobileprovision(mobileprovision_path)
            cert_info = get_certificate_info(p12_cert)
            entitlements_info = check_entitlements(entitlements)
        elif p12_path:
            p12_cert = extract_cert_from_p12(p12_path, password)
            cert_info = get_certificate_info(p12_cert)
            entitlements_info = "Not applicable for p12 files"
        else:
            raise ValueError("Either mobileprovision_path or p12_path must be provided.")
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)

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

    print(json.dumps(result, indent=4, ensure_ascii=False))

def main():
    parser = argparse.ArgumentParser(description="Check information for a .mobileprovision or .p12 file.")
    parser.add_argument("file", help="The path to the .mobileprovision or .p12 file.")
    parser.add_argument("password", nargs="?", help="Password for the .p12 file if required.")

    args = parser.parse_args()

    if args.file.endswith('.mobileprovision'):
        check(mobileprovision_path=args.file)
    elif args.file.endswith('.p12'):
        check(p12_path=args.file, password=args.password or "")
    else:
        print("Unsupported file type. Please provide a .mobileprovision or .p12 file.")
        sys.exit(1)

if __name__ == '__main__':
    main()
