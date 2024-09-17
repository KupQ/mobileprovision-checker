from cryptography import x509
import subprocess
import re
import contextlib

def _get_ocsp_url(cert: x509.Certificate) -> str | None:
    with contextlib.suppress(x509.ExtensionNotFound):
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for desc in aia.value:
            if desc.access_method == x509.OID_OCSP:
                return desc.access_location.value
    return None

def _ocsp_check_with_openssl(cert_path: str, issuer_path: str, ocsp_url: str) -> dict:
    try:
        result = subprocess.run(
            ['openssl', 'ocsp', '-issuer', issuer_path, '-cert', cert_path, '-url', ocsp_url, '-noverify', '-resp_text'],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout
        ocsp_status = {"status": "Unknown"}

        if "revoked" in output:
            ocsp_status["status"] = "Revoked"
            ocsp_status["revocation_time"] = re.search(r'Revocation Time: (.+)', output).group(1) or "Unknown"
            reason_match = re.search(r'Reason: (.+)', output)
            ocsp_status["reason"] = reason_match.group(1) if reason_match else "Reason not provided"
        elif "good" in output:
            ocsp_status["status"] = "Good"

        return ocsp_status
    except subprocess.CalledProcessError as e:
        return {"status": f"OCSP check failed with error: {str(e)}"}
