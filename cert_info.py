from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import Certificate
from ocsp_checker import _get_ocsp_url 

def get_certificate_info(cert: Certificate) -> dict:
    cert_info = {
        "subject": cert.subject.rfc4514_string(),
        "subject_details": {name.oid._name: name.value for name in cert.subject},
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_details": {name.oid._name: name.value for name in cert.issuer},
        "serial_number": cert.serial_number,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_to": cert.not_valid_after_utc.isoformat(),
        "version": cert.version.name,
        "public_key_algorithm": cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'),
        "public_key_size": cert.public_key().key_size,
        "fingerprint_md5": cert.fingerprint(hashes.MD5()).hex(),
        "fingerprint_sha1": cert.fingerprint(hashes.SHA1()).hex(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "signature_value": cert.signature.hex(),
        "ocsp_url": _get_ocsp_url(cert),
        "extensions": {},
    }

    # Extract extensions
    for ext in cert.extensions:
        ext_name = ext.oid._name
        ext_value = None

        if isinstance(ext.value, x509.BasicConstraints):
            ext_value = {
                "ca": ext.value.ca,
                "path_length": ext.value.path_length
            }
        elif isinstance(ext.value, x509.SubjectKeyIdentifier):
            ext_value = {"digest": ext.value.digest.hex()}
        elif isinstance(ext.value, x509.AuthorityKeyIdentifier):
            ext_value = {
                "key_id": ext.value.key_identifier.hex(),
                "authority_cert_issuer": [i.value for i in ext.value.authority_cert_issuer] if ext.value.authority_cert_issuer else None,
                "authority_cert_serial_number": ext.value.authority_cert_serial_number
            }
        elif isinstance(ext.value, x509.KeyUsage):
            ext_value = {
                "digital_signature": ext.value.digital_signature,
                "content_commitment": ext.value.content_commitment,
                "key_encipherment": ext.value.key_encipherment,
                "data_encipherment": ext.value.data_encipherment,
                "key_agreement": ext.value.key_agreement,
                "key_cert_sign": ext.value.key_cert_sign,
                "crl_sign": ext.value.crl_sign,
                "encipher_only": ext.value.encipher_only if ext.value.key_agreement else None,
                "decipher_only": ext.value.decipher_only if ext.value.key_agreement else None
            }
        elif isinstance(ext.value, x509.ExtendedKeyUsage):
            ext_value = {"usages": [eku._name for eku in ext.value]}
        elif isinstance(ext.value, x509.SubjectAlternativeName):
            ext_value = {"dns_names": ext.value.get_values_for_type(x509.DNSName)}
        elif isinstance(ext.value, x509.CertificatePolicies):
            policies = []
            for policy in ext.value:
                policy_info = {"policy_id": policy.policy_identifier.dotted_string}
                if policy.policy_qualifiers:
                    qualifiers = []
                    for qualifier in policy.policy_qualifiers:
                        if isinstance(qualifier, x509.UserNotice):
                            qualifiers.append({
                                "user_notice": {
                                    "notice_reference": qualifier.notice_reference,
                                    "explicit_text": qualifier.explicit_text
                                }
                            })
                        else:
                            qualifiers.append({"cps_uri": str(qualifier)})
                    policy_info["qualifiers"] = qualifiers
                policies.append(policy_info)
            ext_value = {"policies": policies}
        elif isinstance(ext.value, x509.CRLDistributionPoints):
            crl_urls = []
            for point in ext.value:
                for name in point.full_name:
                    crl_urls.append(name.value)
            ext_value = {"crl_urls": crl_urls}
        elif isinstance(ext.value, x509.AuthorityInformationAccess):
            aia_info = []
            for access_desc in ext.value:
                aia_info.append({
                    "access_method": access_desc.access_method._name,
                    "access_location": access_desc.access_location.value
                })
            ext_value = {"authority_information_access": aia_info}
        elif isinstance(ext.value, x509.NameConstraints):
            ext_value = {
                "permitted_subtrees": [str(subtree) for subtree in ext.value.permitted_subtrees] if ext.value.permitted_subtrees else None,
                "excluded_subtrees": [str(subtree) for subtree in ext.value.excluded_subtrees] if ext.value.excluded_subtrees else None
            }
        elif isinstance(ext.value, x509.InhibitAnyPolicy):
            ext_value = {"skip_certs": ext.value.skip_certs}
        elif isinstance(ext.value, x509.SignedCertificateTimestamps):
            sct_info = []
            for sct in ext.value:
                sct_info.append({
                    "log_id": sct.log_id.hex(),
                    "timestamp": sct.timestamp.isoformat(),
                    "signature": sct.signature.hex()
                })
            ext_value = {"signed_certificate_timestamps": sct_info}

        cert_info["extensions"][ext_name] = ext_value

    return cert_info
