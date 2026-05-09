from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import requests


class PKIClient:
    def gen_csr(self, subject_str, key_type="rsa", key_size=2048, san_list=None, out_key="key.pem", out_csr="request.csr.pem"):
        if key_type == "rsa":
            private_key = rsa.generate_private_key(65537, key_size, default_backend())
        else:
            raise ValueError("Only RSA supported")

        pem_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        Path(out_key).write_bytes(pem_key)

        subject = x509.Name.from_rfc4514_string(subject_str)
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

        if san_list:
            sans = []
            for s in san_list:
                if s.startswith("dns:"):
                    sans.append(x509.DNSName(s[4:]))
            if sans:
                builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

        csr = builder.sign(private_key, hashes.SHA256())
        Path(out_csr).write_bytes(csr.public_bytes(serialization.Encoding.PEM))

        print(f"CSR created: {out_csr}")
        print(f"Private key: {out_key}")
        return out_csr

    def request_cert(self, csr_path, template, ca_url="http://127.0.0.1:8080", out_cert="cert.pem"):
        with open(csr_path, "rb") as f:
            csr_data = f.read()

        response = requests.post(
            f"{ca_url}/request-cert",
            files={"csr": csr_data},
            data={"template": template}
        )

        if response.status_code == 201:
            Path(out_cert).write_bytes(response.content)
            print(f"Certificate received: {out_cert}")
            return out_cert
        else:
            print(f"Error: {response.text}")
            return None