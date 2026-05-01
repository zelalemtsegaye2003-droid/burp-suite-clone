"""SSL Certificate Generator for HTTPS Interception"""
import os
import ssl
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime


class SSLCertGenerator:
    def __init__(self, ca_path: str = "ca.pem", key_path: str = "ca.key"):
        self.ca_path = ca_path
        self.key_path = key_path
        self.ca_cert = None
        self.ca_key = None

    def generate_ca(self):
        if os.path.exists(self.ca_path) and os.path.exists(self.key_path):
            self.load_ca()
            return

        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BurpClone CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "BurpClone Root CA"),
        ])

        self.ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).sign(self.ca_key, hashes.SHA256(), default_backend())

        with open(self.ca_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        with open(self.key_path, "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def load_ca(self):
        with open(self.ca_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        with open(self.key_path, "rb") as f:
            self.ca_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

    def generate_cert(self, hostname: str) -> tuple[bytes, bytes]:
        if not self.ca_cert or not self.ca_key:
            self.generate_ca()

        cert_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BurpClone"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            cert_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                x509.DNSName(f"*.{hostname}"),
            ]),
            critical=False,
        ).sign(self.ca_key, hashes.SHA256(), default_backend())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = cert_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        return cert_pem, key_pem


def create_ssl_context(ca_path: str = "ca.pem", key_path: str = "ca.key") -> ssl.SSLContext:
    gen = SSLCertGenerator(ca_path, key_path)
    gen.generate_ca()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca_path, key_path)
    context.verify_mode = ssl.CERT_NONE

    return context


if __name__ == '__main__':
    gen = SSLCertGenerator()
    gen.generate_ca()
    print(f"CA cert created: {gen.ca_path}")
    print(f"CA key created: {gen.key_path}")

    cert, key = gen.generate_cert("example.com")
    print(f"Generated cert for example.com")