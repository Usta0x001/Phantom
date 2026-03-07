"""
Ephemeral TLS Manager

Generates per-scan CA + server/client certificates for mTLS.
All material is deleted when the scan ends.
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import shutil
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_logger = logging.getLogger(__name__)


class EphemeralTLSManager:
    """Per-scan ephemeral TLS certificates for mTLS sandbox communication."""

    def __init__(self) -> None:
        self._temp_dir = Path(tempfile.mkdtemp(prefix="phantom_tls_"))
        self._ca_key = ec.generate_private_key(ec.SECP256R1())
        self._ca_cert = self._make_ca_cert()
        self._save(self._ca_cert, self._ca_key, "ca")

    def _make_ca_cert(self) -> x509.Certificate:
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Phantom Ephemeral CA"),
        ])
        now = datetime.datetime.now(datetime.UTC)
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(hours=24))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

    def generate_server_cert(self) -> tuple[Path, Path]:
        """Returns (cert_path, key_path) for the tool server."""
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, "phantom-sandbox"),
                ]),
            )
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(hours=24))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("phantom-sandbox"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        return self._save(cert, key, "server")

    def generate_client_cert(self) -> tuple[Path, Path]:
        """Returns (cert_path, key_path) for the host client."""
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, "phantom-host"),
                ]),
            )
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(hours=24))
            .sign(self._ca_key, hashes.SHA256())
        )
        return self._save(cert, key, "client")

    def _save(
        self, cert: x509.Certificate, key: ec.EllipticCurvePrivateKey, name: str,
    ) -> tuple[Path, Path]:
        cert_path = self._temp_dir / f"{name}.pem"
        key_path = self._temp_dir / f"{name}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        return cert_path, key_path

    def get_ca_cert_path(self) -> Path:
        """Return path to CA certificate (for container trust store)."""
        return self._temp_dir / "ca.pem"

    def cleanup(self) -> None:
        """Remove ephemeral TLS material from disk."""
        import shutil
        try:
            shutil.rmtree(self._temp_dir, ignore_errors=True)
        except Exception:
            pass
        self._ca_key = None
        self._ca_cert = None

    def __del__(self) -> None:
        """Best-effort cleanup on garbage collection."""
        self.cleanup()

    def create_client_ssl_context(self) -> ssl.SSLContext:
        """Create client SSL context with client cert and CA verification."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            self._temp_dir / "client.pem",
            self._temp_dir / "client.key",
        )
        ctx.load_verify_locations(self._temp_dir / "ca.pem")
        ctx.check_hostname = False  # Container hostname varies
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def cleanup(self) -> None:
        """Delete all TLS material."""
        shutil.rmtree(self._temp_dir, ignore_errors=True)
