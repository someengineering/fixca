import os
import cherrypy
from prometheus_client.exposition import generate_latest, CONTENT_TYPE_LATEST
from typing import Optional, Dict, Callable, Tuple, Union
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509.base import Certificate, CertificateSigningRequest
from resotolib.logger import log
from resotolib.x509 import (
    bootstrap_ca,
    sign_csr,
    cert_to_bytes,
    key_to_bytes,
    cert_fingerprint,
    load_csr_from_bytes,
    load_cert_from_bytes,
    load_key_from_bytes,
)
from resotolib.jwt import encode_jwt, decode_jwt_from_headers
from .k8s import get_secret, set_secret


CA: Optional["CertificateAuthority"] = None
PSK: Optional[Union[str, Certificate, RSAPublicKey]] = None


class CertificateAuthority:
    def __init__(self, ca_key: RSAPrivateKey, ca_cert: Certificate):
        self.ca_key = ca_key
        self.ca_cert = ca_cert

    def sign(self, csr: CertificateSigningRequest) -> Certificate:
        return sign_csr(csr, self.ca_key, self.ca_cert)


def load_ca_data(namespace: str = "fix", secret_name: str = "fix-ca") -> Tuple[RSAPrivateKey, Certificate]:
    log.info("Loading CA data")
    ca_secret = get_secret(namespace=namespace, secret_name=secret_name)

    if isinstance(ca_secret, dict) and (not "key" in ca_secret or not "cert" in ca_secret):
        ca_secret = None
        log.error("CA secret is missing key or cert")

    if ca_secret is None:
        log.debug("Bootstrapping a new CA")
        key, cert = bootstrap_ca(common_name="FIX Certification Authority")
        ca_secret = {
            "key": key_to_bytes(key).decode("utf-8"),
            "cert": cert_to_bytes(cert).decode("utf-8"),
        }
        set_secret(namespace=namespace, secret_name=secret_name, data=ca_secret)
    else:
        log.debug("Loading existing CA")
        key_bytes, cert_bytes = ca_secret["key"].encode(), ca_secret["cert"].encode()
        key = load_key_from_bytes(key_bytes)
        cert = load_cert_from_bytes(cert_bytes)

    return key, cert


def get_ca(namespace: str = "fix", secret_name: str = "fix-ca") -> CertificateAuthority:
    global CA
    if CA is None:
        CA = CertificateAuthority(*load_ca_data(namespace=namespace, secret_name=secret_name))
    return CA


def jwt_check():
    headers = cherrypy.request.headers
    assert PSK is not None

    try:
        jwt_data = decode_jwt_from_headers(headers, PSK)
    except Exception:
        raise cherrypy.HTTPError(401, "Unauthorized")

    if jwt_data is None:
        raise cherrypy.HTTPError(401, "Unauthorized")

    log.debug("JWT check passed")


cherrypy.tools.jwt_check = cherrypy.Tool("before_handler", jwt_check)


class WebApp:
    def __init__(
        self, mountpoint: str = "/", health_conditions: Optional[Dict[str, Callable[[], bool]]] = None
    ) -> None:
        self.mountpoint = mountpoint
        local_path = os.path.abspath(os.path.dirname(__file__))
        config = {
            "tools.gzip.on": True,
            "tools.staticdir.index": "index.html",
            "tools.staticdir.on": True,
            "tools.staticdir.dir": f"{local_path}/static",
        }
        self.ca = get_ca()
        self.config = {"/": config}
        self.health_conditions = health_conditions if health_conditions is not None else {}
        if self.mountpoint not in ("/", ""):
            self.config[self.mountpoint] = config

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    def health(self) -> str:
        cherrypy.response.headers["Content-Type"] = "text/plain"
        unhealthy = [f"- {name}" for name, fn in self.health_conditions.items() if not fn()]
        if not unhealthy:
            cherrypy.response.status = 200
            return "ok\r\n"
        else:
            cherrypy.response.status = 503
            cherrypy.response.headers["Content-Type"] = "text/plain"
            return "not ok\r\n\r\n" + "\r\n".join(unhealthy) + "\r\n"

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    def metrics(self) -> bytes:
        cherrypy.response.headers["Content-Type"] = CONTENT_TYPE_LATEST
        return generate_latest()


class CaApp:
    def __init__(self, ca: CertificateAuthority, psk_or_cert: Union[str, Certificate, RSAPublicKey]) -> None:
        global PSK
        self.ca = ca
        self.psk_or_cert = psk_or_cert
        self.config = {"/": {"tools.gzip.on": False}}
        PSK = self.psk_or_cert

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    def cert(self) -> bytes:
        assert self.psk_or_cert is not None
        fingerprint = cert_fingerprint(self.ca.ca_cert)
        cherrypy.response.headers["Content-Type"] = "application/x-pem-file"
        cherrypy.response.headers["SHA256-Fingerprint"] = fingerprint
        cherrypy.response.headers["Content-Disposition"] = 'attachment; filename="fix_root_ca.pem"'
        cherrypy.response.headers["Authorization"] = "Bearer " + encode_jwt(
            {"sha256_fingerprint": fingerprint}, self.psk_or_cert
        )
        return cert_to_bytes(self.ca.ca_cert)

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    @cherrypy.tools.jwt_check()
    def sign(self) -> bytes:
        try:
            csr = load_csr_from_bytes(cherrypy.request.body.read())
            crt = self.ca.sign(csr)
        except Exception:
            cherrypy.response.status = 400
            return b"Invalid CSR"

        log.info(f"Signed CSR for {crt.subject.rfc4514_string()}")
        filename = crt.subject.rfc4514_string().replace("/", "_").replace(" ", "_").replace("=", "_") + ".pem"

        cherrypy.response.headers["Content-Type"] = "application/x-pem-file"
        cherrypy.response.headers["SHA256-Fingerprint"] = cert_fingerprint(crt)
        cherrypy.response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return cert_to_bytes(crt)
