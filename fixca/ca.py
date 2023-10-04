import os
import cherrypy
from functools import wraps
from prometheus_client.exposition import generate_latest, CONTENT_TYPE_LATEST
from typing import Optional, Dict, Callable, Tuple, Union, Any, List
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
    gen_rsa_key,
    gen_csr,
    gen_ca_bundle_bytes,
)
from resotolib.jwt import encode_jwt, decode_jwt_from_headers
from .k8s import get_secret, set_secret
from .utils import str_to_bool


class CertificateAuthority:
    def __init__(self):
        self.cert = None
        self.__key = None
        self.__initialized = False

    @staticmethod
    def requires_initialized(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(ca_instance: "CertificateAuthority", *args: Any, **kwargs: Any) -> Any:
            if not ca_instance.initialized:
                raise Exception("CA not initialized")
            return func(ca_instance, *args, **kwargs)

        return wrapper

    @requires_initialized
    def sign(self, csr: CertificateSigningRequest) -> Certificate:
        return sign_csr(csr, self.__key, self.cert)

    def initialize(self, namespace: str = "cert-manager", secret_name: str = "fix-ca") -> None:
        self.__key, self.cert = self.__load_ca_data(namespace=namespace, secret_name=secret_name)
        self.__initialized = True

    @property
    def initialized(self) -> bool:
        return self.__initialized

    @staticmethod
    def __load_ca_data(
        namespace: str = "cert-manager", secret_name: str = "fix-ca"
    ) -> Tuple[RSAPrivateKey, Certificate]:
        log.info("Loading CA data")
        ca_secret = get_secret(namespace=namespace, secret_name=secret_name)

        if isinstance(ca_secret, dict) and (not "tls.key" in ca_secret or not "tls.crt" in ca_secret):
            ca_secret = None
            log.error("CA secret is missing key or cert")

        if ca_secret is None:
            log.debug("Bootstrapping a new CA")
            key, cert = bootstrap_ca(common_name="FIX Certification Authority")
            ca_secret = {
                "tls.key": key_to_bytes(key).decode("utf-8"),
                "tls.crt": cert_to_bytes(cert).decode("utf-8"),
            }
            set_secret(namespace=namespace, secret_name=secret_name, data=ca_secret)
        else:
            log.debug("Loading existing CA")
            key_bytes, cert_bytes = ca_secret["tls.key"].encode(), ca_secret["tls.crt"].encode()
            key = load_key_from_bytes(key_bytes)
            cert = load_cert_from_bytes(cert_bytes)

        return key, cert

    @requires_initialized
    def generate(
        self,
        common_name: str,
        san_dns_names: Optional[List[str]] = None,
        san_ip_addresses: Optional[List[str]] = None,
    ) -> Tuple[RSAPrivateKey, Certificate]:
        if san_dns_names is None:
            san_dns_names = []
        elif isinstance(san_dns_names, str):
            san_dns_names = [san_dns_names]
        if san_ip_addresses is None:
            san_ip_addresses = []
        elif isinstance(san_ip_addresses, str):
            san_ip_addresses = [san_ip_addresses]

        cert_key = gen_rsa_key()
        cert_csr = gen_csr(
            cert_key,
            common_name=common_name,
            san_dns_names=san_dns_names,
            san_ip_addresses=san_ip_addresses,
            include_loopback=False,
            connect_to_ips=None,
            discover_local_dns_names=False,
            discover_local_ip_addresses=False,
        )
        cert_crt = self.sign(cert_csr)
        return cert_key, cert_crt

    def store_secret(
        self,
        cert_key: RSAPrivateKey,
        cert_crt: Certificate,
        namespace: str,
        secret_name: str,
        key_cert: str = "cert.pem",
        key_key: str = "cert.key",
        key_ca: str = "ca.pem",
        key_ca_bundle: str = "ca.bundle.pem",
        include_ca_cert: bool = False,
        include_ca_bundle: bool = False,
    ) -> None:
        log.info(f"Storing certificate {cert_crt.subject.rfc4514_string()} in {namespace}/{secret_name}")
        secret = {
            key_cert: cert_to_bytes(cert_crt).decode("utf-8"),
            key_key: key_to_bytes(cert_key).decode("utf-8"),
        }
        if include_ca_cert:
            secret[key_ca] = cert_to_bytes(self.cert).decode("utf-8")
        if include_ca_bundle:
            secret[key_ca_bundle] = gen_ca_bundle_bytes(self.cert).decode("utf-8")

        set_secret(
            namespace=namespace,
            secret_name=secret_name,
            data=secret,
        )


CA: CertificateAuthority = CertificateAuthority()
PSK: Optional[Union[str, Certificate, RSAPublicKey]] = None


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
        self.ca = CA
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
        fingerprint = cert_fingerprint(self.ca.cert)
        cherrypy.response.headers["Content-Type"] = "application/x-pem-file"
        cherrypy.response.headers["SHA256-Fingerprint"] = fingerprint
        cherrypy.response.headers["Content-Disposition"] = 'attachment; filename="fix_root_ca.pem"'
        cherrypy.response.headers["Authorization"] = "Bearer " + encode_jwt(
            {"sha256_fingerprint": fingerprint}, self.psk_or_cert
        )
        return cert_to_bytes(self.ca.cert)

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

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    @cherrypy.tools.allow(methods=["POST"])
    @cherrypy.tools.jwt_check()
    def generate(self) -> bytes:
        try:
            request_json = cherrypy.request.json
            remote_addr = cherrypy.request.remote.ip
            include_ca_cert = str_to_bool(request_json.get("include_ca_cert", False))
            include_ca_bundle = str_to_bool(request_json.get("include_ca_bundle", False))
            common_name = request_json.get("common_name", remote_addr)
            san_dns_name = request_json.get("common_name", "localhost")
            cert_key, cert_crt = self.ca.generate(
                common_name=common_name,
                san_dns_names=[san_dns_name],
                san_ip_addresses=[remote_addr],
            )
            secret_key_cert = request_json.get("key_cert", "cert.pem")
            secret_key_key = request_json.get("key_key", "cert.key")
            secret_key_ca = request_json.get("key_ca", "ca.pem")
            secret_key_ca_bundle = request_json.get("key_ca_bundle", "ca.bundle.pem")
            secret = {
                secret_key_cert: cert_to_bytes(cert_crt).decode("utf-8"),
                secret_key_key: key_to_bytes(cert_key).decode("utf-8"),
            }
            if include_ca_cert:
                secret[secret_key_ca] = cert_to_bytes(self.ca.cert).decode("utf-8")
            if include_ca_bundle:
                secret[secret_key_ca_bundle] = gen_ca_bundle_bytes(self.ca.cert).decode("utf-8")
        except Exception:
            cherrypy.response.status = 400
            return {"error": "Invalid request"}

        return secret
