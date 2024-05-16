from fixca.ca import CA
from fixlib.x509 import (
    gen_rsa_key,
    gen_csr,
)
from cryptography.x509.base import Certificate


def test_ca() -> None:
    cn = "test.fix"
    CA.initialize(dummy_ca=True)
    test_cert: Certificate = CA.sign(gen_csr(gen_rsa_key(), common_name=cn, san_dns_names=[cn]))
    assert test_cert.subject.rfc4514_string() == f"CN={cn}"
