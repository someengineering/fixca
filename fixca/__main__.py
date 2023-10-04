import os
import sys
import resotolib.proc
from tempfile import TemporaryDirectory
from resotolib.logger import log, setup_logger, add_args as logging_add_args
from resotolib.web import WebServer
from resotolib.event import EventType, add_event_listener
from resotolib.x509 import gen_csr, gen_rsa_key, write_cert_to_file, write_key_to_file
from .args import parse_args
from .ca import CA, WebApp, CaApp
from threading import Event


shutdown_event = Event()


def shutdown(event) -> None:
    log.info("Shutting down")
    shutdown_event.set()


def main() -> None:
    setup_logger("fixca")
    args = parse_args([logging_add_args])
    log.info(f"Starting FIX CA on port {args.port}")
    resotolib.proc.initializer()
    resotolib.proc.parent_pid = os.getpid()

    add_event_listener(EventType.SHUTDOWN, shutdown)

    CA.initialize(namespace=args.namespace, secret_name=args.secret, dummy_ca=args.dummy_ca)

    common_name = "ca.fix"
    cert_key = gen_rsa_key()
    cert_csr = gen_csr(
        cert_key,
        common_name=common_name,
        san_dns_names=[common_name],
    )
    cert_crt = CA.sign(cert_csr)
    with TemporaryDirectory() as tmpdir:
        cert_path = os.path.join(tmpdir, "ca.crt")
        key_path = os.path.join(tmpdir, "ca.key")
        log.debug(f"Writing CA cert to {cert_path}")
        write_cert_to_file(cert_crt, cert_path)
        log.debug(f"Writing CA key to {key_path}")
        write_key_to_file(cert_key, key_path)

        web_server = WebServer(
            WebApp(),
            web_host="::",
            web_port=args.port,
            ssl_cert=cert_path,
            ssl_key=key_path,
            extra_config={
                "tools.proxy.on": True,
            },
        )
        web_server.mount("/ca", CaApp(CA, args.psk))

        web_server.daemon = True
        web_server.start()
        shutdown_event.wait()
        web_server.shutdown()

    resotolib.proc.kill_children(resotolib.proc.SIGTERM, ensure_death=True)
    log.info("Shutdown complete")
    sys.exit(0)


if __name__ == "__main__":
    main()
