import os
from argparse import ArgumentParser, Namespace
from typing import Callable, List


def parse_args(add_args: List[Callable]) -> Namespace:
    parser = ArgumentParser(prog="fixca", description="FIX Certification Authority")
    parser.add_argument("--psk", dest="psk", help="Pre-shared-key", default=os.environ.get("FIXCA_PSK"))
    parser.add_argument(
        "--port",
        dest="port",
        help="HTTPS port to listen on (default: 7900)",
        default=os.environ.get("FIXCA_PORT", 7900),
        type=int,
    )
    parser.add_argument(
        "--namespace",
        dest="namespace",
        help="K8s namespace (default: cert-manager)",
        default=os.environ.get("FIXCA_NAMESPACE", "cert-manager"),
    )
    parser.add_argument(
        "--secret",
        dest="secret",
        help="Secret name (default: fix-ca)",
        default=os.environ.get("FIXCA_SECRET", "fix-ca"),
    )
    for add_arg in add_args:
        add_arg(parser)

    args = parser.parse_args()
    if args.psk is None:
        parser.error("Missing --psk argument")

    return args
