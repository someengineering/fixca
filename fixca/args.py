from argparse import ArgumentParser, Namespace
from typing import Callable, List


def parse_args(add_args: List[Callable]) -> Namespace:
    parser = ArgumentParser(prog="fixca", description="FIX Certification Authority")
    parser.add_argument("--psk", dest="psk", help="Pre-shared-key", required=True)
    parser.add_argument("--port", dest="port", help="TCP port to listen on", default=7900, type=int)
    for add_arg in add_args:
        add_arg(parser)
    return parser.parse_args()
