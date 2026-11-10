"""
Fuzz the DNS message parser (roadmap P8.8) with Atheris (libFuzzer).

The contract: parse_dns either returns a message or raises DNSParseError
(compression loops, names running past the message, ...). Anything else is
a bug. The tunnel detector's helpers run on every parsed name.

    python fuzz/fuzz_dns.py -max_total_time=3600 fuzz/corpus/dns
"""

import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

with atheris.instrument_imports():
    from app.services.dns_parser import DNSParseError, base_domain, entropy, parse_dns, subdomain


def test_one_input(data: bytes) -> None:
    try:
        message = parse_dns(data)
    except DNSParseError:
        return
    for name in [message.qname] if getattr(message, "qname", None) else []:
        assert len(name) <= 255
        base_domain(name)
        subdomain(name)
        assert 0.0 <= entropy(name) <= 8.0


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
