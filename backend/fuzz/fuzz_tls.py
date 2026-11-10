"""
Fuzz the TLS ClientHello parser (roadmap P8.8) with Atheris (libFuzzer).

The contract: parse_client_hello either returns a ClientHello whose
fingerprints can be computed, or raises TLSParseError. Anything else (an
IndexError, a struct.error, a hang) is a bug.

    python fuzz/fuzz_tls.py -max_total_time=3600 fuzz/corpus/tls
"""

import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

with atheris.instrument_imports():
    from app.services.tls_parser import TLSParseError, parse_client_hello, record_length


def test_one_input(data: bytes) -> None:
    record_length(data)
    try:
        hello = parse_client_hello(data)
    except TLSParseError:
        return
    # Everything the backend derives from a hello must work too
    assert len(hello.ja3) == 32
    assert hello.ja4.count("_") == 2
    hello.ja3_string
    hello.ja4_r


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
