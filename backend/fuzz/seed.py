"""Write seed corpora: the real ClientHellos from the tests, and a few DNS messages"""

import os
import shutil
import struct
import sys
from pathlib import Path

HERE = Path(__file__).parent
CORPUS = HERE / "corpus"


def dns_query(name: str, qtype: int = 1, flags: int = 0x0100) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x1234, flags, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def main() -> None:
    (CORPUS / "tls").mkdir(parents=True, exist_ok=True)
    (CORPUS / "dns").mkdir(parents=True, exist_ok=True)
    for f in (HERE.parent / "tests" / "fixtures" / "tls").glob("*.bin"):
        shutil.copy(f, CORPUS / "tls" / f.name)
    seeds = {"a": dns_query("www.example.com"), "txt": dns_query("x7f3a9.tunnel.example", 16),
             "long": dns_query(".".join(["a" * 63] * 3) + ".example", 10)}
    # A response with one answer whose name is a compression pointer to the question
    response = dns_query("example.com", 1, 0x8180)
    record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
    seeds["answer"] = response[:6] + b"\x00\x01" + response[8:] + record
    for name, data in seeds.items():
        (CORPUS / "dns" / name).write_bytes(data)
    print(f"tls seeds: {len(os.listdir(CORPUS / 'tls'))}, dns seeds: {len(seeds)}", file=sys.stderr)


if __name__ == "__main__":
    main()
