"""Mine and sign a U object. RFC 8032 test key only unless --sk-hex is given."""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from protocol import mine_and_sign, parse_object

TEST_SK = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: mine.py unsigned.json [--sk-hex HEX]", file=sys.stderr)
        return 3
    sk = TEST_SK
    if len(argv) == 4 and argv[2] == "--sk-hex":
        sk = bytes.fromhex(argv[3])
    u = parse_object(Path(argv[1]).read_bytes())
    env = mine_and_sign(u, sk)
    sys.stdout.write(json.dumps(env, ensure_ascii=False, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
