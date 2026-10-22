#!/usr/bin/env python3
"""Generate only the versioned synthetic config seeds; never touch runtime corpora."""

import argparse
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1] / "seeds"


def framed(selector, file=b"", process=b""):
    return bytes([selector]) + struct.pack("<I", len(file)) + file + process


def fixtures():
    env = {
        "empty.env": b"",
        "valid.env": b"VECTIS_MODE=prod\nVECTIS_LOG_LEVEL=warning\n",
        "quoting.env": b"VECTIS_PLAINTEXT_MESSAGE='  literal # text=a=b  '\n",
        "unicode.env": "VECTIS_PLAINTEXT_MESSAGE='synthetic \U0001f642'\n".encode(),
        "crlf.env": b"VECTIS_MODE=dev\r\nVECTIS_APIKEY=\r\n",
        "duplicate.env": b"VECTIS_MODE=dev\nVECTIS_MODE=dev\n",
        "nul.env": b"VECTIS_MODE=dev\x00\n",
        "isolated-cr.env": b"VECTIS_MODE=dev\rvalue",
        "bad-name.env": b"VECTIS_BAD-NAME=synthetic",
        "bad-quote.env": b"VECTIS_MODE='synthetic",
        "unknown.env": b"VECTIS_UNKNOWN_SETTING=synthetic",
        "prohibited.env": b"VECTIS_UNSEAL_KEY=synthetic",
    }
    for length in (128, 129):
        env[f"name-{length}.env"] = b"VECTIS_" + b"A" * (length - 7) + b"=synthetic"
    for length in (4096, 4097):
        env[f"value-{length}.env"] = b"VECTIS_APIKEY=" + b"x" * length
    for length in (65536, 65537):
        env[f"file-{length}.env"] = b"#" + b"x" * (length - 1)

    loader = {f"scenario-{index}.bin": framed(index, b"VECTIS_MODE=prod", b"dev")
              for index in range(9)}
    loader.update({
        "short-header.bin": b"\x08\xff",
        "declared-length-max.bin": b"\x08\xff\xff\xff\xffVECTIS_MODE=dev",
        "empty-value.bin": framed(0),
        "non-unicode-process.bin": framed(0, process=b"synthetic\xff"),
        "non-unicode-file.bin": framed(8, b"\xff", b"dev"),
        "invalid-override.bin": framed(2, process=b"invalid"),
        "unused-non-unicode.bin": framed(4, process=b"\xff"),
    })
    for name, content in env.items():
        loader[f"file-{name}.bin"] = framed(8, content)
    for length in (4096, 4097):
        loader[f"process-{length}.bin"] = framed(0, process=b"x" * length)
    maximum = ((1 << (struct.calcsize("P") * 8)) - 1) >> 3
    for variable, values in enumerate((
        ("", " ", "0", "1", "+1", str(maximum), str(maximum + 1)),
        ("", " ", "0", "1", "+1", "128", str(maximum), str(maximum + 1)),
        ("", " ", "0", "1", "+1", "1000", "30000", "30001"),
    )):
        for index, value in enumerate(values):
            loader[f"admission-{variable}-{index}.bin"] = framed(6 + variable * 9, process=value.encode())
    return {"fuzz_env_file": env, "fuzz_config_loader": loader}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Generate versioned seeds")
    args = parser.parse_args()
    count = 0
    for target, seeds in fixtures().items():
        for name, content in seeds.items():
            path = ROOT / target / name
            if args.write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            elif not path.is_file() or path.read_bytes() != content:
                raise SystemExit(f"seed mismatch: {target}/{name}")
            count += 1
    print(f"Configuration seeds: {count} {'generated' if args.write else 'verified'}")


if __name__ == "__main__":
    main()
