import copy
import json

from oracle import _parse


BAD_VALUES = [
    None,
    True,
    False,
    0,
    -1,
    2**70,
    -(2**70),
    1.5,
    "",
    "A" * 20000,
    "\x00\x01\x02",
    "../../../etc/passwd",
    "🔥" * 500,
    [],
    {},
    [1] * 2000,
    {"x": {"y": {"z": {}}}},
    float("nan"),
    float("inf"),
]

NEAR_MISS_ENUMS = [
    "Ed25518",
    "Ed449",
    "ML-DSA-45",
    "ML-DSA-43",
    "ML-KEM-513",
    "ChaCha20Poly1306",
    "X25518",
    "X449",
    "AES-257/GCM",
    "AES-128/CBC",
    "SHA-385",
    "BLAKE2b(257)",
]

NUMERIC_EDGE_STRINGS = ["1e400", "-0", "007", "0x1F", "1_000", str(2**64), "NaN"]

NASTY_KIDS = [
    "",
    "..",
    "../..",
    "%2e%2e",
    "..%2f..",
    "\x00\x00",
    "🔥",
    "a" * 10000,
    "not-hex",
    "z" * 64,
    "0" * 63,
    "0" * 65,
    "0" * 64,
    " ",
    "null",
]

BAD_APIKEYS = [
    "",
    "x",
    "00" * 32,
    "not-a-hex-key",
    "café" * 10,
    "a" * 5000,
    "0" * 63,
    "0" * 65,
]

WRONG_METHODS = ["GET", "PUT", "DELETE", "PATCH", "HEAD"]
def all_paths(node, prefix=()):
    paths = [prefix]
    if isinstance(node, dict):
        for key, value in node.items():
            paths.extend(all_paths(value, prefix + (key,)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            paths.extend(all_paths(value, prefix + (index,)))
    return paths


def get_at(node, path):
    for step in path:
        node = node[step]
    return node


def set_at(node, path, value):
    if not path:
        return value
    parent = get_at(node, path[:-1])
    parent[path[-1]] = value
    return node


def del_at(node, path):
    if not path:
        return node
    parent = get_at(node, path[:-1])
    key = path[-1]
    if isinstance(parent, dict):
        parent.pop(key, None)
    elif isinstance(parent, list) and isinstance(key, int) and 0 <= key < len(parent):
        parent.pop(key)
    return node


def corrupt_string(value, rng):
    if not value:
        return rng.choice(["", "x", "\x00"])
    op = rng.choice(["flip", "truncate", "append", "huge", "nullbyte", "odd"])
    if op == "flip":
        i = rng.randrange(len(value))
        return value[:i] + rng.choice("zZ!@#\x00") + value[i + 1 :]
    if op == "truncate":
        return value[: rng.randrange(len(value))]
    if op == "append":
        return value + rng.choice(["==", "..", "%%", "\x00"]) * 3
    if op == "huge":
        return value * 50
    if op == "nullbyte":
        i = rng.randrange(len(value))
        return value[:i] + "\x00" + value[i:]
    return value[:-1] if len(value) > 1 else value + "a"


def looks_hex(value):
    return (
        isinstance(value, str)
        and len(value) >= 2
        and all(c in "0123456789abcdefABCDEF" for c in value)
    )


def domain_mutate(key, value, rng):
    key_lower = str(key).lower()
    if "alg" in key_lower or "variant" in key_lower or "cipher" in key_lower:
        return rng.choice(NEAR_MISS_ENUMS)
    if looks_hex(value):
        op = rng.choice(["drop1", "add1", "double", "halve", "oddbyte"])
        if op == "drop1":
            return value[:-1]
        if op == "add1":
            return value + "a"
        if op == "double":
            return value + value
        if op == "halve":
            return value[: len(value) // 2]
        return value + "abc"
    return rng.choice(NUMERIC_EDGE_STRINGS)


def mutate_structured(seed, rng):
    node = json.loads(json.dumps(seed))
    for _ in range(rng.randint(1, 3)):
        paths = all_paths(node)
        path = rng.choice(paths)
        if path and rng.random() < 0.4:
            node = del_at(node, path)
            continue
        current = get_at(node, path) if path else node
        last_key = path[-1] if path else None
        roll = rng.random()
        if isinstance(current, str) and last_key is not None and roll < 0.3:
            new_value = domain_mutate(last_key, current, rng)
        elif isinstance(current, str) and roll < 0.7:
            new_value = corrupt_string(current, rng)
        else:
            new_value = copy.deepcopy(rng.choice(BAD_VALUES))
        node = set_at(node, path, new_value)
    return node


def mutate_raw(seed, rng):
    data = json.dumps(seed).encode("utf-8")
    op = rng.choice(
        ["truncate", "flip", "append", "prepend", "nullbyte", "dupkey", "repeat"]
    )
    if op == "truncate":
        return data[: rng.randrange(len(data))]
    if op == "flip":
        i = rng.randrange(len(data))
        buffer = bytearray(data)
        buffer[i] ^= rng.randint(1, 255)
        return bytes(buffer)
    if op == "append":
        return data + rng.choice([b"}}}", b"\x00\x00", b",,,", b"[]"])
    if op == "prepend":
        return rng.choice([b"\x00", b"[", b"{"]) + data
    if op == "nullbyte":
        i = rng.randrange(len(data))
        return data[:i] + b"\x00" + data[i:]
    if op == "dupkey":
        obj = _parse(data.decode("utf-8", "replace"))
        if isinstance(obj, dict) and obj:
            key = rng.choice(list(obj.keys()))
            duplicate = json.dumps({key: obj[key]})[1:-1]
            return data.replace(b"{", b"{" + duplicate.encode("utf-8") + b",", 1)
        return data + b',"dup":"dup"'
    return data * rng.randint(2, 5)
