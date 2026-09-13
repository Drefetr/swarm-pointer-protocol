"""§7A schema, §15–18 work/nonce, §20 validator, mining."""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any

from ed25519_spp import sign, verify_spp_ed25519_1
from jcs import canonicalize, canonicalize_bytes
from json_input import JsonInputError, parse_object, parse_utf8

SHA256_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
ACTOR_ID = re.compile(r"^ed25519:[0-9a-f]{64}$")
SIG = re.compile(r"^[0-9a-f]{128}$")
NONCE = re.compile(r"^(0|[1-9][0-9]{0,19})$")
MAX_NONCE = (1 << 64) - 1
MAX_CREATED = 9007199254740991
MAX_JCS = 1048576
MAX_LOCATORS = 256
MAX_LOCATOR_BYTES = 8192
MAX_PARENTS = 1024
UNIT_SCALE = 65536
MAX_H = (1 << 256) - 1
CORE = {
    "v",
    "type",
    "actor",
    "created",
    "nonce",
    "channel",
    "ref",
    "parents",
    "descriptor",
    "id",
    "sig",
    "ext",
}


class SppError(Exception):
    def __init__(self, stage: str, reason: str, detail: str = "") -> None:
        self.stage = stage
        self.reason = reason
        self.detail = detail
        super().__init__(f"{stage}:{reason}")


class UnsupportedError(SppError):
    pass


def reconstruct_u(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in ("id", "sig")}


def is_int_value(n: Any) -> bool:
    return isinstance(n, float) and math.isfinite(n) and n.is_integer()


def sha256_id_of(jcs: bytes) -> tuple[str, bytes]:
    d = hashlib.sha256(jcs).digest()
    return "sha256:" + d.hex(), d


def work_units(u: dict, jcs_len: int) -> int:
    t = u["type"]
    if t == "pointer":
        loc = len(u["ref"]["locators"])
        parents = len(u["parents"]) if "parents" in u else 0
        extra = 0
    elif t == "channel":
        loc = len(u["descriptor"]["locators"]) if "descriptor" in u else 0
        parents = 0
        extra = 16
    else:
        raise SppError("schema", "unknown-type")
    return 1 + math.ceil(jcs_len / 1024) + loc + parents + extra


def target_for_units(units: int) -> int:
    return MAX_H // (units * UNIT_SCALE)


def work_ok(h: int, units: int) -> bool:
    return h <= target_for_units(units)


def _check_sha256_id(value: Any, stage: str = "identifier") -> None:
    if not isinstance(value, str) or not SHA256_ID.fullmatch(value):
        raise SppError(stage, "identifier")


def _check_ref(obj: Any) -> None:
    if not isinstance(obj, dict) or set(obj.keys()) != {"hash", "locators"}:
        raise SppError("schema", "schema")
    _check_sha256_id(obj["hash"])
    locs = obj["locators"]
    if not isinstance(locs, list):
        raise SppError("schema", "schema")
    if len(locs) > MAX_LOCATORS:
        raise SppError("length", "too-many-locators")
    for loc in locs:
        if not isinstance(loc, str):
            raise SppError("schema", "schema")
        if len(loc.encode("utf-8")) > MAX_LOCATOR_BYTES:
            raise SppError("length", "locator-too-long")


def check_schema(u: dict) -> None:
    if not isinstance(u, dict):
        raise SppError("schema", "schema")
    unknown = set(u.keys()) - CORE
    if unknown:
        raise SppError("schema", "schema")
    for req in ("v", "type", "actor", "created", "nonce"):
        if req not in u:
            raise SppError("schema", "schema")
    if not isinstance(u["v"], float) or not math.isfinite(u["v"]):
        raise SppError("schema", "schema")
    if u["v"] != 1.0:
        raise UnsupportedError("version", "unknown-v")
    t = u["type"]
    if t not in ("channel", "pointer"):
        raise SppError("schema", "unknown-type")
    if not isinstance(u["actor"], str) or not ACTOR_ID.fullmatch(u["actor"]):
        raise SppError("identifier", "identifier")
    if not is_int_value(u["created"]):
        raise SppError("created", "created")
    created = int(u["created"])
    if created < 0 or created > MAX_CREATED:
        raise SppError("created", "created")
    if not isinstance(u["nonce"], str) or not NONCE.fullmatch(u["nonce"]):
        raise SppError("nonce", "nonce")
    if int(u["nonce"]) > MAX_NONCE:
        raise SppError("nonce", "nonce")
    if "ext" in u and not isinstance(u["ext"], dict):
        raise SppError("schema", "schema")

    if t == "pointer":
        if "descriptor" in u or "channel" not in u or "ref" not in u:
            raise SppError("schema", "schema")
        _check_sha256_id(u["channel"])
        _check_ref(u["ref"])
        if "parents" in u:
            parents = u["parents"]
            if not isinstance(parents, list):
                raise SppError("schema", "schema")
            if len(parents) > MAX_PARENTS:
                raise SppError("length", "too-many-parents")
            for p in parents:
                _check_sha256_id(p)
    else:
        if any(k in u for k in ("channel", "parents", "ref")):
            raise SppError("schema", "schema")
        if "descriptor" in u:
            _check_ref(u["descriptor"])


def validate_bytes(data: bytes) -> dict:
    try:
        obj = parse_object(data)
    except JsonInputError as e:
        raise SppError("json-input", e.reason, e.detail) from e
    return validate_object(obj)


def validate_object(obj: dict) -> dict:
    if (
        "v" in obj
        and isinstance(obj["v"], float)
        and math.isfinite(obj["v"])
        and obj["v"] != 1.0
    ):
        raise UnsupportedError("version", "unknown-v")
    u = reconstruct_u(obj)
    check_schema(u)
    jcs = canonicalize_bytes(u)
    if len(jcs) > MAX_JCS:
        raise SppError("length", "jcs-too-large")
    ident, digest = sha256_id_of(jcs)
    if "id" not in obj or not isinstance(obj["id"], str):
        raise SppError("identifier", "missing-id")
    if obj["id"] != ident:
        raise SppError("identity", "id-mismatch")
    units = work_units(u, len(jcs))
    h = int.from_bytes(digest, "big")
    tgt = target_for_units(units)
    if h > tgt:
        raise SppError("work", "insufficient-work")
    if "sig" not in obj or not isinstance(obj["sig"], str) or not SIG.fullmatch(obj["sig"]):
        raise SppError("signature", "signature")
    actor_hex = u["actor"].split(":", 1)[1]
    if not verify_spp_ed25519_1(
        bytes.fromhex(actor_hex), bytes.fromhex(obj["sig"]), digest
    ):
        raise SppError("signature", "signature")
    return {
        "id": ident,
        "units": units,
        "target_hex": f"{tgt:064x}",
        "jcs": canonicalize(u),
        "sig": obj["sig"],
        "digest_hex": digest.hex(),
    }


def mine_and_sign(u: dict, private_key: bytes, start: int = 0) -> dict:
    check_schema({**u, "nonce": u.get("nonce", "0")})
    body = {k: v for k, v in u.items() if k != "nonce"}
    nonce = start
    while nonce <= MAX_NONCE:
        cand = {**body, "nonce": str(nonce) if nonce > 0 else "0"}
        if nonce == 0:
            cand["nonce"] = "0"
        else:
            cand["nonce"] = str(nonce)
        jcs = canonicalize_bytes(cand)
        if len(jcs) > MAX_JCS:
            raise SppError("length", "jcs-too-large")
        units = work_units(cand, len(jcs))
        ident, digest = sha256_id_of(jcs)
        h = int.from_bytes(digest, "big")
        if h <= target_for_units(units):
            sig = sign(private_key, digest)
            env = dict(cand)
            env["id"] = ident
            env["sig"] = sig.hex()
            return env
        nonce += 1
    raise SppError("work", "insufficient-work")


def parse_any(data: bytes) -> Any:
    return parse_utf8(data)
