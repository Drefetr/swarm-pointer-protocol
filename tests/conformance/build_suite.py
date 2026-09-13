"""Emit conformance/vectors/suite.json from conformance/vectors/source.json.

Run once when the source vector object changes. Verifiers must not import this
file. The emitted suite is the independently consumable artifact.

Usage:
  python build_suite.py           # rebuild suite.json
  python build_suite.py --check   # verify suite.json matches generator (CI)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SRC = ROOT / "tests" / "conformance" / "vectors" / "source.json"
OUT = Path(__file__).resolve().parent / "vectors" / "suite.json"

RESERVED_U = (
    "v",
    "type",
    "actor",
    "created",
    "nonce",
    "channel",
    "ref",
    "parents",
    "descriptor",
    "ext",
)


def compact(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def u_of(envelope: dict) -> dict:
    return {k: v for k, v in envelope.items() if k not in ("id", "sig")}


def full(cid, raw, want=None, expect="valid"):
    case = {
        "id": cid,
        "class": "full-assertion",
        "expect": expect,
        "input": {"kind": "json-text", "utf8": raw},
    }
    if want:
        case["want"] = want
    return case


def main() -> None:
    src = json.loads(SRC.read_text(encoding="utf-8"))
    cases = []

    for key, label in (
        ("A1_channel", "A.1"),
        ("A2_pointer", "A.2"),
        ("A3_unlisted", "A.3"),
        ("A6_channel_no_descriptor", "A.6"),
        ("A7_pointer_with_parent", "A.7"),
        ("A8_pointer_with_ext", "A.8"),
    ):
        rec = src[key]
        env = rec["envelope"]
        cases.append(
            full(
                label,
                compact(env),
                {
                    "id": rec["id"],
                    "units": rec["units"],
                    "target_hex": rec["target_hex"],
                    "jcs": rec["jcs"],
                    "sig": rec["sig"],
                },
            )
        )

    cases.append(
        full(
            "A.11",
            src["A11_A2_with_v_1_0"],
            {
                "id": src["A2_pointer"]["id"],
                "units": src["A2_pointer"]["units"],
                "target_hex": src["A2_pointer"]["target_hex"],
                "jcs": src["A2_pointer"]["jcs"],
                "sig": src["A2_pointer"]["sig"],
            },
        )
    )

    a2 = compact(src["A2_pointer"]["envelope"])
    if not a2.startswith('{"v":1,'):
        raise SystemExit("A.2 envelope prefix changed; update A.12 splice")
    a12 = '{"v":1.0000000000000001,' + a2[len('{"v":1,') :]
    cases.append(
        full(
            "A.12",
            a12,
            {
                "id": src["A2_pointer"]["id"],
                "units": src["A2_pointer"]["units"],
                "target_hex": src["A2_pointer"]["target_hex"],
                "jcs": src["A2_pointer"]["jcs"],
                "sig": src["A2_pointer"]["sig"],
            },
        )
    )

    cases.append(
        {
            "id": "A.9",
            "class": "jcs",
            "expect": "valid",
            "input": {
                "kind": "json-text",
                "utf8": '{"\U00010000":2,"\ue000":1}',
            },
            "want": {"jcs_hex": src["A9_jcs_utf8_hex"]},
        }
    )
    cases.append(
        {
            "id": "A.13",
            "class": "jcs",
            "expect": "valid",
            "input": {"kind": "json-text", "utf8": '{"n":9007199254740993}'},
            "want": {"jcs": src["A13_jcs"]["jcs"]},
        }
    )
    cases.append(
        {
            "id": "A.14",
            "class": "jcs",
            "expect": "valid",
            "input": {"kind": "json-text", "utf8": '{"n":5e-324}'},
            "want": {"jcs": '{"n":5e-324}'},
        }
    )
    cases.append(
        {
            "id": "A.15",
            "class": "jcs",
            "expect": "valid",
            "input": {"kind": "json-text", "utf8": src["A15_hostile_review_input"]},
            "want": {"jcs": src["A15_large_int_jcs"]["jcs"]},
        }
    )

    a4 = src["A4_optional_field_identity"]
    cases.append(
        {
            "id": "A.4-omitted",
            "class": "jcs",
            "expect": "valid",
            "input": {
                "kind": "json-text",
                "utf8": a4["omitted_parents_jcs"],
            },
            "want": {
                "jcs": a4["omitted_parents_jcs"],
                "id": a4["omitted_parents_id"],
            },
        }
    )
    cases.append(
        {
            "id": "A.4-empty",
            "class": "jcs",
            "expect": "valid",
            "input": {"kind": "json-text", "utf8": a4["empty_parents_jcs"]},
            "want": {
                "jcs": a4["empty_parents_jcs"],
                "id": a4["empty_parents_id"],
            },
        }
    )

    actor = src["test_key"]["actor"]
    obj_hash = src["object"]["hash"]
    a3_ch = src["A3_unlisted"]["u"]["channel"]
    cases.append(
        {
            "id": "A.5",
            "class": "length",
            "expect": "valid",
            "input": {
                "kind": "construct-pad",
                "nonce": "9",
                "pad_len": 680,
                "channel": a3_ch,
                "actor": actor,
                "created": 1789184927,
                "hash": obj_hash,
            },
            "want": {"jcs_bytes": 1024, "units": 2},
        }
    )
    cases.append(
        {
            "id": "A.5b",
            "class": "length",
            "expect": "valid",
            "input": {
                "kind": "construct-pad",
                "nonce": "10",
                "pad_len": 680,
                "channel": a3_ch,
                "actor": actor,
                "created": 1789184927,
                "hash": obj_hash,
            },
            "want": {"jcs_bytes": 1025, "units": 3},
        }
    )
    cases.append(
        {
            "id": "A.10",
            "class": "length",
            "expect": "valid",
            "input": {
                "kind": "construct-pad",
                "nonce": "0",
                "pad_len": 1048232,
                "channel": a3_ch,
                "actor": actor,
                "created": 1789184927,
                "hash": obj_hash,
            },
            "want": {"jcs_bytes": 1048576},
        }
    )
    cases.append(
        {
            "id": "N17",
            "class": "length",
            "expect": "invalid",
            "input": {
                "kind": "construct-pad",
                "nonce": "0",
                "pad_len": 1048233,
                "channel": a3_ch,
                "actor": actor,
                "created": 1789184927,
                "hash": obj_hash,
            },
            "want": {"jcs_bytes": 1048577, "reasons": ["jcs-too-large"]},
        }
    )

    cases.append(
        {
            "id": "N1",
            "class": "json-input",
            "expect": "invalid",
            "input": {"kind": "json-text", "utf8": src["N1_duplicate_v_raw"]},
            "want": {"reasons": ["duplicate-member-name"]},
        }
    )
    cases.append(
        {
            "id": "N2",
            "class": "json-input",
            "expect": "invalid",
            "input": {"kind": "json-text", "utf8": r'{"x":"\uD800"}'},
            "want": {"reasons": ["lone-surrogate"]},
        }
    )
    cases.append(
        {
            "id": "N21",
            "class": "json-input",
            "expect": "invalid",
            "input": {"kind": "json-text", "utf8": r'{"ext":{"n":"\uFDD0"}}'},
            "want": {"reasons": ["noncharacter"]},
        }
    )
    cases.append(
        {
            "id": "N24",
            "class": "json-input",
            "expect": "invalid",
            "input": {"kind": "json-text", "utf8": r'{"ext":{"n":"\uFFFE"}}'},
            "want": {"reasons": ["noncharacter"]},
        }
    )
    cases.append(
        {
            "id": "N25",
            "class": "json-input",
            "expect": "invalid",
            "input": {"kind": "json-text", "utf8": '{"ext":{"n":"\U0010FFFF"}}'},
            "want": {"reasons": ["noncharacter"]},
        }
    )
    cases.append(
        {
            "id": "N22",
            "class": "json-input",
            "expect": "invalid",
            "input": {"kind": "json-text", "utf8": '{"created":-0}'},
            "want": {"reasons": ["negative-zero"]},
        }
    )
    cases.append(
        {
            "id": "N23",
            "class": "json-input",
            "expect": "invalid",
            "input": {
                "kind": "json-text",
                "utf8": "\ufeff" + compact(src["A2_pointer"]["envelope"]),
            },
            "want": {"reasons": ["invalid-json"]},
        }
    )

    a2u = dict(src["A2_pointer"]["u"])
    n9 = dict(a2u)
    n9["parents"] = (
        "sha256:000018da6b416f566189390610b73b34b6d109265842a1988b3d41301490c6ae"
    )
    cases.append(
        {
            "id": "N9",
            "class": "schema",
            "expect": "invalid",
            "input": {"kind": "json-text", "utf8": compact(n9)},
            "want": {"reasons": ["schema"]},
        }
    )
    cases.append(
        {
            "id": "N10",
            "class": "schema",
            "expect": "invalid",
            "input": {
                "kind": "json-text",
                "utf8": compact(u_of(src["N10_pointer_with_descriptor"])),
            },
            "want": {"reasons": ["schema"]},
        }
    )
    n11 = dict(src["A6_channel_no_descriptor"]["u"])
    n11["ref"] = {"hash": obj_hash, "locators": []}
    cases.append(
        {
            "id": "N11",
            "class": "schema",
            "expect": "invalid",
            "input": {"kind": "json-text", "utf8": compact(n11)},
            "want": {"reasons": ["schema"]},
        }
    )
    n12 = dict(a2u)
    n12["ref"] = {
        "hash": obj_hash,
        "locators": [],
        "foo": 1,
    }
    cases.append(
        {
            "id": "N12",
            "class": "schema",
            "expect": "invalid",
            "input": {"kind": "json-text", "utf8": compact(n12)},
            "want": {"reasons": ["schema"]},
        }
    )
    cases.append(
        {
            "id": "N13",
            "class": "schema",
            "expect": "invalid",
            "input": {
                "kind": "json-text",
                "utf8": compact(u_of(src["N13_unknown_top_level"])),
            },
            "want": {"reasons": ["schema"]},
        }
    )
    cases.append(
        {
            "id": "N18",
            "class": "schema",
            "expect": "invalid",
            "input": {
                "kind": "json-text",
                "utf8": compact(u_of(src["N18_unknown_type"])),
            },
            "want": {"reasons": ["unknown-type"]},
        }
    )

    n3 = dict(src["A2_pointer"]["envelope"])
    n3["created"] = -1
    cases.append(
        full(
            "N3",
            compact(n3),
            {"reasons": ["created"]},
            expect="invalid",
        )
    )
    n4 = dict(src["A2_pointer"]["envelope"])
    n4["created"] = 9007199254740992
    cases.append(
        full(
            "N4",
            compact(n4),
            {"reasons": ["created"]},
            expect="invalid",
        )
    )
    n5 = dict(src["A2_pointer"]["envelope"])
    n5["nonce"] = "18446744073709551616"
    cases.append(
        full(
            "N5",
            compact(n5),
            {"reasons": ["nonce"]},
            expect="invalid",
        )
    )
    n6 = dict(src["A2_pointer"]["envelope"])
    n6["nonce"] = "018"
    cases.append(
        full(
            "N6",
            compact(n6),
            {"reasons": ["nonce"]},
            expect="invalid",
        )
    )
    n7 = dict(src["A2_pointer"]["envelope"])
    n7["channel"] = (
        "sha256:0000058DA39AF8F5E2CB8C1268B45E6F198320A5E5AC53512F4B707E8672986B"
    )
    cases.append(
        full(
            "N7",
            compact(n7),
            {"reasons": ["identifier"]},
            expect="invalid",
        )
    )
    n8 = dict(src["A2_pointer"]["envelope"])
    n8["channel"] = "sha256:00"
    cases.append(
        full(
            "N8",
            compact(n8),
            {"reasons": ["identifier"]},
            expect="invalid",
        )
    )

    n26 = dict(src["A2_pointer"]["envelope"])
    n26["v"] = 1.5
    cases.append(
        full(
            "N26",
            compact(n26),
            {"reasons": ["unknown-v"]},
            expect="unsupported",
        )
    )

    n16 = dict(a2u)
    n16["ref"] = {"hash": obj_hash, "locators": ["x" * 8193]}
    cases.append(
        {
            "id": "N16",
            "class": "length",
            "expect": "invalid",
            "input": {"kind": "json-text", "utf8": compact(n16)},
            "want": {"reasons": ["locator-too-long"]},
        }
    )

    pk = src["test_key"]["public_key_hex"]
    d_a1 = src["A1_channel"]["d_hex"]
    cases.append(
        {
            "id": "N14",
            "class": "spp-ed25519-1",
            "expect": "invalid",
            "input": {
                "kind": "ed25519",
                "A": pk,
                "sig": src["ed25519"]["A1_sig_S_plus_L"],
                "D": d_a1,
            },
            "want": {"reasons": ["signature"]},
        }
    )
    cases.append(
        {
            "id": "N15",
            "class": "spp-ed25519-1",
            "expect": "invalid",
            "input": {
                "kind": "ed25519",
                "A": src["ed25519"]["identity_A"],
                "sig": src["A1_channel"]["sig"],
                "D": d_a1,
            },
            "want": {"reasons": ["signature"]},
        }
    )
    for nid in ("N19", "N20"):
        rec = src[f"{nid}_ed25519"]
        cases.append(
            {
                "id": nid,
                "class": "spp-ed25519-1",
                "expect": "invalid",
                "input": {
                    "kind": "ed25519",
                    "A": rec["A"],
                    "sig": rec["sig"],
                    "D": rec["D"],
                },
                "want": {"reasons": ["signature"]},
            }
        )

    powb = src["pow_boundaries_units_3"]
    for i, row in enumerate(powb["cases"]):
        cases.append(
            {
                "id": f"B.{i + 1}",
                "class": "work",
                "expect": "valid" if row["accept"] else "invalid",
                "input": {
                    "kind": "work-compare",
                    "units": powb["units"],
                    "H_hex": row["H_hex"],
                },
                "want": {
                    "accept": row["accept"],
                    "target_hex": powb["target_hex"],
                },
            }
        )

    # --- Nesting-depth vectors (RC3 remediation of the impl-a recursion fork).
    # ND.x: paired cases at each depth — mined-valid, work-failure (true id,
    # real signature, unmined), id-mismatch, schema-illegal — plus the exact
    # 1 MiB canonical-body boundary via construct-depth. §5: nesting depth is
    # not a validity criterion; the 1 MiB JCS bound is.
    nd = src["nesting_depth"]
    n = 0
    for d in ("495", "600", "2200"):
        rec = nd["depths"][d]
        n += 1
        cases.append(
            full(
                f"ND.{n}",
                rec["mined"]["envelope"],
                {
                    "id": rec["mined"]["id"],
                    "units": rec["mined"]["units"],
                    "target_hex": rec["mined"]["target_hex"],
                },
            )
        )
        n += 1
        cases.append(
            full(
                f"ND.{n}",
                rec["work_fail"]["envelope"],
                {"reasons": ["insufficient-work"]},
                expect="invalid",
            )
        )
        n += 1
        cases.append(
            full(
                f"ND.{n}",
                rec["id_mismatch"]["envelope"],
                {"reasons": ["id-mismatch"]},
                expect="invalid",
            )
        )
        n += 1
        cases.append(
            {
                "id": f"ND.{n}",
                "class": "schema",
                "expect": "invalid",
                "input": {
                    "kind": "json-text",
                    "utf8": rec["work_fail"]["u"][:-1] + ',"parents":"'
                    + src["object"]["hash"] + '"}',
                },
                "want": {"reasons": ["schema"]},
            }
        )
    # JCS identity of a deep U (id pins the canonical bytes compactly).
    n += 1
    cases.append(
        {
            "id": f"ND.{n}",
            "class": "jcs",
            "expect": "valid",
            "input": {
                "kind": "json-text",
                "utf8": nd["depths"]["2200"]["mined"]["u"],
            },
            "want": {"id": nd["depths"]["2200"]["mined"]["id"]},
        }
    )
    # Exact 1 MiB canonical-body boundary at maximum legal nesting depth.
    n += 1
    cases.append(
        {
            "id": f"ND.{n}",
            "class": "length",
            "expect": "valid",
            "input": {
                "kind": "construct-depth",
                "depth": nd["max_fit_depth"],
                "nonce": nd["max_fit"]["nonce"],
                "channel": a3_ch,
                "actor": actor,
                "created": 1789184927,
                "hash": obj_hash,
            },
            "want": {
                "jcs_bytes": nd["max_fit"]["jcs_bytes"],
                "units": nd["max_fit"]["units"],
            },
        }
    )
    n += 1
    cases.append(
        {
            "id": f"ND.{n}",
            "class": "length",
            "expect": "invalid",
            "input": {
                "kind": "construct-depth",
                "depth": nd["over_1mib_depth"],
                "nonce": "0",
                "channel": a3_ch,
                "actor": actor,
                "created": 1789184927,
                "hash": obj_hash,
            },
            "want": {"reasons": ["jcs-too-large"]},
        }
    )

    suite = {
        "profile": "spp-v1-rc3",
        "comment": "Independently consumable. Do not generate these at verify time.",
        "cases": cases,
    }
    return suite


def _render(suite: dict) -> str:
    return json.dumps(suite, indent=2, ensure_ascii=False) + "\n"


def build_and_write() -> None:
    suite = main()
    OUT.write_text(_render(suite), encoding="utf-8")
    print(f"wrote {OUT} ({len(suite['cases'])} cases)")


def check() -> int:
    """Regenerate suite in memory and compare with committed suite.json.

    Exits 1 if different (CI freeze blocker), 0 if identical.
    """
    suite = main()
    generated = _render(suite)
    if not OUT.exists():
        print(f"FAIL: {OUT} does not exist — run build_suite.py to create it")
        return 1
    committed = OUT.read_text(encoding="utf-8")
    if generated == committed:
        print(f"OK: suite.json matches generator ({len(suite['cases'])} cases)")
        return 0
    # Show a useful diff summary
    gen_cases = suite["cases"]
    try:
        com_cases = json.loads(committed)["cases"]
    except Exception:
        com_cases = []
    gen_ids = [c["id"] for c in gen_cases]
    com_ids = [c["id"] for c in com_cases]
    missing = [i for i in gen_ids if i not in com_ids]
    extra = [i for i in com_ids if i not in gen_ids]
    if missing:
        print(f"  Missing from committed suite: {missing}")
    if extra:
        print(f"  Extra in committed suite: {extra}")
    if not missing and not extra:
        print("  Case list matches but content differs (check field values)")
    print(f"FAIL: committed suite.json does not match generator output")
    print(f"  Run: python conformance/build_suite.py  to rebuild")
    return 1


if __name__ == "__main__":
    if "--check" in sys.argv:
        raise SystemExit(check())
    build_and_write()
