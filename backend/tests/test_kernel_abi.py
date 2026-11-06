"""
The Python readers and tools hard-code numbers from the kernel's UAPI header.
Parse the header and check they still match, so the two cannot drift apart.
"""

import importlib.util
import re
from pathlib import Path

from app.services import kguard_device, kguard_netlink

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "kernel" / "include" / "uapi" / "linux" / "kguard.h"


def enum_values(name):
    text = HEADER.read_text()
    body = re.search(r"enum " + name + r" \{(.*?)\};", text, re.S).group(1)
    values, current = {}, -1
    for line in body.splitlines():
        m = re.match(r"\s*(\w+)\s*(?:=\s*(\w+))?,", line)
        if not m or m.group(1).startswith("__"):
            continue
        current = int(m.group(2), 0) if m.group(2) else current + 1
        values[m.group(1)] = current
    return values


def define(name):
    value = re.search(rf"#define {name}\s+(\w+)", HEADER.read_text()).group(1)
    return int(value.rstrip("uUlL"), 0)


def load_kguardctl():
    spec = importlib.util.spec_from_file_location("kguardctl", ROOT / "kernel" / "tools" / "kguardctl.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_event_record_layout():
    assert kguard_device.EVENT.size == 96
    assert kguard_device.MAGIC == define("KGUARD_MMAP_MAGIC")
    assert kguard_device.ABI_VERSION == define("KGUARD_ABI_VERSION")
    assert {v: k for k, v in kguard_device.DIRECTIONS.items()} == {
        "in": enum_values("kguard_direction")["KGUARD_DIR_IN"],
        "out": enum_values("kguard_direction")["KGUARD_DIR_OUT"],
        "fwd": enum_values("kguard_direction")["KGUARD_DIR_FWD"],
    }
    ct = enum_values("kguard_ct_state")
    assert kguard_device.CT_STATES == {
        ct["KGUARD_CT_NONE"]: "none", ct["KGUARD_CT_NEW"]: "new",
        ct["KGUARD_CT_ESTABLISHED"]: "established", ct["KGUARD_CT_RELATED"]: "related",
        ct["KGUARD_CT_INVALID"]: "invalid", ct["KGUARD_CT_UNTRACKED"]: "untracked",
    }


def test_backend_netlink_constants():
    cmds = enum_values("kguard_genl_cmd")
    attrs = enum_values("kguard_genl_attr")
    assert kguard_netlink.KGUARD_CMD_ALERT == cmds["KGUARD_CMD_ALERT"]
    assert kguard_netlink.KGUARD_CMD_CONFIG_CHANGED == cmds["KGUARD_CMD_CONFIG_CHANGED"]
    assert kguard_netlink.KGUARD_CMD_BLOCK_ADD == cmds["KGUARD_CMD_BLOCK_ADD"]
    for name in ("ADDR", "NETNS", "TIMESTAMP", "ALERT_TYPE", "ALERT_ACTION", "ALERT_PORTS", "ALERT_ATTEMPTS"):
        assert getattr(kguard_netlink, f"KGUARD_ATTR_{name}") == attrs[f"KGUARD_ATTR_{name}"], name
    types = enum_values("kguard_alert_type")
    assert kguard_netlink.ALERT_TYPES == {
        types["KGUARD_ALERT_SCAN"]: "scan",
        types["KGUARD_ALERT_SYN_RATE"]: "syn_rate",
    }


def test_kguardctl_constants():
    ctl = load_kguardctl()
    cmds = enum_values("kguard_genl_cmd")
    attrs = enum_values("kguard_genl_attr")
    for name, value in cmds.items():
        short = name.replace("KGUARD_", "")
        if hasattr(ctl, short):
            assert getattr(ctl, short) == value, name
    for attr_id, stat in ctl.STATS.items():
        key = "KGUARD_ATTR_STAT_" + {"ns_per_packet": "NS_PER_PKT"}.get(stat, stat.upper())
        assert attrs[key] == attr_id, key
    for attr_id, (name, _fmt) in ctl.CONFIG.items():
        assert attrs["KGUARD_ATTR_CFG_" + name.upper()] == attr_id, name
    for name in ("ADDR", "PREFIX_LEN", "TIMEOUT", "EXPIRES_MS", "REASON", "NETNS", "TIMESTAMP",
                 "ALERT_TYPE", "ALERT_ACTION", "ALERT_PORTS", "ALERT_ATTEMPTS", "ALLOW_ENTRY"):
        assert getattr(ctl, f"ATTR_{name}") == attrs[f"KGUARD_ATTR_{name}"], name
