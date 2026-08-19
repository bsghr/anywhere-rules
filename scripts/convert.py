#!/usr/bin/env python3
"""
将 Shadowrocket/Surge 风格规则集转换为 Anywhere .arrs。

原则：
1. 不重新整理规则，仅进行格式转换；
2. 保持原规则顺序；
3. 不主动去重；
4. Unsupported 规则明确记录到头部；
5. DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / IP-CIDR6
   分别映射为 Anywhere 支持的对应规则类型。
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
import urllib.request
from pathlib import Path

TYPE_MAP = {
    "DOMAIN": 1,
    "DOMAIN-SUFFIX": 2,
    "DOMAIN-KEYWORD": 3,
    "IP-CIDR": 4,
    "IP-CIDR6": 5,
}

SUPPORTED = set(TYPE_MAP)


def download(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "anywhere-rules-sync/1.0"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8-sig")


def clean_comment(line: str) -> str:
    # 规则行末尾的 // 注释不是规则内容。
    return line.split("//", 1)[0].strip()


def parse_rule(line: str):
    line = clean_comment(line)
    if not line or line.startswith("#"):
        return None, None

    # Shadowrocket 规则一般为 TYPE,value[,policy...]
    parts = [x.strip() for x in line.split(",")]
    rule_type = parts[0].upper()

    if rule_type not in SUPPORTED:
        return rule_type, None

    if len(parts) < 2 or not parts[1]:
        return rule_type, None

    value = parts[1]

    # IP-CIDR 可能同时承载 IPv4/IPv6；按地址族自动分流。
    if rule_type == "IP-CIDR":
        try:
            network = ipaddress.ip_network(value, strict=False)
            if network.version == 6:
                return "IP-CIDR6", network.with_prefixlen
            return "IP-CIDR", network.with_prefixlen
        except ValueError:
            return rule_type, None

    if rule_type == "IP-CIDR6":
        try:
            network = ipaddress.ip_network(value, strict=False)
            if network.version == 6:
                return rule_type, network.with_prefixlen
            return rule_type, None
        except ValueError:
            return rule_type, None

    return rule_type, value


def parse_header(lines):
    meta = {}
    for line in lines:
        if not line.startswith("#"):
            break
        m = re.match(r"#\s*([^:]+):\s*(.*)$", line)
        if m:
            meta[m.group(1).strip().upper()] = m.group(2).strip()
    return meta


def convert(source_text: str, name: str, source_url: str, routing: int, description: str):
    lines = source_text.splitlines()
    source_meta = parse_header(lines)

    output = []
    skipped = {}
    total_source_rules = 0

    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue

        total_source_rules += 1
        rule_type, value = parse_rule(raw)

        if rule_type is None:
            continue

        if value is None:
            skipped[rule_type] = skipped.get(rule_type, 0) + 1
            continue

        output.append(f"{TYPE_MAP[rule_type]}, {value}")

    header = [
        f"# NAME: {name}",
        "# GENERATED-FOR: Anywhere Routing Rule Set",
        f"# DESCRIPTION: {description}",
        f"# RULES: {len(output)}",
        f"# SOURCE-RULES: {total_source_rules}",
        f"# SOURCE: {source_url}",
    ]

    if "UPDATED" in source_meta:
        header.append(f"# UPSTREAM-UPDATED: {source_meta['UPDATED']}")

    if skipped:
        header.append(f"# SKIPPED: {sum(skipped.values())}")
        header.append(
            "# SKIPPED-TYPES: " +
            ", ".join(f"{k}={v}" for k, v in sorted(skipped.items()))
        )
    else:
        header.append("# SKIPPED: 0")

    return "\n".join(header + ["", f"name = {name}", f"routing = {routing}"] + output) + "\n", skipped


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--routing", type=int, default=0)
    parser.add_argument("--description", default="")
    args = parser.parse_args()

    try:
        text = download(args.source)
        result, skipped = convert(
            text,
            args.name,
            args.source,
            args.routing,
            args.description,
        )
    except Exception as e:
        print(f"ERROR: {args.name}: {e}", file=sys.stderr)
        return 1

    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result, encoding="utf-8")

    if skipped:
        print(f"{args.name}: converted with skipped types: {skipped}")
    else:
        print(f"{args.name}: converted successfully")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
