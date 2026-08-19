#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import sys
import urllib.request
from pathlib import Path


ADGUARD_DOMAIN_PATTERN = re.compile(
    r"^\|\|([A-Za-z0-9*._-]+)\^$"
)


def download(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "anywhere-rules-sync/1.0"},
    )

    with urllib.request.urlopen(req, timeout=60) as response:
        return response.read().decode("utf-8-sig")


def parse_adguard_rule(line: str):
    """
    将 AdGuard 的域名规则：

        ||example.com^

    转换为：

        DOMAIN-SUFFIX -> Anywhere 类型 2

    仅转换不带其他修饰符的 ||domain^ 规则，
    避免改变原始规则语义。
    """

    line = line.strip()

    if not line:
        return None, None

    # AdGuard 注释及元数据
    if line.startswith("!"):
        return None, None

    # 白名单规则
    if line.startswith("@@"):
        return "EXCEPTION", None

    match = ADGUARD_DOMAIN_PATTERN.match(line)

    if match:
        domain = match.group(1)

        # AdGuard 中 * 属于通配语义，不能直接作为普通域名后缀转换。
        if "*" in domain:
            return "WILDCARD", None

        return "DOMAIN-SUFFIX", domain

    return "UNSUPPORTED", None


def parse_metadata(lines):
    metadata = {}

    for line in lines:
        line = line.strip()

        if not line.startswith("!"):
            continue

        content = line[1:].strip()

        if ":" in content:
            key, value = content.split(":", 1)
            metadata[key.strip().upper()] = value.strip()

    return metadata


def convert(
    source_text: str,
    name: str,
    source_url: str,
    routing: int,
    description: str,
):
    lines = source_text.splitlines()

    metadata = parse_metadata(lines)

    output_rules = []
    skipped = {}

    source_rules = 0

    for line in lines:
        line = line.strip()

        if not line or line.startswith("!"):
            continue

        source_rules += 1

        rule_type, value = parse_adguard_rule(line)

        if rule_type == "DOMAIN-SUFFIX":
            output_rules.append(f"2, {value}")
            continue

        skipped[rule_type] = skipped.get(rule_type, 0) + 1

    header = [
        f"# NAME: {name}",
        "# GENERATED-FOR: Anywhere Routing Rule Set",
        f"# DESCRIPTION: {description}",
        f"# RULES: {len(output_rules)}",
        f"# SOURCE-RULES: {source_rules}",
        f"# SOURCE: {source_url}",
    ]

    if "UPDATED" in metadata:
        header.append(
            f"# UPSTREAM-UPDATED: {metadata['UPDATED']}"
        )

    if "TOTAL" in metadata:
        header.append(
            f"# UPSTREAM-TOTAL: {metadata['TOTAL']}"
        )

    skipped_count = sum(skipped.values())

    header.append(f"# SKIPPED: {skipped_count}")

    if skipped:
        header.append(
            "# SKIPPED-TYPES: "
            + ", ".join(
                f"{key}={value}"
                for key, value in sorted(skipped.items())
            )
        )

    result = (
        header
        + [
            "",
            f"name = {name}",
            f"routing = {routing}",
        ]
        + output_rules
    )

    return "\n".join(result) + "\n", skipped


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--name", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--routing", type=int, default=0)
    parser.add_argument("--description", default="")

    args = parser.parse_args()

    try:
        source_text = download(args.source)

        result, skipped = convert(
            source_text=source_text,
            name=args.name,
            source_url=args.source,
            routing=args.routing,
            description=args.description,
        )

    except Exception as exc:
        print(
            f"ERROR: {args.name}: {exc}",
            file=sys.stderr,
        )
        return 1

    output_path = Path(args.output)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        result,
        encoding="utf-8",
    )

    if skipped:
        print(
            f"{args.name}: converted with skipped types: {skipped}"
        )
    else:
        print(
            f"{args.name}: converted successfully"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
