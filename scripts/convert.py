#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import re
import sys
import urllib.request
from pathlib import Path


# Anywhere rule type mapping:
# DOMAIN / DOMAIN-SUFFIX -> 2
# DOMAIN-KEYWORD        -> 3
# IP-CIDR               -> 0
# IP-CIDR6              -> 1
TYPE_MAP = {
    "DOMAIN": 2,
    "DOMAIN-SUFFIX": 2,
    "DOMAIN-KEYWORD": 3,
    "IP-CIDR": 0,
    "IP-CIDR6": 1,
}

MAX_RULES_PER_SET = 100_000


def download(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "bsghr-anywhere-rules/1.0"},
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8-sig")

def load_source(source: str) -> str:
    if source.startswith(("http://", "https://")):
        return download(source)

    return Path(source).read_text(encoding="utf-8-sig")

def parse_metadata(lines: list[str]) -> dict[str, str]:
    metadata: dict[str, str] = {}

    for raw in lines:
        line = raw.strip()

        if not line.startswith("#"):
            continue

        body = line[1:].strip()

        if ":" not in body:
            continue

        key, value = body.split(":", 1)
        metadata[key.strip().upper()] = value.strip()

    return metadata


def detect_format(source_url: str) -> str:
    if "/AdGuard/" in source_url:
        return "adguard"

    if source_url.endswith("_Domain.list"):
        return "shadowrocket-domain"

    return "shadowrocket"


def split_csv(line: str) -> list[str]:
    try:
        return [
            part.strip()
            for part in next(
                csv.reader(
                    [line],
                    skipinitialspace=True,
                )
            )
        ]
    except csv.Error:
        return []


def normalize_domain(value: str) -> str | None:
    domain = value.strip().lower().rstrip(".")

    if domain.startswith("+."):
        domain = domain[2:]

    if domain.startswith("*."):
        domain = domain[2:]

    if domain.startswith("."):
        domain = domain[1:]

    if not domain or "*" in domain or "?" in domain or "/" in domain:
        return None

    return domain


def normalize_keyword(value: str) -> str | None:
    keyword = value.strip().lower()

    if not keyword or "*" in keyword or "?" in keyword or "/" in keyword:
        return None

    return keyword


def parse_adguard(line: str):
    if not line or line.startswith("!"):
        return None, None

    # AdGuard exception rules cannot be represented
    # by a simple positive Anywhere rule.
    if line.startswith("@@"):
        return None, "EXCEPTION"

    # AdvertisingLite uses:
    # ||example.com^
    match = re.fullmatch(
        r"\|\|([A-Za-z0-9._-]+)\^",
        line,
    )

    if match:
        return (2, match.group(1).lower()), None

    return None, "UNSUPPORTED"


def parse_shadowrocket(line: str):
    if not line or line.startswith("#") or line.startswith("//"):
        return None, None

    fields = split_csv(line)

    if len(fields) < 2:
        return None, "UNKNOWN"

    rule_type = fields[0].upper()
    value = fields[1]

    anywhere_type = TYPE_MAP.get(rule_type)

    if anywhere_type is None:
        return None, rule_type

    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        normalized = normalize_domain(value)

        if normalized is None:
            return None, rule_type

        return (2, normalized), None

    if rule_type == "DOMAIN-KEYWORD":
        normalized = normalize_keyword(value)

        if normalized is None:
            return None, rule_type

        return (3, normalized), None

    return (anywhere_type, value.strip()), None


def parse_shadowrocket_domain(line: str):
    if not line or line.startswith("#") or line.startswith("//"):
        return None, None

    value = line.strip()

    # DOMAIN-SET 中以 "." 开头的项目表示域名后缀。
    # Anywhere 对 DOMAIN 和 DOMAIN-SUFFIX 均采用类型 2。
    if value.startswith("."):
        value = value[1:]

    normalized = normalize_domain(value)

    if normalized is None:
        return None, "DOMAIN-SET"

    return (2, normalized), None


def parse_line(line: str, source_format: str):
    line = line.strip()

    if source_format == "adguard":
        return parse_adguard(line)

    if source_format == "shadowrocket-domain":
        return parse_shadowrocket_domain(line)

    return parse_shadowrocket(line)


def make_header(
    name: str,
    description: str,
    source_url: str,
    source_format: str,
    rule_count: int,
    source_rule_count: int,
    skipped: dict[str, int],
    upstream_updated: str | None,
    part: int | None = None,
    total_parts: int | None = None,
):
    header = [
        f"# NAME: {name}",
        "# GENERATED-FOR: Anywhere Routing Rule Set",
        f"# DESCRIPTION: {description}",
        f"# SOURCE-FORMAT: {source_format}",
        f"# RULES: {rule_count}",
        f"# SOURCE-RULES: {source_rule_count}",
        f"# SOURCE: {source_url}",
    ]

    if upstream_updated:
        header.append(
            f"# UPSTREAM-UPDATED: {upstream_updated}"
        )

    skipped_count = sum(skipped.values())

    header.append(
        f"# SKIPPED: {skipped_count}"
    )

    if skipped:
        summary = ", ".join(
            f"{key}={value}"
            for key, value in sorted(skipped.items())
        )

        header.append(
            f"# SKIPPED-TYPES: {summary}"
        )

    if total_parts is not None and total_parts > 1:
        header.append(
            f"# PART: {part}/{total_parts}"
        )

    return header


def remove_old_outputs(destination: Path):
    destination.unlink(missing_ok=True)

    pattern = (
        f"{destination.stem}_*"
        f"{destination.suffix}"
    )

    for old_part in destination.parent.glob(pattern):
        old_part.unlink(missing_ok=True)


def write_outputs(
    destination: Path,
    name: str,
    description: str,
    source_url: str,
    source_format: str,
    rules: list[tuple[int, str]],
    source_rule_count: int,
    skipped: dict[str, int],
    upstream_updated: str | None,
    routing: int,
):
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # 删除旧的主文件和旧分片，避免规则数量变化后
    # 仓库中残留过期分片。
    remove_old_outputs(destination)

    if not rules:
        raise RuntimeError(
            f"{name}: no convertible rules found"
        )

    parts = [
        rules[index:index + MAX_RULES_PER_SET]
        for index in range(
            0,
            len(rules),
            MAX_RULES_PER_SET,
        )
    ]

    total_parts = len(parts)
    outputs = []

    for index, part_rules in enumerate(parts, start=1):

        if total_parts == 1:
            part_name = name
            part_path = destination

        else:
            part_name = f"{name}_{index:02d}"

            part_path = destination.with_name(
                f"{destination.stem}_{index:02d}"
                f"{destination.suffix}"
            )

        header = make_header(
            name=part_name,
            description=description,
            source_url=source_url,
            source_format=source_format,
            rule_count=len(part_rules),
            source_rule_count=(
                source_rule_count
                if index == 1
                else len(part_rules)
            ),
            skipped=(
                skipped
                if index == 1
                else {}
            ),
            upstream_updated=upstream_updated,
            part=(
                index
                if total_parts > 1
                else None
            ),
            total_parts=(
                total_parts
                if total_parts > 1
                else None
            ),
        )

        body = header + [
            "",
            f"name = {part_name}",
            f"routing = {routing}",
        ]

        body.extend(
            f"{rule_type}, {value}"
            for rule_type, value in part_rules
        )

        part_path.write_text(
            "\n".join(body) + "\n",
            encoding="utf-8",
        )

        outputs.append(
            (
                part_name,
                part_path,
                len(part_rules),
            )
        )

    return outputs


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--name",
        required=True,
    )

    parser.add_argument(
        "--source",
        required=True,
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    parser.add_argument(
        "--routing",
        type=int,
        default=0,
    )

    parser.add_argument(
        "--description",
        default="",
    )

    args = parser.parse_args()

    try:
        source_text = load_source(args.source)
        lines = source_text.splitlines()

        metadata = parse_metadata(lines)

        source_format = detect_format(
            args.source
        )

        rules: list[tuple[int, str]] = []
        skipped: dict[str, int] = {}

        source_rule_count = 0

        for raw in lines:
            line = raw.strip()

            if not line:
                continue

            # 统计实际规则行，不统计元数据。
            if source_format == "adguard":
                if line.startswith("!"):
                    continue
            else:
                if (
                    line.startswith("#")
                    or line.startswith("//")
                ):
                    continue

            source_rule_count += 1

            converted, skipped_type = parse_line(
                line,
                source_format,
            )

            if converted is not None:
                rules.append(converted)

            elif skipped_type:
                skipped[skipped_type] = (
                    skipped.get(
                        skipped_type,
                        0,
                    )
                    + 1
                )

        outputs = write_outputs(
            destination=Path(args.output),
            name=args.name,
            description=args.description,
            source_url=args.source,
            source_format=source_format,
            rules=rules,
            source_rule_count=source_rule_count,
            skipped=skipped,
            upstream_updated=metadata.get(
                "UPDATED"
            ),
            routing=args.routing,
        )

        print(
            f"{args.name}: "
            f"source={source_rule_count}, "
            f"converted={len(rules)}, "
            f"skipped={sum(skipped.values())}, "
            f"outputs={len(outputs)}"
        )

        if skipped:
            print(
                "Skipped types: "
                + ", ".join(
                    f"{key}={value}"
                    for key, value
                    in sorted(
                        skipped.items()
                    )
                )
            )

        return 0

    except Exception as exc:
        print(
            f"ERROR: {args.name}: {exc}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())
