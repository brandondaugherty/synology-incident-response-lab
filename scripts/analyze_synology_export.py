#!/usr/bin/env python3
"""Safely summarize Synology DSM HTML exports without emitting raw indicators."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path


BLOCK_PATTERN = re.compile(
    r"^Host \[([0-9a-fA-F:.]+)\] was blocked via \[(SSH|DSM)\]\.$"
)


class SynologyTableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.rows: list[list[str]] = []
        self._row: list[str] = []
        self._cell: list[str] = []
        self._in_cell = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "td":
            self._in_cell = True
            self._cell = []

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            self._cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "td" and self._in_cell:
            self._row.append("".join(self._cell).strip())
            self._in_cell = False
        elif tag == "tr":
            if len(self._row) == 5:
                self.rows.append(self._row)
            self._row = []


def parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None


def analyze(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    parser = SynologyTableParser()
    parser.feed(raw.decode("utf-8", errors="replace"))

    timestamps: list[datetime] = []
    block_events: list[tuple[datetime, str, str, str]] = []

    for level, _log, time_value, user, event in parser.rows:
        timestamp = parse_timestamp(time_value)
        if timestamp is None:
            continue
        timestamps.append(timestamp)

        match = BLOCK_PATTERN.fullmatch(event)
        if not match or level != "Warning":
            continue

        try:
            source = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        block_events.append((timestamp, str(source), match.group(2), user))

    if not timestamps:
        raise ValueError("No Synology table records with valid timestamps were found")

    monthly = Counter(timestamp.strftime("%Y-%m") for timestamp, *_ in block_events)
    daily = Counter(timestamp.strftime("%Y-%m-%d") for timestamp, *_ in block_events)
    networks = Counter(
        str(ipaddress.ip_network(f"{source}/24", strict=False))
        for _, source, _, _ in block_events
    )

    top_networks = [
        {"network_token": f"NET-{index:02d}", "events": count}
        for index, (_, count) in enumerate(networks.most_common(10), start=1)
    ]

    return {
        "evidence": {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
            "parsed_rows": len(timestamps),
        },
        "window": {
            "first": min(timestamps).isoformat(sep=" "),
            "last": max(timestamps).isoformat(sep=" "),
        },
        "auto_blocks": {
            "total": len(block_events),
            "ssh": sum(service == "SSH" for _, _, service, _ in block_events),
            "dsm": sum(service == "DSM" for _, _, service, _ in block_events),
            "unique_source_ips": len({source for _, source, _, _ in block_events}),
            "unique_24_networks": len(networks),
            "named_account_labels": sum(user != "SYSTEM" for *_, user in block_events),
            "distinct_named_labels": len(
                {user for *_, user in block_events if user != "SYSTEM"}
            ),
        },
        "peak_day": (
            {"date": daily.most_common(1)[0][0], "events": daily.most_common(1)[0][1]}
            if daily
            else None
        ),
        "monthly_counts": dict(sorted(monthly.items())),
        "top_network_clusters": top_networks,
        "privacy": {
            "raw_source_ips_emitted": False,
            "raw_usernames_emitted": False,
            "raw_event_text_emitted": False,
        },
    }


def main() -> None:
    argument_parser = argparse.ArgumentParser(
        description="Create a sanitized aggregate summary from a Synology HTML log export."
    )
    argument_parser.add_argument("export", type=Path, help="Path to a private HTML export")
    args = argument_parser.parse_args()
    print(json.dumps(analyze(args.export), indent=2))


if __name__ == "__main__":
    main()
