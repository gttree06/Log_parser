#!/usr/bin/env python3
"""
log_parser.py — Parse and format mixed JSON/text log files.

Usage:
    python log_parser.py <logfile>
    python log_parser.py <logfile> --level WARN
    python log_parser.py <logfile> --since "2024-01-15 10:00:00"
"""

import json
import re
import sys
import argparse
from datetime import datetime
from pathlib import Path
from collections import Counter


# ── Colors ────────────────────────────────────────────────────────────────────

COLORS = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m",
    "blue": "\033[94m", "cyan": "\033[96m", "magenta": "\033[95m",
    "white": "\033[97m", "gray": "\033[90m",
}

LEVEL_COLORS = {
    "ERROR": "red", "CRITICAL": "red", "FATAL": "red",
    "WARN": "yellow", "WARNING": "yellow",
    "INFO": "green", "DEBUG": "blue", "TRACE": "cyan",
}

USE_COLOR = True

def c(text, *names):
    if not USE_COLOR:
        return text
    return "".join(COLORS.get(n, "") for n in names) + text + COLORS["reset"]


# ── Parsing ───────────────────────────────────────────────────────────────────

TS_PATTERNS = [
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)",
    r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})",
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
]

TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S", "%b %d %H:%M:%S", "%b  %d %H:%M:%S",
]

LEVEL_RE = re.compile(
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRITICAL|FATAL|SEVERE)\b",
    re.IGNORECASE
)


def parse_timestamp(s):
    s = s.strip().rstrip("Z")
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def parse_line(raw):
    """Identify and parse a single log line — JSON or plain text — into a dict."""
    line = raw.strip()

    # ── JSON ──
    if line.startswith("{"):
        try:
            obj = json.loads(line)

            ts = next((parse_timestamp(str(obj[k])) for k in
                       ("timestamp","time","ts","@timestamp","datetime","date","created_at")
                       if k in obj), None)

            level = next((str(obj[k]).upper() for k in
                          ("level","severity","log_level","lvl") if k in obj), "INFO")

            message = next((str(obj[k]) for k in
                            ("message","msg","text","body","log","event") if k in obj), str(obj))

            source = next((str(obj[k]) for k in
                           ("logger","source","service","module","name","component","app")
                           if k in obj), None)

            known = {"timestamp","time","ts","@timestamp","datetime","date","created_at",
                     "level","severity","log_level","lvl","message","msg","text","body",
                     "log","event","logger","source","service","module","name","component","app"}
            extra = {k: v for k, v in obj.items() if k not in known}

            return dict(ts=ts, level=level, message=message, source=source, extra=extra)
        except json.JSONDecodeError:
            pass  # fall through to text parsing

    # ── Plain text ──
    ts, ts_str = None, None
    for pattern in TS_PATTERNS:
        m = re.search(pattern, line)
        if m:
            ts = parse_timestamp(m.group(1))
            if ts:
                ts_str = m.group(1)
                break

    level_m = LEVEL_RE.search(line)
    level = level_m.group(1).upper() if level_m else "INFO"

    working = line
    if ts_str:
        working = working.replace(ts_str, "", 1).strip()

    source = None
    for token in re.findall(r"\[([^\]]+)\]", working):
        token = token.strip()
        if not LEVEL_RE.fullmatch(token) and not re.match(r"^\d+$", token):
            source = token
            break

    message = re.sub(r"^\s*(\[[^\]]*\]\s*)+", "", working).strip()
    message = re.sub(r"^[\s|:,\-–]+", "", message).strip() or working

    return dict(ts=ts, level=level, message=message, source=source, extra={})


def parse_file(path):
    entries = []
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.strip():
            entries.append(parse_line(raw))
    return entries


# ── Filtering ─────────────────────────────────────────────────────────────────

LEVEL_ORDER = ["TRACE","DEBUG","INFO","NOTICE","WARN","WARNING","ERROR","CRITICAL","FATAL","SEVERE"]

def above_level(entry_level, min_level):
    try:
        return LEVEL_ORDER.index(entry_level) >= LEVEL_ORDER.index(min_level.upper())
    except ValueError:
        return entry_level == min_level.upper()

def in_time_range(ts, since, until):
    if ts is None:
        return True
    if since and ts < since:
        return False
    if until and ts > until:
        return False
    return True


# ── Formatting ────────────────────────────────────────────────────────────────

SEP = c("─" * 100, "dim")

def format_entry(e):
    ts  = c(e["ts"].strftime("%Y-%m-%d %H:%M:%S"), "cyan") if e["ts"] else c("─" * 19, "dim")
    lvl = e["level"][:8].center(8)
    badge = c(f"[{lvl}]", LEVEL_COLORS.get(e["level"], "white"), "bold")
    src = c((e["source"] or "")[:20].ljust(20), "magenta") if e["source"] else c("─" * 20, "dim")
    msg = e["message"]
    if e["level"] in ("ERROR","CRITICAL","FATAL"):
        msg = c(msg, "red", "bold")
    elif e["level"] in ("WARN","WARNING"):
        msg = c(msg, "yellow")

    line = f"  {ts}  {badge}  {src}  {msg}"

    if e["extra"]:
        pairs = "  ".join(
            c(k, "gray") + c("=", "dim") + c(json.dumps(v) if not isinstance(v, str) else v, "dim")
            for k, v in e["extra"].items()
        )
        line += "\n" + " " * 58 + pairs

    return line


def print_header(path, total, shown):
    print()
    print(c("╔" + "═" * 98 + "╗", "dim"))
    print(c("║", "dim") +
          f"  {c(' LOG PARSER ', 'bold', 'white')}  {c(str(path), 'cyan')}  →  "
          f"{c(str(shown), 'green', 'bold')}{c(f' / {total} entries', 'gray')}"
          + c("  ║", "dim"))
    print(c("╚" + "═" * 98 + "╝", "dim"))
    print()
    print(c(f"  {'TIMESTAMP':<19}  {'LEVEL':^10}  {'SOURCE':<20}  MESSAGE", "bold", "white"))
    print(SEP)


def print_summary(all_entries, filtered):
    counts = Counter(e["level"] for e in filtered)
    ts_list = [e["ts"] for e in filtered if e["ts"]]
    print()
    print(SEP)
    print()
    print(c("  SUMMARY", "bold", "white"))
    print()
    print(f"  Entries shown : {c(str(len(filtered)), 'green', 'bold')}  {c(f'(of {len(all_entries)} total)', 'gray')}")
    if counts:
        parts = [c(f"{lvl}: {counts[lvl]}", LEVEL_COLORS.get(lvl, "white"))
                 for lvl in LEVEL_ORDER if lvl in counts]
        print(f"  By level      :  {'  |  '.join(parts)}")
    if ts_list:
        print(f"  Time range    :  {c(min(ts_list).strftime('%Y-%m-%d %H:%M:%S'), 'cyan')}"
              f"  →  {c(max(ts_list).strftime('%Y-%m-%d %H:%M:%S'), 'cyan')}")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global USE_COLOR

    ap = argparse.ArgumentParser(description="Parse and format mixed JSON/text log files.")
    ap.add_argument("file", help="Path to the log file")
    ap.add_argument("--level", help="Minimum log level (DEBUG/INFO/WARN/ERROR)")
    ap.add_argument("--since", help='Show entries after this time e.g. "2024-01-15 10:00:00"')
    ap.add_argument("--until", help='Show entries before this time e.g. "2024-01-15 18:00:00"')
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--summary", action="store_true", help="Show only the summary")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        USE_COLOR = False

    path = Path(args.file)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    since = parse_timestamp(args.since) if args.since else None
    until = parse_timestamp(args.until) if args.until else None

    all_entries = parse_file(path)

    filtered = [
        e for e in all_entries
        if (not args.level or above_level(e["level"], args.level))
        and in_time_range(e["ts"], since, until)
    ]

    print_header(path, len(all_entries), len(filtered))

    if not args.summary:
        for e in filtered:
            print(format_entry(e))
        if not filtered:
            print(c("  (no entries match the current filters)", "dim"))

    print_summary(all_entries, filtered)


if __name__ == "__main__":
    main()