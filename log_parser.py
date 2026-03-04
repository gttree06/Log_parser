#!/usr/bin/env python3
"""
log_parser.py — Parse and format JSON and plain-text log files into a clean, uniform view.

Usage:
    python log_parser.py <logfile> [options]

Options:
    --level LEVEL       Filter by log level (e.g. ERROR, WARN, INFO, DEBUG)
    --since DATETIME    Show logs after this time (e.g. "2024-01-15 10:00:00")
    --until DATETIME    Show logs before this time (e.g. "2024-01-15 18:00:00")
    --no-color          Disable colored output
    --summary           Show only the summary, not individual log lines
    --output FILE       Write formatted output to a file instead of stdout

Examples:
    python log_parser.py app.log
    python log_parser.py app.json --level ERROR
    python log_parser.py app.log --since "2024-01-15 10:00:00" --level WARN
    python log_parser.py app.log --output clean.txt --no-color
"""

import json
import re
import sys
import argparse
from datetime import datetime
from pathlib import Path
from collections import Counter


# ── ANSI color codes ──────────────────────────────────────────────────────────

COLORS = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
    "red":     "\033[91m",
    "yellow":  "\033[93m",
    "green":   "\033[92m",
    "blue":    "\033[94m",
    "cyan":    "\033[96m",
    "magenta": "\033[95m",
    "white":   "\033[97m",
    "gray":    "\033[90m",
}

LEVEL_COLORS = {
    "ERROR":    "red",
    "CRITICAL": "red",
    "FATAL":    "red",
    "WARN":     "yellow",
    "WARNING":  "yellow",
    "INFO":     "green",
    "DEBUG":    "blue",
    "TRACE":    "cyan",
}

USE_COLOR = True


def c(text, *color_names):
    """Wrap text in ANSI color codes (no-op if color disabled)."""
    if not USE_COLOR:
        return text
    codes = "".join(COLORS.get(name, "") for name in color_names)
    return f"{codes}{text}{COLORS['reset']}"


# ── Log entry dataclass ───────────────────────────────────────────────────────

class LogEntry:
    def __init__(self, timestamp=None, level=None, message=None, source=None, extra=None, raw=None):
        self.timestamp: datetime | None = timestamp
        self.level: str = (level or "INFO").upper()
        self.message: str = message or ""
        self.source: str | None = source
        self.extra: dict = extra or {}
        self.raw: str = raw or ""

    def matches_level(self, filter_level: str) -> bool:
        order = ["TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "FATAL"]
        try:
            entry_idx = order.index(self.level)
            filter_idx = order.index(filter_level.upper())
            return entry_idx >= filter_idx
        except ValueError:
            return self.level == filter_level.upper()

    def matches_time(self, since=None, until=None) -> bool:
        if self.timestamp is None:
            return True  # can't filter what we don't have
        if since and self.timestamp < since:
            return False
        if until and self.timestamp > until:
            return False
        return True


# ── Parsers ───────────────────────────────────────────────────────────────────

# Common timestamp patterns
TS_PATTERNS = [
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)",
    r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})",  # Apache style: 10/Jan/2024:13:00:00
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",   # Syslog style: Jan 15 13:00:00
]

LEVEL_PATTERN = re.compile(
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRITICAL|FATAL|SEVERE)\b",
    re.IGNORECASE
)

TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",
    "%b  %d %H:%M:%S",
]


def parse_timestamp(ts_str: str) -> datetime | None:
    ts_str = ts_str.strip().rstrip("Z")
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def parse_json_log(content: str) -> list[LogEntry]:
    """Parse a file where each line (or the whole file) is JSON."""
    entries = []
    lines = content.strip().splitlines()

    # Try whole file as a JSON array first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for item in data:
                entries.append(_json_obj_to_entry(item))
            return entries
    except json.JSONDecodeError:
        pass

    # Fall back to one JSON object per line (NDJSON)
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            entries.append(_json_obj_to_entry(obj))
        except json.JSONDecodeError:
            entries.append(LogEntry(message=line, level="INFO", raw=line))

    return entries


def _json_obj_to_entry(obj: dict) -> LogEntry:
    """Normalize a JSON log object to a LogEntry, handling various key conventions."""
    if not isinstance(obj, dict):
        return LogEntry(message=str(obj), raw=str(obj))

    # Timestamp — try common key names
    ts = None
    for key in ("timestamp", "time", "ts", "@timestamp", "datetime", "date", "created_at"):
        if key in obj:
            ts = parse_timestamp(str(obj[key]))
            break

    # Level
    level = "INFO"
    for key in ("level", "severity", "log_level", "lvl", "type", "status"):
        if key in obj:
            level = str(obj[key]).upper()
            break

    # Message
    message = ""
    for key in ("message", "msg", "text", "body", "log", "event", "description", "detail"):
        if key in obj:
            message = str(obj[key])
            break
    if not message:
        message = str(obj)

    # Source / logger name
    source = None
    for key in ("logger", "source", "service", "module", "name", "component", "app"):
        if key in obj:
            source = str(obj[key])
            break

    # Everything else goes into extra
    known_keys = {"timestamp", "time", "ts", "@timestamp", "datetime", "date", "created_at",
                  "level", "severity", "log_level", "lvl", "type",
                  "message", "msg", "text", "body", "log", "event", "description", "detail",
                  "logger", "source", "service", "module", "name", "component", "app", "status"}
    extra = {k: v for k, v in obj.items() if k not in known_keys}

    return LogEntry(timestamp=ts, level=level, message=message, source=source, extra=extra, raw=json.dumps(obj))


def parse_text_log(content: str) -> list[LogEntry]:
    """Parse a plain-text log file using regex heuristics."""
    entries = []
    for line in content.splitlines():
        raw = line
        line = line.strip()
        if not line:
            continue

        # Extract timestamp
        ts = None
        ts_str = None
        for pattern in TS_PATTERNS:
            m = re.search(pattern, line)
            if m:
                ts_str = m.group(1)
                ts = parse_timestamp(ts_str)
                if ts:
                    break

        # Extract level
        level = "INFO"
        level_match = LEVEL_PATTERN.search(line)
        if level_match:
            level = level_match.group(1).upper()

        # Remove timestamp from working copy
        working = line
        if ts_str:
            working = working.replace(ts_str, "", 1).strip()

        # Try to extract bracketed tokens: [LEVEL] [Source] Message
        bracketed = re.findall(r"\[([^\]]+)\]", working)
        source = None
        for token in bracketed:
            token = token.strip()
            if LEVEL_PATTERN.fullmatch(token):
                continue  # that's the level badge, skip
            if not re.match(r"^\d+$", token):
                source = token
                break

        # Extract message: remove all leading [token] groups then clean up
        message = re.sub(r"^\s*(\[[^\]]*\]\s*)+", "", working).strip()
        # Also strip leading separators
        message = re.sub(r"^[\s|:,\-–]+", "", message).strip()
        if not message:
            message = working  # fallback

        entries.append(LogEntry(timestamp=ts, level=level, message=message, source=source, raw=raw))

    return entries


def parse_file(path: Path) -> list[LogEntry]:
    content = path.read_text(encoding="utf-8", errors="replace")
    suffix = path.suffix.lower()

    if suffix == ".json":
        return parse_json_log(content)
    elif suffix in (".log", ".txt", ""):
        # Peek: if first non-empty line looks like JSON, treat as NDJSON
        first = next((l.strip() for l in content.splitlines() if l.strip()), "")
        if first.startswith("{"):
            return parse_json_log(content)
        return parse_text_log(content)
    else:
        # Best effort for unknown extensions
        first = next((l.strip() for l in content.splitlines() if l.strip()), "")
        if first.startswith("{") or first.startswith("["):
            return parse_json_log(content)
        return parse_text_log(content)


# ── Formatter ─────────────────────────────────────────────────────────────────

COL_WIDTHS = {"timestamp": 19, "level": 8, "source": 20}
SEPARATOR = c("─" * 100, "dim")


def format_level_badge(level: str) -> str:
    color = LEVEL_COLORS.get(level, "white")
    padded = level[:8].center(8)
    return c(f"[{padded}]", color, "bold")


def format_timestamp(ts: datetime | None) -> str:
    if ts is None:
        return c("─" * 19, "dim")
    formatted = ts.strftime("%Y-%m-%d %H:%M:%S")
    return c(formatted, "cyan")


def format_source(source: str | None) -> str:
    if not source:
        return c("─" * COL_WIDTHS["source"], "dim")
    trimmed = source[:COL_WIDTHS["source"]].ljust(COL_WIDTHS["source"])
    return c(trimmed, "magenta")


def format_message(message: str, level: str) -> str:
    color = LEVEL_COLORS.get(level, "white")
    if level in ("ERROR", "CRITICAL", "FATAL"):
        return c(message, color, "bold")
    if level in ("WARN", "WARNING"):
        return c(message, color)
    return message


def format_entry(entry: LogEntry, show_extra: bool = True) -> str:
    ts = format_timestamp(entry.timestamp)
    badge = format_level_badge(entry.level)
    src = format_source(entry.source)
    msg = format_message(entry.message, entry.level)

    line = f"  {ts}  {badge}  {src}  {msg}"

    if show_extra and entry.extra:
        extras = []
        for k, v in entry.extra.items():
            val = json.dumps(v) if not isinstance(v, str) else v
            extras.append(c(f"{k}", "gray") + c("=", "dim") + c(val, "dim"))
        line += "\n" + " " * 56 + "  " + "  ".join(extras)

    return line


def print_header(path: Path, total: int, filtered: int):
    title = c(f" LOG PARSER ", "bold", "white")
    file_info = c(str(path), "cyan")
    count_info = c(f"{filtered}", "green", "bold") + c(f" / {total} entries", "gray")

    print()
    print(c("╔" + "═" * 98 + "╗", "dim"))
    print(c("║", "dim") + f"  {title}  {file_info}  →  {count_info}" + c("  ║", "dim"))
    print(c("╚" + "═" * 98 + "╝", "dim"))
    print()

    header = (
        f"  {'TIMESTAMP':<19}  {'LEVEL':^10}  {'SOURCE':<20}  MESSAGE"
    )
    print(c(header, "bold", "white"))
    print(SEPARATOR)


def print_summary(entries: list[LogEntry], filtered: list[LogEntry]):
    level_counts = Counter(e.level for e in filtered)
    print()
    print(SEPARATOR)
    print()
    print(c("  SUMMARY", "bold", "white"))
    print()

    total_filtered = len(filtered)
    total_all = len(entries)
    print(f"  Entries shown : {c(str(total_filtered), 'green', 'bold')}  {c(f'(of {total_all} total)', 'gray')}")

    if level_counts:
        print(f"  By level      :", end="")
        parts = []
        for level in ["FATAL", "CRITICAL", "ERROR", "WARN", "WARNING", "INFO", "DEBUG", "TRACE"]:
            if level in level_counts:
                color = LEVEL_COLORS.get(level, "white")
                parts.append(c(f"{level}: {level_counts[level]}", color))
        print("  " + "  |  ".join(parts))

    ts_list = [e.timestamp for e in filtered if e.timestamp]
    if ts_list:
        earliest = min(ts_list).strftime("%Y-%m-%d %H:%M:%S")
        latest = max(ts_list).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  Time range    :  {c(earliest, 'cyan')}  →  {c(latest, 'cyan')}")

    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global USE_COLOR

    parser = argparse.ArgumentParser(
        description="Parse and format JSON and plain-text log files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("file", help="Path to the log file (.json, .log, .txt)")
    parser.add_argument("--level", help="Minimum log level to show (DEBUG/INFO/WARN/ERROR)")
    parser.add_argument("--since", help='Show entries after this time, e.g. "2024-01-15 10:00:00"')
    parser.add_argument("--until", help='Show entries before this time, e.g. "2024-01-15 18:00:00"')
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--summary", action="store_true", help="Show only the summary")
    parser.add_argument("--output", help="Write formatted output to this file (implies --no-color)")
    args = parser.parse_args()

    # Setup color
    if args.no_color or args.output or not sys.stdout.isatty():
        USE_COLOR = False

    # Parse time filters
    since = parse_timestamp(args.since) if args.since else None
    until = parse_timestamp(args.until) if args.until else None
    if args.since and since is None:
        print(f"Warning: could not parse --since value: {args.since!r}", file=sys.stderr)
    if args.until and until is None:
        print(f"Warning: could not parse --until value: {args.until!r}", file=sys.stderr)

    # Load file
    path = Path(args.file)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    all_entries = parse_file(path)

    # Apply filters
    filtered = all_entries
    if args.level:
        filtered = [e for e in filtered if e.matches_level(args.level)]
    filtered = [e for e in filtered if e.matches_time(since, until)]

    # Output destination
    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout

    try:
        # Redirect print to file if needed
        if args.output:
            import builtins
            _orig_print = builtins.print
            def _file_print(*a, **kw):
                kw.setdefault("file", out)
                _orig_print(*a, **kw)
            builtins.print = _file_print

        print_header(path, len(all_entries), len(filtered))

        if not args.summary:
            for entry in filtered:
                print(format_entry(entry))
            if not filtered:
                print(c("  (no entries match the current filters)", "dim"))

        print_summary(all_entries, filtered)

    finally:
        if args.output:
            import builtins
            builtins.print = _orig_print
            out.close()
            print(f"Output written to: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()