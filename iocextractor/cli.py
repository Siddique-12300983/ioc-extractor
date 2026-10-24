"""Command-line interface for ioc-extractor."""

from __future__ import annotations

import argparse
import sys

from . import __version__, exporter
from .extract import extract


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ioc-extractor",
        description="Extract indicators of compromise (IPs, domains, URLs, emails, hashes, CVEs) from text.",
    )
    p.add_argument("input", nargs="?", default="-",
                   help="input file, or - for stdin (default)")
    p.add_argument("-f", "--format", choices=("table", "json", "csv"), default="table")
    p.add_argument("-o", "--output", help="write to a file instead of stdout")
    p.add_argument("--filter-private", action="store_true",
                   help="drop private, loopback and reserved IP addresses")
    p.add_argument("--no-refang", action="store_true",
                   help="do not undo defanged notation before matching")
    p.add_argument("--defang", action="store_true",
                   help="defang the indicators in the output (safe to paste)")
    p.add_argument("--version", action="version", version=f"ioc-extractor {__version__}")
    return p


def run(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.input == "-":
        text = sys.stdin.read()
    else:
        try:
            with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print(f"error: cannot read {args.input}: {exc}", file=sys.stderr)
            return 2

    iocs = extract(text, refang=not args.no_refang, filter_private=args.filter_private)

    if args.format == "json":
        out = exporter.to_json(iocs, defang=args.defang)
    elif args.format == "csv":
        out = exporter.to_csv(iocs, defang=args.defang)
    else:
        out = exporter.to_table(iocs, defang=args.defang)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(out)

    total = sum(len(v) for v in iocs.values())
    return 0 if total else 1


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
