"""Command line for `python3 -m phishcheck`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from phishcheck import __version__
from phishcheck.engine import analyse
from phishcheck.ioc import render_ioc_csv, render_ioc_json
from phishcheck.report import render_json, render_markdown


def _samples_dir(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    cwd = Path.cwd() / "samples"
    if any(cwd.glob("*.eml")):
        return cwd
    return Path(__file__).resolve().parents[1] / "samples"


def _write(path: str, text: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")
    print(f"wrote {destination}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishcheck",
        description="Offline heuristic phishing analyser for .eml files.",
    )
    parser.add_argument("--version", action="version", version=f"phishcheck {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    analyse_parser = sub.add_parser("analyse", help="score one .eml file")
    analyse_parser.add_argument("eml", help="path to a .eml file")
    analyse_parser.add_argument("--json", action="store_true", help="print the full analysis as JSON")
    analyse_parser.add_argument("--report", metavar="out.md", help="write a markdown report")
    analyse_parser.add_argument("--ioc-json", metavar="path", help="write defanged indicators as JSON")
    analyse_parser.add_argument("--ioc-csv", metavar="path", help="write defanged indicators as CSV")
    analyse_parser.add_argument(
        "--dns",
        action="store_true",
        help="fetch published SPF and DMARC TXT records (off by default; does not change the score)",
    )
    analyse_parser.add_argument(
        "--dns-server",
        metavar="IP",
        help="resolver for --dns (default: first IPv4 nameserver in resolv.conf, else 1.1.1.1)",
    )
    analyse_parser.add_argument(
        "--brands",
        metavar="file.json",
        help="JSON brand list to add to the built-in list (or replace it; see README)",
    )

    demo = sub.add_parser("demo", help="score the synthetic samples shipped with the repo")
    demo.add_argument("--samples", metavar="dir", help="directory of .eml files (default: ./samples)")
    return parser


def _analyse_command(args: argparse.Namespace) -> int:
    path = Path(args.eml)
    if not path.is_file():
        print(f"file not found: {path}", file=sys.stderr)
        return 2
    try:
        result = analyse(
            path,
            dns=args.dns,
            brands_path=args.brands,
            dns_server=args.dns_server,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"could not read {path}: {exc}", file=sys.stderr)
        return 2

    markdown = render_markdown(result)
    if args.report:
        _write(args.report, markdown)
    if args.ioc_json:
        _write(args.ioc_json, render_ioc_json(result))
    if args.ioc_csv:
        _write(args.ioc_csv, render_ioc_csv(result))
    if args.json:
        sys.stdout.write(render_json(result))
    else:
        sys.stdout.write(markdown)
    return 0


def _demo_command(args: argparse.Namespace) -> int:
    directory = _samples_dir(args.samples)
    files = sorted(directory.glob("*.eml"))
    if not files:
        print(f"no .eml files in {directory}", file=sys.stderr)
        return 2
    print("phishcheck demo — synthetic samples only. Scores are a heuristic checklist.")
    print(f"{'Sample':<44} {'Score':>5}  Verdict")
    failed = False
    for file_path in files:
        try:
            result = analyse(file_path)
        except (OSError, ValueError) as exc:
            failed = True
            print(f"{file_path.name:<44} {'ERR':>5}  {exc}")
            continue
        print(f"{file_path.name:<44} {result.score:>5}  {result.verdict}")
    print("Likely-safe samples should sit under 25. The phishing samples should sit at 60 or above.")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyse":
        return _analyse_command(args)
    if args.command == "demo":
        return _demo_command(args)
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
