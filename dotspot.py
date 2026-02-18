#!/usr/bin/env python3

import argparse
from ui.banner import show_banner
from ui.prompts import run_interactive_prompts
from core.scanner import run_scan
from checks.ai_overview import analyze_scan_report


def main():
    show_banner()

    parser = argparse.ArgumentParser(
        prog="dotspot",
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a target URL")
    scan_parser.add_argument("url", help="Target URL")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze scan results with AI")
    analyze_parser.add_argument("json_file", help="Path to scan JSON file")
    analyze_parser.add_argument("--api-key", help="Groq API key (or set GROQ_API_KEY env var)")

    subparsers.add_parser("help", help="Show help")

    args = parser.parse_args()

    if args.command == "scan":
        result = run_interactive_prompts()

        if result["mode"] == "vulnerabilities":
            run_scan(args.url, vuln_filter=result["vuln_filter"])
        elif result["mode"] == "flag":
            run_scan(args.url, vuln_filter=None)
    elif args.command == "analyze":
        analyze_scan_report(args.json_file, args.api_key if hasattr(args, 'api_key') else None)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
