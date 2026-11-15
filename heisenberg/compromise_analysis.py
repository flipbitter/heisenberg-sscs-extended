# heisenberg/compromise_analysis.py

import csv
import os
import sys
import argparse

from .config import Settings

_settings = Settings()
DEFAULT_OUTPUT = getattr(_settings, "output_csv", "analyze_matches.csv")

from .sbom_utils import (
    write_repos_file,
    load_repos_from_file,
    run_github_sbom_script,
    iter_selected_sboms,
    cleanup_sbom_dir,
)


def _read_list_file(path):
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.append(s)
    return out


def _split_csv_list(s):
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def _normalize(s, case_sensitive):
    s = (s or "").strip()
    return s if case_sensitive else s.lower()


def _dedupe_rows_preserve_order(rows):
    seen = set()
    out = []
    for r in rows:
        key = tuple(r)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _load_header_and_rows(sbom_csv, match_column="package"):
    if not os.path.exists(sbom_csv):
        raise FileNotFoundError(f"SBOM not found: {sbom_csv}")
    with open(sbom_csv, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        if match_column not in header:
            raise ValueError(f"SBOM CSV is missing required '{match_column}' column.")
        rows = list(reader)
    return header, rows


def run_analyze(sbom_csv, targets, case_sensitive, match_column="package"):
    print(f"[INFO] Loading SBOM: {sbom_csv}", file=sys.stderr)
    header, rows = _load_header_and_rows(sbom_csv, match_column=match_column)

    print(
        f"[INFO] Matching {len(targets)} targeta against column '{match_column}'",
        file=sys.stderr,
    )
    wanted = {_normalize(x, case_sensitive) for x in targets if x.strip()}

    matches = []
    for row in rows:
        pkg = row.get(match_column, "")
        if _normalize(pkg, case_sensitive) in wanted:
            matches.append([row.get(col, "") for col in header])

    matches = _dedupe_rows_preserve_order(matches)
    print(f"[INFO] Found {len(matches)} matching row(s)", file=sys.stderr)
    return header, matches


def add_arguments(parser):
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-sbom", "--sbom", help="Path to SBOM CSV to scan.")
    target.add_argument(
        "-r", "--repos", help="Comma-separated repo list, e.g. 'repo1,repo2'."
    )
    target.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Use repos from repos.txt (requires --org/--repos-file).",
    )

    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "-pkg", "--pkg", help="Comma-separated package names, e.g. 'pkg1,pkg2'."
    )
    g.add_argument("-file", "--file", help="Text file of package names (one per line).")

    parser.add_argument(
        "-o",
        "--output",
        "--out",
        dest="output",
        default=DEFAULT_OUTPUT,
        help=f"Output CSV path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Match package names case-sensitively (default: case-insensitive).",
    )
    parser.add_argument(
        "--column",
        default="package",
        help="CSV column to match against (default: 'package'). Use 'full_action' for actions investigations.",
    )
    parser.add_argument(
        "--org",
        default=_settings.org,
        help="GitHub org name (used when -r/--repos or -a/--all is provided).",
    )
    parser.add_argument(
        "--repos-file",
        default=_settings.repos_file_name,
        help="Path to repos.txt (used with -a/--all).",
    )
    parser.add_argument(
        "--sbom-dir",
        default=_settings.sbom_dir,
        help="Directory to write/read SBOM CSVs when using repo mode.",
    )


def parse_cli():
    p = argparse.ArgumentParser(
        description="Analyze SBOM CSV for presence of specific package names."
    )
    add_arguments(p)
    return p.parse_args()


def _analyze_single(
    sbom_csv,
    targets,
    case_sensitive,
    writer,
    wrote_header: list[bool],
    repo_name: str | None = None,
):
    header, rows = run_analyze(sbom_csv, targets, case_sensitive)
    if repo_name:
        if not wrote_header[0]:
            writer.writerow(["repo_name"] + header)
            wrote_header[0] = True
        for r in rows:
            writer.writerow([repo_name] + r)
    else:
        if not wrote_header[0]:
            writer.writerow(header)
            wrote_header[0] = True
        writer.writerows(rows)


def investigate(sources, targets, case_sensitive=False, match_column="package"):
    """Yield coverage + real rows from the existing matcher once per source."""
    for source in sources:
        if source.get("status") == "error":
            yield {"coverage": source, "rows": [], "header": []}
            continue
        try:
            header, rows = run_analyze(
                source["path"], targets, case_sensitive, match_column
            )
            yield {
                "coverage": {**source, "status": "searched", "matches": len(rows)},
                "header": header,
                "rows": rows,
            }
        except Exception as e:
            yield {
                "coverage": {**source, "status": "error", "error": type(e).__name__},
                "header": [],
                "rows": [],
            }


def _write_investigation(args, sources, targets):
    stream = (
        sys.stdout
        if args.output == "-"
        else open(args.output, "w", encoding="utf-8", newline="")
    )
    failed, wrote = False, False
    try:
        writer = csv.writer(stream)
        repo_mode = not args.sbom
        for result in investigate(sources, targets, args.case_sensitive, args.column):
            if result["coverage"]["status"] == "error":
                failed = True
                print(f"[ERROR] {result['coverage']}", file=sys.stderr)
                continue
            if not wrote:
                writer.writerow((["repo_name"] if repo_mode else []) + result["header"])
                wrote = True
            for row in result["rows"]:
                writer.writerow(
                    ([result["coverage"]["repo"]] if repo_mode else []) + row
                )
    finally:
        if stream is not sys.stdout:
            stream.close()
    return 1 if failed else 0


def main(args=None):
    import tempfile
    from .github_sbom import generate_sboms

    args = args or parse_cli()
    targets = _split_csv_list(args.pkg) if args.pkg else _read_list_file(args.file)
    if not targets:
        print("[ERROR] No package names provided.", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="heis-analyze-") as work:
        if args.sbom:
            sources = [
                {"repo": None, "path": args.sbom, "inventory_completeness": "unknown"}
            ]
        else:
            repos = (
                load_repos_from_file(args.repos_file)
                if args.all
                else _split_csv_list(args.repos)
            )
            if not repos:
                return 2
            # Use a fresh owned directory. Never delete an operator's --sbom-dir.
            if args.sbom_dir:
                os.makedirs(args.sbom_dir, exist_ok=True)
            with tempfile.TemporaryDirectory(
                prefix="scan-", dir=args.sbom_dir or work
            ) as scan:
                sources = generate_sboms(args.org, repos, scan)
                return _write_investigation(args, sources, targets)
        return _write_investigation(args, sources, targets)


def cli(args=None):
    return main(args)


if __name__ == "__main__":
    sys.exit(main())
