# heisenberg/heisenberg_depsdev.py

import argparse
import urllib.parse
import sys
import math
from datetime import datetime, timezone

from .npm_postinstall import check_npm_postinstall
from .cargo_build_script import check_cargo_build_script
from . import safe_http as requests

BASE_URL = "https://api.deps.dev/v3"
HTTP_TIMEOUT = 15  # seconds; safe_http also enforces its own per-request deadline
SUPPORTED_MANAGERS = ("pypi", "npm", "go", "cargo")


def _q(value):
    """URL-encode one path segment. '/', '..' and '?' can no longer reshape the URL."""
    return urllib.parse.quote(value, safe="")


def _log(msg):
    """Diagnostics go to stderr. stdout carries only the report that `bulk` parses."""
    print(msg, file=sys.stderr)


def parse_args():
    parser = argparse.ArgumentParser(description="Check package info using deps.dev")
    add_arguments(parser)
    return parser.parse_args()


def add_arguments(parser):
    parser.add_argument(
        "mode",
        nargs="?",
        default="main_package",
        choices=["main_package"],
        help="Only 'main_package' is supported.",
    )
    parser.add_argument(
        "-mgmt",
        "--mgmt",
        required=True,
        help="Package management system (e.g., pypi, npm, go, cargo)",
    )
    parser.add_argument("-pkg", "--pkg", required=True, help="Package name")
    parser.add_argument("-v", "--version", required=True, help="Package version")


def fetch_npm_deprecated(package_manager, package_name, package_version):
    """Checks if npm package waas potentially deprecated."""
    if package_manager != "npm":
        return None
    npm_url = f"https://registry.npmjs.org/{_q(package_name)}/{_q(package_version)}"
    npm_resp = requests.get(npm_url, timeout=HTTP_TIMEOUT)
    if npm_resp.status_code == 200:
        npm_data = npm_resp.json()
        return npm_data.get("deprecated", None)
    else:
        _log(f"Warning: npm registry request failed with status {npm_resp.status_code}")
        return None


def fetch_pypi_deprecated(package_manager, package_name, package_version):
    """Checks if the pypi package was potentially deprecated."""
    if package_manager != "pypi":
        return None

    url = f"https://pypi.org/pypi/{_q(package_name)}/{_q(package_version)}/json"
    try:
        resp = requests.get(url, timeout=HTTP_TIMEOUT)
        if resp.status_code != 200:
            return None

        data = resp.json()
        info = data.get("info", {}) or {}
        classifiers = info.get("classifiers", []) or []

        for c in classifiers:
            if c.strip().lower() == "development status :: 7 - inactive".lower():
                return "Inactive/Deprecated (Development Status :: 7 - Inactive)"

        return None
    except Exception:
        return None


def fetch_cargo_deprecated(package_manager, package_name, package_version):
    """Checks if the cargo package was potentially deprecated / yanked."""
    if package_manager != "cargo":
        return None
    url = f"https://crates.io/api/v1/crates/{_q(package_name)}/{_q(package_version)}"
    try:
        resp = requests.get(
            url,
            headers={
                "User-Agent": "heisenberg-ssc-health-check (https://github.com/AppOmni-Labs/heisenberg-ssc-health-check)"
            },
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        version_info = resp.json().get("version", {}) or {}
        if version_info.get("yanked"):
            return "Yanked from crates.io"
        return None
    except Exception:
        return None


def fetch_version_data(base_url, package_manager, encoded_name, package_version):
    version_url = f"{base_url}/systems/{package_manager}/packages/{encoded_name}/versions/{_q(package_version)}"
    return requests.get(version_url, timeout=HTTP_TIMEOUT)


def fetch_dependents_count(package_manager, encoded_name, package_version):
    """Fetch data on how many projects depend on the package version."""
    dependents_url = f"https://api.deps.dev/v3alpha/systems/{package_manager}/packages/{encoded_name}/versions/{_q(package_version)}:dependents"
    dependents_resp = requests.get(dependents_url, timeout=HTTP_TIMEOUT)
    if dependents_resp.status_code == 200:
        return dependents_resp.json().get("dependentCount", "N/A")
    return "N/A"


def fetch_project_data_with_github_fallback(base_url, project_id):
    """Fetch data from deps.dev or github if deps.dev not available."""
    project_data = {}
    stars = 0
    forks = 0
    if not project_id:
        _log("[INFO] No project ID found, skipping project-level metadata.")
        return project_data, stars, forks

    project_url = f"{base_url}/projects/{_q(project_id)}"
    project_response = requests.get(project_url, timeout=HTTP_TIMEOUT)
    if project_response.status_code == 200:
        project_data = project_response.json()
        return project_data, stars, forks

    _log(f"[INFO] deps.dev project is not found (status {project_response.status_code})")
    if project_id.startswith("github.com"):
        try:
            owner_repo = project_id[len("github.com/"):]
            parts = owner_repo.split("/")
            if len(parts) != 2 or not all(parts) or ".." in parts:
                raise ValueError(f"unexpected GitHub project id {project_id!r}")
            gh_api_url = f"https://api.github.com/repos/{_q(parts[0])}/{_q(parts[1])}"
            gh_resp = requests.get(gh_api_url, timeout=HTTP_TIMEOUT)
            if gh_resp.status_code == 200:
                gh_data = gh_resp.json()
                stars = gh_data.get("stargazers_count", 0)
                forks = gh_data.get("forks_count", 0)
            else:
                _log(f"[WARN] Github API failed for {owner_repo} with {gh_resp.status_code}")
        except Exception as e:
            _log(f"[ERROR] Exception during Github API fallback: {e}")
    return project_data, stars, forks


# TODO: Experimental, need to revise the formula and put more weight into Security and Maintanance
# deps.dev health score is too agressive and it would be better to soften the score a bit. Therefore,
# it makes sense to calculate our own score based on the metrics we care about the most.
def compute_custom_health_score(parsed):
    try:
        stars = int(parsed["popularity_info_stars"])
        forks = int(parsed["popularity_info_forks"])
        maintained = (
            float(parsed["maintenance_info"])
            if parsed["maintenance_info"] != "N/A"
            else 0
        )
        vulnerabilities = (
            float(parsed["security_score"]) if parsed["security_score"] != "N/A" else 0
        )
        dependents = int(parsed["dependents"]) if parsed["dependents"] != "N/A" else 0

        raw_pop = math.log1p(stars + forks)
        popularity_score = min((raw_pop / 2.5) * 10, 10)
        dependent_score = min((math.log1p(dependents) / 10) * 10, 10)

        health_score = (
            popularity_score * 0.25
            + maintained * 0.2
            + vulnerabilities * 0.3
            + dependent_score * 0.25
        )
        computed = round(health_score, 1)

        if parsed["health_score"] not in {"N/A", "Not Found"}:
            try:
                package_score = float(parsed["health_score"])
                final_score = round((package_score + computed) / 2, 1)
                return final_score
            except ValueError:
                pass

        return computed

    except Exception:
        return "Unknown"


def _deprecation(package_manager, package_name, package_version):
    if package_manager == "npm":
        return fetch_npm_deprecated(package_manager, package_name, package_version)
    if package_manager == "pypi":
        return fetch_pypi_deprecated(package_manager, package_name, package_version)
    if package_manager == "cargo":
        return fetch_cargo_deprecated(package_manager, package_name, package_version)
    return None


def _install_scripts(package_manager, package_name, package_version):
    """npm lifecycle scripts / cargo build scripts. Errors are reported, never hidden."""
    if package_manager == "npm":
        try:
            return {"kind": "npm_lifecycle", **check_npm_postinstall(package_name, package_version)}
        except Exception as e:
            return {"kind": "npm_lifecycle", "has_postinstall": None, "lifecycle": [],
                    "postinstall_cmd": "", "error": f"{type(e).__name__}: {e}"}
    if package_manager == "cargo":
        try:
            return {"kind": "cargo_build_script", **check_cargo_build_script(package_name, package_version)}
        except Exception as e:
            return {"kind": "cargo_build_script", "has_build_script": None,
                    "build_script_path": "", "error": f"{type(e).__name__}: {e}"}
    return None


def check_package(package_manager, package_name, package_version):
    """Single source of truth for `heisenberg check`, bulk/vendor (via the CLI) and MCP.

    Returns a dict with "status": "ok" | "not_found" | "error" | "unsupported".
    "not_found" means deps.dev answered 404; "error" means any other non-200 answer.
    Network errors propagate; callers decide how to report them.
    """
    package_manager = package_manager.lower()
    base = {"ecosystem": package_manager, "package": package_name, "version": package_version}
    if package_manager not in SUPPORTED_MANAGERS:
        return {**base, "status": "unsupported", "error": f"manager '{package_manager}' not supported"}

    encoded_name = _q(package_name)
    deprecated = _deprecation(package_manager, package_name, package_version)
    version_response = fetch_version_data(BASE_URL, package_manager, encoded_name, package_version)

    if version_response.status_code != 200:
        return {
            **base,
            "status": "not_found" if version_response.status_code == 404 else "error",
            "http_status": version_response.status_code,
            "health_score": "Not Found", "description": "N/A",
            "popularity_info_stars": "N/A", "popularity_info_forks": "N/A",
            "dependents": "N/A", "maintenance_info": "N/A",
            "security_info": "None", "security_advisories": "N/A", "advisory_ids": [],
            "security_score": "N/A", "deprecated": "N/A", "custom_health_score": "N/A",
            "published_at": "N/A", "fresh_publish": "N/A", "install_scripts": None,
        }

    version_data = version_response.json()
    related_projects = version_data.get("relatedProjects", [])
    project_id = related_projects[0].get("projectKey", {}).get("id", "") if related_projects else ""
    advisory_ids = [a.get("id") for a in version_data.get("advisoryKeys", []) if a.get("id")]
    dependent_count = fetch_dependents_count(package_manager, encoded_name, package_version)

    published_at_iso = version_data.get("publishedAt")
    fresh_flag = "N/A"
    if published_at_iso:
        try:
            dt = datetime.fromisoformat(published_at_iso.replace("Z", "+00:00"))
            hours_old = (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
            fresh_flag = "Yes" if hours_old < 24.0 else "No"
        except Exception:
            fresh_flag = "N/A"

    project_data, stars, forks = fetch_project_data_with_github_fallback(BASE_URL, project_id)
    scorecard = {c["name"]: c for c in project_data.get("scorecard", {}).get("checks", [])}
    parsed = {
        "health_score": project_data.get("scorecard", {}).get("overallScore", "N/A"),
        "description": project_data.get("description", "N/A"),
        # display values: exactly what the CLI has always printed
        "popularity_info_stars": project_data.get("starsCount", stars if stars else "N/A"),
        "popularity_info_forks": project_data.get("forksCount", forks if forks else "N/A"),
        "dependents": dependent_count,
        "maintenance_info": scorecard.get("Maintained", {}).get("score", "N/A"),
        "security_score": scorecard.get("Vulnerabilities", {}).get("score", "N/A"),
    }
    # the score needs numbers; use the GitHub fallback consistently
    custom = compute_custom_health_score({
        **parsed,
        "popularity_info_stars": project_data.get("starsCount", stars or 0),
        "popularity_info_forks": project_data.get("forksCount", forks or 0),
    })

    pkg_safe_name = package_name.replace("/", "%2F")
    snyk_ecosystem, socket_ecosystem = map_ecosystems(package_manager)
    return {
        **base, "status": "ok", **parsed,
        "security_info": f"{len(advisory_ids)}" if advisory_ids else "None",
        "security_advisories": ", ".join(advisory_ids) if advisory_ids else "N/A",
        "advisory_ids": advisory_ids,
        "deprecated": deprecated,
        "custom_health_score": custom,
        "published_at": published_at_iso or "N/A",
        "fresh_publish": fresh_flag,
        "install_scripts": _install_scripts(package_manager, package_name, package_version),
        "deps_url": f"https://deps.dev/{package_manager}/{pkg_safe_name}/{package_version}",
        "snyk_url": f"https://snyk.io/advisor/{snyk_ecosystem}/{package_name}",
        "socket_url": f"https://socket.dev/{socket_ecosystem}/package/{package_name}",
    }


def map_ecosystems(package_manager):
    """Helper to map ecosystem."""
    if package_manager == "pypi":
        return "python", "pypi"
    elif package_manager == "npm":
        return "npm-package", "npm"
    elif package_manager == "go":
        return "golang", "go"
    elif package_manager == "cargo":
        return "cargo", "cargo"
    else:
        return package_manager, package_manager


def print_not_found_and_exit(package_name, package_version):
    print(f"Package: {package_name}")
    print(f"Version: {package_version}")
    print("Package Health Score: Not Found")
    print("Description: N/A")
    print("Popularity (Stars): N/A")
    print("Popularity (Forks): N/A")
    print("Dependents: N/A")
    print("Maintained Score: N/A")
    print("Security Advisory: None")
    print("Security Score (Vulnerabilities): N/A")
    print("Deprecated: N/A")
    print("Published At: N/A")
    print("Fresh Publish (<24h): N/A")
    sys.exit(0)


def print_check_report(r):
    """Text report for `heisenberg check`. bulk_check.parse_output depends on these labels."""
    print(f"Package: {r['package']}")
    print(f"Version: {r['version']}")
    print(f"Package Health Score: {r['health_score']}")
    print(f"Description: {r['description']}")
    print(f"Popularity (Stars): {r['popularity_info_stars']}")
    print(f"Popularity (Forks): {r['popularity_info_forks']}")
    print(f"Dependents: {r['dependents']}")
    print(f"Maintained Score: {r['maintenance_info']}")
    if r["advisory_ids"]:
        print(f"Security Advisory Count: {len(r['advisory_ids'])}")
        print(f"Security Advisory IDs: {', '.join(r['advisory_ids'])}")
    else:
        print("Security Advisory: None")
    print(f"Deprecated: {r['deprecated']}")
    print(f"Custom Health Score: {r['custom_health_score']}")
    print(f"Security Score (Vulnerabilities): {r['security_score']}")
    print(f"Published At: {r['published_at']}")
    print(f"Fresh Publish (<24h): {r['fresh_publish']}")

    info = r.get("install_scripts") or {}
    if r["ecosystem"] == "npm":
        has_post = "Yes" if info.get("has_postinstall") else "No"
        print(f"Has Postinstall: {has_post}")
        print(f"Lifecycle Scripts: {', '.join(info.get('lifecycle', [])) or 'None'}")
        if has_post == "Yes":
            cmd = info.get("postinstall_cmd") or ""
            print(f"Postinstall Cmd: {(cmd[:160] + '…') if len(cmd) > 160 else (cmd or 'N/A')}")
    if r["ecosystem"] == "cargo":
        has_build = "Yes" if info.get("has_build_script") else "No"
        print(f"Has Build Script (build.rs): {has_build}")
        if has_build == "Yes":
            print(f"Build Script Path: {info.get('build_script_path', '')}")

    print("\n[Cross-Check URLs]")
    print(f"deps.dev:    {r['deps_url']}")
    print(f"Snyk:        {r['snyk_url']}")
    print(f"Socket.dev:  {r['socket_url']}")


def cli(args=None):
    if args is None:
        args = parse_args()
    if args.mgmt.lower() not in SUPPORTED_MANAGERS:
        print(f"Error: Package manager '{args.mgmt}' is not supported yet.")
        sys.exit(1)
    result = check_package(args.mgmt, args.pkg, args.version)
    if result["status"] in ("not_found", "error"):
        print_not_found_and_exit(args.pkg, args.version)
    print_check_report(result)


if __name__ == "__main__":
    cli()
