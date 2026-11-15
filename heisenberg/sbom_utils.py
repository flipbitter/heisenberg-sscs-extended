# heisenberg/sbom_utils.py

import os
import sys
import subprocess
import shutil
import tempfile
from contextlib import contextmanager

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def write_repos_file(target_dir: str, repos_list: list[str], repos_file_name: str) -> str:
    ensure_dir(target_dir)
    path = os.path.join(target_dir, repos_file_name)
    with open(path, "w", encoding="utf-8") as f:
        for r in repos_list:
            f.write(f"{r}\n")
    print(f"[INFO] Wrote repo list to {path}")
    return path

def load_repos_from_file(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def run_github_sbom_script(sbom_dir: str, org: str, repos_file_name: str) -> bool:
    ensure_dir(sbom_dir)
    cmd = [
        sys.executable, "-m", "heisenberg.github_sbom",
        "-a",
        "--org", org,
        "--repos-file", repos_file_name,
        "-out", ".",
    ]
    print(f"[INFO] Running SBOM generator: {' '.join(cmd)} (cwd={sbom_dir})")
    proc = subprocess.run(cmd, cwd=sbom_dir, text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout)
    if proc.returncode != 0:
        print("[ERROR] github_sbom module failed")
        if proc.stderr:
            print("STDERR:", proc.stderr)
        return False
    return True

def iter_selected_sboms(sbom_dir: str, selected_repos: list[str]):
    for repo in selected_repos:
        path = os.path.join(sbom_dir, f"{repo}_sbom.csv")
        if os.path.exists(path):
            yield repo, path
        else:
            print(f"[WARN] SBOM not found for repo '{repo}': {path}")

@contextmanager
def sbom_workspace(base_dir: str):
    """Yield a fresh, private, per-run directory inside ``base_dir``.

    Only what this run created is deleted afterwards: the per-run directory,
    and ``base_dir`` itself only if this run created it and it is now empty.
    A pre-existing ``base_dir`` (e.g. ``--sbom-dir .``) and anything else in it
    are never touched. A fresh directory per run also means concurrent runs
    cannot clobber each other and no stale SBOM from an earlier run is reused.
    """
    base_dir = os.path.abspath(base_dir)
    created_base = not os.path.exists(base_dir)
    os.makedirs(base_dir, exist_ok=True)
    work = tempfile.mkdtemp(prefix="heis-sbom-", dir=base_dir)  # mode 0700
    try:
        yield work
    finally:
        try:
            shutil.rmtree(work)
        except OSError as e:
            print(f"[WARN] Failed to remove SBOM run directory {work}: {e}")
        if created_base:
            try:
                os.rmdir(base_dir)  # only succeeds if empty
            except OSError:
                pass
