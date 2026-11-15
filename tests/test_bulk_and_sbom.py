import argparse
import csv
import io
import os
import stat
from pathlib import Path

import pytest

from heisenberg import bulk_check as bc
from heisenberg import github_sbom as gs
from heisenberg import heisenberg_depsdev as dd
from heisenberg import sbom_utils as su


# ---------------- sbom_utils ----------------

def test_repos_file_roundtrip(tmp_path):
    path = su.write_repos_file(str(tmp_path / "sbom"), ["a", "b"], "repos.txt")
    with open(path) as f:
        assert f.read() == "a\nb\n"
    blank = tmp_path / "r.txt"
    blank.write_text("a\n\n  b  \n")
    assert su.load_repos_from_file(str(blank)) == ["a", "b"]


def test_iter_selected_sboms_skips_missing(tmp_path, capsys):
    (tmp_path / "a_sbom.csv").write_text("package\n")
    assert list(su.iter_selected_sboms(str(tmp_path), ["a", "b"])) == [("a", str(tmp_path / "a_sbom.csv"))]
    assert "SBOM not found for repo 'b'" in capsys.readouterr().out


def test_sbom_workspace_never_deletes_preexisting_dir(tmp_path):
    base = tmp_path / "mine"
    base.mkdir()
    (base / "keep.txt").write_text("user data")
    with su.sbom_workspace(str(base)) as work:
        assert os.path.dirname(work) == str(base)
        (Path(work) / "svc_sbom.csv").write_text("package\n")
    assert (base / "keep.txt").read_text() == "user data"
    assert sorted(p.name for p in base.iterdir()) == ["keep.txt"]


def test_sbom_workspace_current_directory_is_safe(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "keep.txt").write_text("x")
    with su.sbom_workspace("."):
        pass
    assert sorted(p.name for p in tmp_path.iterdir()) == ["keep.txt"]


def test_sbom_workspace_removes_only_what_it_created(tmp_path):
    base = tmp_path / "sbom"
    with su.sbom_workspace(str(base)) as work:
        assert Path(work).is_dir()
        assert stat.S_IMODE(os.stat(work).st_mode) == 0o700
    assert not base.exists()


def test_sbom_workspace_runs_are_isolated_and_fresh(tmp_path):
    base = tmp_path / "sbom"
    with su.sbom_workspace(str(base)) as a, su.sbom_workspace(str(base)) as b:
        assert a != b
        (Path(a) / "svc_sbom.csv").write_text("stale\n")
        assert not (Path(b) / "svc_sbom.csv").exists()
    with su.sbom_workspace(str(base)) as c:
        assert list(Path(c).iterdir()) == []


def test_sbom_workspace_cleans_up_on_error(tmp_path):
    base = tmp_path / "mine"
    base.mkdir()
    with pytest.raises(RuntimeError):
        with su.sbom_workspace(str(base)) as work:
            (Path(work) / "x").write_text("1")
            raise RuntimeError("boom")
    assert base.exists() and list(base.iterdir()) == []


def test_run_github_sbom_script_uses_argv_list_not_shell(monkeypatch, tmp_path):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"], seen["kwargs"] = cmd, kwargs
        import subprocess
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(su.subprocess, "run", fake_run)
    assert su.run_github_sbom_script(str(tmp_path), "org; rm -rf /", "repos.txt")
    assert isinstance(seen["cmd"], list)
    assert "org; rm -rf /" in seen["cmd"], "org must be passed as a single argv element"
    assert not seen["kwargs"].get("shell")


# ---------------- github_sbom ----------------

GITHUB_SBOM = {
    "sbom": {
        "packages": [
            {"name": "node_modules/left-pad", "versionInfo": "1.3.0", "licenseConcluded": "MIT",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0"}]},
            {"name": "requests", "versionInfo": "2.32.3", "licenseConcluded": "NOASSERTION",
             "licenseDeclared": "Apache-2.0",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.32.3"}]},
            {"name": "com.github.my-org/svc", "versionInfo": "main"},
        ]
    }
}


def test_github_sbom_writes_csv(fake_http, tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    fake_http.add(r"/repos/my-org/svc/dependency-graph/sbom$", json_data=GITHUB_SBOM)
    fake_http.add(r"/repos/my-org/missing/dependency-graph/sbom$", status_code=404, text="Not Found")

    gs.cli(argparse.Namespace(org="my-org", all=False, repos="svc,missing", repos_file=None, out=str(tmp_path)))

    with open(tmp_path / "svc_sbom.csv") as f:
        rows = list(csv.reader(f))
    assert rows == [
        ["package", "version", "language", "license"],
        ["left-pad", "1.3.0", "npm", "MIT"],
        ["requests", "2.32.3", "pypi", "Apache-2.0"],
        ["com.github.my-org/svc", "main", "", "N/A"],
    ]
    assert not (tmp_path / "missing_sbom.csv").exists()
    assert fake_http.calls[0]["headers"]["Authorization"] == "Bearer tok"


# ---------------- bulk_check ----------------

def test_parse_output_from_real_report(depsdev_report):
    parsed = bc.parse_output(depsdev_report)
    assert parsed["health_score"] == "7.5"
    assert parsed["security_info"] == "1"
    assert parsed["security_advisories"] == "GHSA-aaaa"
    assert parsed["deps_url"] == "https://deps.dev/pypi/requests/2.32.3"
    assert parsed["socket_url"] == "https://socket.dev/pypi/package/requests"


def test_parse_output_defaults():
    parsed = bc.parse_output("garbage\nno colon here\n")
    assert set(parsed.values()) == {"N/A"}


def test_run_check_passes_untrusted_names_as_argv(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"], seen["kwargs"] = cmd, kwargs
        import subprocess
        return subprocess.CompletedProcess(cmd, 0, stdout="Package Health Score: 5\n", stderr="")

    monkeypatch.setattr(bc.subprocess, "run", fake_run)
    evil = "pkg$(touch /tmp/pwned);`id`"
    out = bc.run_check("npm", evil, "1.0")
    assert out["health_score"] == "5"
    assert seen["cmd"][seen["cmd"].index("-pkg") + 1] == evil
    assert not seen["kwargs"].get("shell")
    assert seen["kwargs"]["timeout"] == bc.TIMEOUT


def test_run_check_timeout(monkeypatch):
    import subprocess

    def boom(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(bc.subprocess, "run", boom)
    assert bc.run_check("npm", "x", "1")["health_score"] == "Timeout"


def test_process_sbom_file_normalizes_and_skips(monkeypatch, fixtures_dir):
    monkeypatch.setattr(bc, "run_check", lambda mgr, name, ver: {"health_score": f"{mgr}:{name}"})
    buf = io.StringIO()
    bc.process_sbom_file(str(fixtures_dir / "sbom.csv"), "repo1", csv.writer(buf))
    rows = list(csv.reader(io.StringIO(buf.getvalue())))
    by_pkg = {r[1]: r for r in rows}
    assert len(rows) == 5
    assert by_pkg["serde"][3] == "cargo"
    assert by_pkg["github.com/pkg/errors"][3] == "go"
    assert "incomplete" not in by_pkg
    assert all(len(r) == len(bc.CSV_HEADER) for r in rows)


@pytest.mark.xfail(strict=True, reason="BUG: error row in process_tasks has 16 columns but CSV_HEADER has 19")
def test_process_tasks_error_row_matches_header(monkeypatch):
    def explode(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(bc, "build_csv_row", explode)
    buf = io.StringIO()
    bc.process_tasks([("repo", "pkg", "1.0", "npm", "MIT")], csv.writer(buf))
    row = next(csv.reader(io.StringIO(buf.getvalue())))
    assert len(row) == len(bc.CSV_HEADER)


@pytest.fixture
def depsdev_report(fake_http, capsys):
    fake_http.add(r"pypi\.org", json_data={"info": {"classifiers": []}})
    fake_http.add(r":dependents$", json_data={"dependentCount": 10})
    fake_http.add(r"/v3/systems/pypi/", json_data={
        "relatedProjects": [{"projectKey": {"id": "github.com/psf/requests"}}],
        "advisoryKeys": [{"id": "GHSA-aaaa"}],
    })
    fake_http.add(r"/v3/projects/", json_data={
        "scorecard": {"overallScore": 7.5, "checks": []}, "starsCount": 1, "forksCount": 1,
    })
    dd.cli(argparse.Namespace(mgmt="pypi", pkg="requests", version="2.32.3"))
    return capsys.readouterr().out
