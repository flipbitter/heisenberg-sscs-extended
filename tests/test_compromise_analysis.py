import argparse
import csv
import os
from pathlib import Path

import pytest

from heisenberg import compromise_analysis as ca


def _args(**kw):
    base = dict(sbom=None, repos=None, all=False, pkg=None, file=None, output="-",
                case_sensitive=False, column="package", org="my-org", repos_file="repos.txt", sbom_dir="sbom")
    base.update(kw)
    return argparse.Namespace(**base)


def test_run_analyze_case_insensitive_and_dedupes(fixtures_dir):
    header, rows = ca.run_analyze(str(fixtures_dir / "sbom.csv"), ["LEFT-PAD"], case_sensitive=False)
    assert header == ["package", "version", "language", "license"]
    assert [r[0] for r in rows] == ["left-pad", "Left-Pad"]


def test_run_analyze_case_sensitive(fixtures_dir):
    _, rows = ca.run_analyze(str(fixtures_dir / "sbom.csv"), ["Left-Pad"], case_sensitive=True)
    assert [r[0] for r in rows] == ["Left-Pad"]


def test_run_analyze_custom_column_and_errors(tmp_path, fixtures_dir):
    _, rows = ca.run_analyze(str(fixtures_dir / "sbom.csv"), ["rust"], False, match_column="language")
    assert [r[0] for r in rows] == ["serde"]
    with pytest.raises(ValueError):
        ca.run_analyze(str(fixtures_dir / "sbom.csv"), ["x"], False, match_column="nope")
    with pytest.raises(FileNotFoundError):
        ca.run_analyze(str(tmp_path / "missing.csv"), ["x"], False)


def test_read_list_file_skips_comments(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text("# compromised\nleft-pad\n\n  event-stream \n")
    assert ca._read_list_file(str(f)) == ["left-pad", "event-stream"]


def test_main_sbom_mode_writes_csv(fixtures_dir, tmp_path):
    out = tmp_path / "findings.csv"
    rc = ca.main(_args(sbom=str(fixtures_dir / "sbom.csv"), pkg="requests,serde", output=str(out)))
    assert rc == 0
    with open(out) as f:
        rows = list(csv.reader(f))
    assert [r[0] for r in rows] == ["package", "requests", "serde"]


def test_main_no_targets_returns_2(fixtures_dir):
    assert ca.main(_args(sbom=str(fixtures_dir / "sbom.csv"), pkg=" , ")) == 2


def test_main_repo_mode_adds_repo_column_and_cleans_up(monkeypatch, tmp_path, fixtures_dir):
    sbom_dir = tmp_path / "sbom"

    def fake_generate(d, org, repos_file):
        assert org == "my-org"
        assert os.path.dirname(d) == str(sbom_dir), "SBOMs go in a per-run subdirectory"
        for repo in ("svc-a", "svc-b"):
            (Path(d) / f"{repo}_sbom.csv").write_text((fixtures_dir / "sbom.csv").read_text())
        return True

    monkeypatch.setattr(ca, "run_github_sbom_script", fake_generate)
    out = tmp_path / "out.csv"
    rc = ca.main(_args(repos="svc-a,svc-b", pkg="left-pad", output=str(out), sbom_dir=str(sbom_dir)))

    assert rc == 0
    with open(out) as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["repo_name", "package", "version", "language", "license"]
    assert [(r[0], r[1]) for r in rows[1:]] == [
        ("svc-a", "left-pad"), ("svc-a", "Left-Pad"), ("svc-b", "left-pad"), ("svc-b", "Left-Pad"),
    ]
    assert not sbom_dir.exists(), "temporary SBOM dir must be cleaned up"


def test_main_repo_mode_generation_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(ca, "run_github_sbom_script", lambda *a: False)
    assert ca.main(_args(repos="svc", pkg="x", sbom_dir=str(tmp_path / "s"))) == 1
    assert not (tmp_path / "s").exists(), "nothing may be left behind after a failed run"


def test_main_repo_mode_keeps_preexisting_sbom_dir(monkeypatch, tmp_path, fixtures_dir):
    """Regression: --sbom-dir pointing at an existing directory must never be deleted."""
    mine = tmp_path / "mine"
    mine.mkdir()
    (mine / "important.txt").write_text("do not delete")
    (mine / "svc_sbom.csv").write_text("package,version,language,license\nleft-pad,0.0.1,npm,MIT\n")

    def fake_generate(d, org, repos_file):
        return True  # generation "succeeds" but writes nothing for svc

    monkeypatch.setattr(ca, "run_github_sbom_script", fake_generate)
    out = tmp_path / "out.csv"
    assert ca.main(_args(repos="svc", pkg="left-pad", output=str(out), sbom_dir=str(mine))) == 0
    assert (mine / "important.txt").read_text() == "do not delete"
    assert sorted(p.name for p in mine.iterdir()) == ["important.txt", "svc_sbom.csv"]
    # the stale svc_sbom.csv in the user's directory must not be analysed
    assert "left-pad" not in out.read_text()
