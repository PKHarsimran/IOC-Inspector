from click.testing import CliRunner

import main


def test_cli_multiple_files(monkeypatch, tmp_path):
    calls = []

    def fake_analyze(path):
        calls.append(path)
        return {"score": 0, "verdict": "benign"}

    monkeypatch.setattr(main, "analyze", fake_analyze)

    f1 = tmp_path / "a.txt"
    f2 = tmp_path / "b.txt"
    f1.write_text("a")
    f2.write_text("b")

    runner = CliRunner()
    result = runner.invoke(main.cli, ["--file", str(f1), "--file", str(f2), "--quiet"])
    assert result.exit_code == 0
    assert calls == [f1, f2]

