import json
import subprocess
import tempfile
from pathlib import Path


def test_cli_execution():
    with tempfile.TemporaryDirectory() as tmp:
        out_file = Path(tmp) / "report.json"
        cmd = ["python", "agent.py", "--repo", ".", "--output", str(out_file), "--offline"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert res.returncode == 0
        assert out_file.exists()

        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert "repository" in data
        assert "violations" in data
        assert isinstance(data["violations"], list)


def test_cli_missing_repo():
    cmd = ["python", "agent.py", "--repo", "invalid_non_existent_folder_12345", "--output", "out.json"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode != 0
