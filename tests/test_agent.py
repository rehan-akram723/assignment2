import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock
from agent_modules.agent_loop import run_agent_loop, run_heuristic_audit
from tools import RepoTools


def test_agent_loop_with_mock_llm():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "main.py").write_text("print('test')")

        mock_client = MagicMock()

        # step 1: LLM decides to list files
        tc1 = MagicMock()
        tc1.id = "call_1"
        tc1.function.name = "list_files"
        tc1.function.arguments = json.dumps({"subpath": ""})
        msg1 = MagicMock(tool_calls=[tc1])
        resp1 = MagicMock(choices=[MagicMock(message=msg1)])

        # step 2: LLM finishes audit
        tc2 = MagicMock()
        tc2.id = "call_2"
        tc2.function.name = "finish_audit"
        tc2.function.arguments = json.dumps({
            "violations": [
                {
                    "rule_id": "TEST-001",
                    "category": "testing",
                    "severity": "high",
                    "file": None,
                    "line": None,
                    "description": "Missing test suite",
                    "evidence": "No tests in repository",
                    "recommendation": "Add pytest tests"
                }
            ]
        })
        msg2 = MagicMock(tool_calls=[tc2])
        resp2 = MagicMock(choices=[MagicMock(message=msg2)])

        mock_client.chat.completions.create.side_effect = [resp1, resp2]

        report = run_agent_loop(
            repo_url="https://github.com/mock/repo",
            repo_dir=str(tmp_path),
            client=mock_client,
            max_steps=5
        )

        assert len(report.violations) == 1
        assert report.violations[0].rule_id == "TEST-001"


def test_heuristic_defective_repo():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / ".env").write_text("SECRET_KEY=12345")
        (tmp_path / "Pipfile").write_text("[packages]\nrequests = '*'\n")
        (tmp_path / "app.py").write_text('token = "secret12345"\n')

        tools = RepoTools(str(tmp_path))
        report = run_heuristic_audit(tools, "https://github.com/mock/defective")

        rule_ids = {v.rule_id for v in report.violations}
        assert "HYG-001" in rule_ids  # missing readme
        assert "CONF-002" in rule_ids  # committed .env
        assert "DEP-001" in rule_ids  # missing Pipfile.lock


def test_heuristic_healthy_repo():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "README.md").write_text("# Project")
        (tmp_path / ".gitignore").write_text("*.pyc\n.env\n")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_main.py").write_text("def test_ok(): assert True")
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / ".github" / "workflows" / "test.yml").write_text(
            "name: CI\non: [push]\njobs:\n  test:\n    steps:\n      - run: pytest\n"
        )
        (tmp_path / "requirements.txt").write_text("pytest==7.4.0\n")

        tools = RepoTools(str(tmp_path))
        report = run_heuristic_audit(tools, "https://github.com/mock/healthy")

        # should not report missing readme, missing gitignore, or missing tests
        rule_ids = {v.rule_id for v in report.violations}
        assert "HYG-001" not in rule_ids
        assert "HYG-002" not in rule_ids
        assert "TEST-001" not in rule_ids
