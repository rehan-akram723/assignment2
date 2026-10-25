import tempfile
import pytest
from pathlib import Path
from tools import RepoTools, redact_secrets


@pytest.fixture
def sample_repo():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # create mock repository files
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text('API_KEY = "sk-1234567890abcdef1234567890"\nprint("hello")\n')
        (tmp_path / "README.md").write_text("# Test Project\nSample description.\n")
        (tmp_path / "requirements.txt").write_text("requests\npytest>=7.0.0\n")
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
            "name: CI\non: [pull_request_target]\njobs:\n  build:\n    permissions: write-all\n    steps:\n      - uses: actions/checkout@v3\n"
        )
        yield tmp_path


def test_redact_secrets():
    raw = 'OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"'
    redacted = redact_secrets(raw)
    assert "sk-" not in redacted or "[REDACTED]" in redacted


def test_list_files(sample_repo):
    tools = RepoTools(sample_repo)
    listing = tools.list_files()
    assert "src/app.py" in listing
    assert "README.md" in listing


def test_read_file(sample_repo):
    tools = RepoTools(sample_repo)
    content = tools.read_file("README.md", 1, 2)
    assert "# Test Project" in content
    assert "1: " in content


def test_path_traversal_blocked(sample_repo):
    tools = RepoTools(sample_repo)
    result = tools.read_file("../../outside.txt")
    assert "Error" in result or "traversal" in result.lower()


def test_search_code(sample_repo):
    tools = RepoTools(sample_repo)
    res = tools.search_code(r"hello")
    assert "src/app.py:2" in res


def test_inspect_ci_workflows(sample_repo):
    tools = RepoTools(sample_repo)
    ci_res = tools.inspect_ci_workflows()
    assert "pull_request_target" in ci_res
    assert "write-all" in ci_res


def test_inspect_dependencies(sample_repo):
    tools = RepoTools(sample_repo)
    dep_res = tools.inspect_dependencies()
    assert "unpinned packages: requests" in dep_res
