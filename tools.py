import os
import re
import subprocess
from pathlib import Path
from typing import Optional

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"github_pat_[a-zA-Z0-9_]{40,}"),
    re.compile(r"sk-[a-zA-Z0-9_-]{20,}"),
    re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r'(?i)(api[_-]?key|secret|password|token|auth_token)\s*[:=]\s*["\']([^"\']{6,})["\']')
]


def redact_secrets(text: str) -> str:
    redacted = text
    for pat in SECRET_PATTERNS:
        if pat.pattern.startswith("(?i)"):
            def _sub(match):
                key = match.group(1)
                return f'{key}="[REDACTED]"'
            redacted = pat.sub(_sub, redacted)
        else:
            redacted = pat.sub("[REDACTED]", redacted)
    return redacted


class RepoTools:
    def __init__(self, repo_dir: str):
        self.repo_dir = Path(repo_dir).resolve()

    def _resolve_safe(self, rel_path: str) -> Path:
        target = (self.repo_dir / rel_path).resolve()
        if not str(target).startswith(str(self.repo_dir)):
            raise ValueError(f"Path traversal detected: {rel_path}")
        return target

    def list_files(self, subpath: str = "") -> str:
        # returns file tree excluding git internals
        target_dir = self._resolve_safe(subpath)
        if not target_dir.exists():
            return f"Directory '{subpath}' does not exist."

        collected = []
        for root, dirs, files in os.walk(target_dir):
            if ".git" in dirs:
                dirs.remove(".git")
            if "__pycache__" in dirs:
                dirs.remove("__pycache__")
            if ".pytest_cache" in dirs:
                dirs.remove(".pytest_cache")

            rel_root = os.path.relpath(root, self.repo_dir)
            prefix = "" if rel_root == "." else rel_root.replace("\\", "/") + "/"
            for d in sorted(dirs):
                collected.append(f"{prefix}{d}/")
            for f in sorted(files):
                collected.append(f"{prefix}{f}")

        if not collected:
            return "Repository is empty."
        if len(collected) > 400:
            preview = collected[:400]
            return "\n".join(preview) + f"\n... [{len(collected) - 400} more files truncated]"
        return "\n".join(collected)

    def read_file(self, path: str, start_line: Optional[int] = 1, end_line: Optional[int] = 250) -> str:
        try:
            target = self._resolve_safe(path)
            if not target.is_file():
                return f"File '{path}' does not exist or is not a regular file."

            try:
                content = target.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                return f"Could not read file '{path}': {e}"

            lines = content.splitlines()
            total_lines = len(lines)
            s = max(1, start_line or 1)
            e = min(total_lines, end_line or total_lines)

            slice_lines = lines[s - 1:e]
            numbered = [f"{s + idx}: {redact_secrets(line)}" for idx, line in enumerate(slice_lines)]
            header = f"--- {path} (lines {s}-{e} of {total_lines}) ---\n"
            return header + "\n".join(numbered)
        except Exception as err:
            return f"Error reading file '{path}': {err}"

    def search_code(self, pattern: str, file_pattern: Optional[str] = None) -> str:
        # searches repository files using regex
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except Exception as e:
            return f"Invalid regex pattern '{pattern}': {e}"

        matches = []
        for root, dirs, files in os.walk(self.repo_dir):
            if ".git" in dirs:
                dirs.remove(".git")
            if "__pycache__" in dirs:
                dirs.remove("__pycache__")

            for file in files:
                if file_pattern and not re.search(file_pattern, file, re.IGNORECASE):
                    continue
                file_path = Path(root) / file
                rel_path = str(file_path.relative_to(self.repo_dir)).replace("\\", "/")

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_no, line in enumerate(f, start=1):
                            if regex.search(line):
                                clean_line = redact_secrets(line.strip())
                                matches.append(f"{rel_path}:{line_no}: {clean_line}")
                                if len(matches) >= 50:
                                    break
                except Exception:
                    continue
            if len(matches) >= 50:
                break

        if not matches:
            return f"No matches found for pattern '{pattern}'."
        result = "\n".join(matches)
        if len(matches) >= 50:
            result += "\n... [Search results capped at 50 matches]"
        return result

    def git_log(self, max_count: int = 10) -> str:
        try:
            proc = subprocess.run(
                ["git", "log", f"-n{max_count}", "--pretty=format:%h | %an | %ar | %s"],
                cwd=str(self.repo_dir),
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            if proc.returncode != 0:
                return f"git log failed: {proc.stderr.strip()}"
            return proc.stdout.strip() or "No git commits found."
        except Exception as e:
            return f"Unable to read git log: {e}"

    def git_status(self) -> str:
        try:
            proc = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(self.repo_dir),
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            if proc.returncode != 0:
                return f"git status failed: {proc.stderr.strip()}"
            out = proc.stdout.strip()
            return out if out else "Working tree clean, no untracked files."
        except Exception as e:
            return f"Unable to check git status: {e}"

    def inspect_ci_workflows(self) -> str:
        # inspects github workflows for common security and configuration issues
        wf_dir = self.repo_dir / ".github" / "workflows"
        if not wf_dir.is_dir():
            return "No GitHub Actions workflows found (.github/workflows directory missing)."

        findings = []
        for file in wf_dir.glob("*.y*ml"):
            rel_name = f".github/workflows/{file.name}"
            try:
                content = file.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()

                has_tests = False
                has_pr_target = False
                has_checkout = False
                has_write_all = False
                continue_on_error = []

                for idx, line in enumerate(lines, start=1):
                    lower = line.lower()
                    if "pull_request_target" in lower:
                        has_pr_target = True
                    if "actions/checkout" in lower:
                        has_checkout = True
                    if "permissions: write-all" in lower or "permissions: { write-all }" in lower:
                        has_write_all = True
                    if "continue-on-error: true" in lower:
                        continue_on_error.append(idx)
                    if any(cmd in lower for cmd in ["pytest", "npm test", "go test", "cargo test", "mvn test"]):
                        has_tests = True

                issues = []
                if has_pr_target and has_checkout:
                    issues.append("Uses 'pull_request_target' with 'actions/checkout', potential code injection risk.")
                if has_write_all:
                    issues.append("Uses overly permissive 'permissions: write-all'.")
                if continue_on_error:
                    issues.append(f"Uses 'continue-on-error: true' at line(s): {continue_on_error}.")
                if not has_tests:
                    issues.append("No automated test execution step detected in this workflow.")

                summary = f"Workflow '{rel_name}':\n"
                if issues:
                    summary += "\n".join(f"  - {iss}" for iss in issues)
                else:
                    summary += "  - Standard workflow configuration observed."
                findings.append(summary)
            except Exception as e:
                findings.append(f"Workflow '{rel_name}': could not read ({e})")

        return "\n\n".join(findings) if findings else "No workflow files found in .github/workflows."

    def inspect_dependencies(self) -> str:
        # checks dependency specifications and lockfiles
        findings = []
        files = {f.name: f for f in self.repo_dir.iterdir() if f.is_file()}

        # python checks
        has_reqs = "requirements.txt" in files
        has_pyproject = "pyproject.toml" in files
        has_pipfile = "Pipfile" in files
        has_pipfile_lock = "Pipfile.lock" in files
        has_poetry_lock = "poetry.lock" in files

        if has_pipfile and not has_pipfile_lock:
            findings.append("Pipfile exists but Pipfile.lock is missing.")

        if has_pyproject and not has_poetry_lock:
            try:
                pyproj_text = files["pyproject.toml"].read_text(encoding="utf-8", errors="ignore")
                if "[tool.poetry]" in pyproj_text:
                    findings.append("Poetry configuration in pyproject.toml without poetry.lock.")
            except Exception:
                pass

        if has_reqs:
            try:
                req_text = files["requirements.txt"].read_text(encoding="utf-8", errors="ignore")
                unpinned = []
                for line in req_text.splitlines():
                    clean = line.strip().split("#")[0].strip()
                    if clean and not clean.startswith("-") and not re.search(r"[=><~^]", clean):
                        unpinned.append(clean)
                if unpinned:
                    findings.append(f"requirements.txt has unpinned packages: {', '.join(unpinned[:5])}")
            except Exception:
                pass

        # node checks
        has_pkg = "package.json" in files
        has_pkg_lock = "package-lock.json" in files or "yarn.lock" in files or "pnpm-lock.yaml" in files
        if has_pkg and not has_pkg_lock:
            findings.append("package.json exists but no lockfile (package-lock.json, yarn.lock, pnpm-lock) found.")

        if not findings:
            return "No obvious lockfile or dependency specification conflicts found."
        return "\n".join(f"- {f}" for f in findings)

    def run_pytest(self) -> str:
        # safe execution of pytest if tests exist
        test_dir = self.repo_dir / "tests"
        if not test_dir.exists() and not list(self.repo_dir.glob("test_*.py")):
            return "No test directory or test files found in repository."
        try:
            proc = subprocess.run(
                ["pytest", "-q"],
                cwd=str(self.repo_dir),
                capture_output=True,
                text=True,
                timeout=25,
                check=False
            )
            out = (proc.stdout + "\n" + proc.stderr).strip()
            return f"Pytest exit code {proc.returncode}:\n{out[:500]}"
        except subprocess.TimeoutExpired:
            return "Pytest execution timed out after 25s."
        except Exception as e:
            return f"Failed to run pytest: {e}"

    def run_ruff(self) -> str:
        # safe execution of ruff linter
        try:
            proc = subprocess.run(
                ["ruff", "check", "."],
                cwd=str(self.repo_dir),
                capture_output=True,
                text=True,
                timeout=20,
                check=False
            )
            out = (proc.stdout + "\n" + proc.stderr).strip()
            return f"Ruff exit code {proc.returncode}:\n{out[:500]}" if out else "Ruff passed cleanly."
        except subprocess.TimeoutExpired:
            return "Ruff execution timed out."
        except Exception as e:
            return f"Failed to run ruff: {e}"
