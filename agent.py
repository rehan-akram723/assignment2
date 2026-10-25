import os
import sys
import json
import shutil
import tempfile
import argparse
import subprocess
from pathlib import Path
from dotenv import load_dotenv

from agent_modules.agent_loop import run_agent_loop, run_heuristic_audit
from tools import RepoTools


def clone_target_repo(repo_url: str) -> str:
    # clones public repo shallowly into temp directory
    temp_dir = tempfile.mkdtemp(prefix="repo_audit_")
    try:
        cmd = ["git", "clone", "--depth", "1", repo_url, temp_dir]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if res.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            sys.stderr.write(f"Git clone error: {res.stderr.strip()}\n")
            sys.exit(1)
        return temp_dir
    except subprocess.TimeoutExpired:
        shutil.rmtree(temp_dir, ignore_errors=True)
        sys.stderr.write("Git clone timed out after 90 seconds.\n")
        sys.exit(1)
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        sys.stderr.write(f"Failed to clone repository: {e}\n")
        sys.exit(1)


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="Autonomous DevOps Repository Auditing Agent")
    parser.add_argument("--repo", required=True, help="Public GitHub repository URL or local repository path")
    parser.add_argument("--output", required=True, help="Path to write output JSON report")
    parser.add_argument("--model", default=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), help="LLM model name")
    parser.add_argument("--max-steps", type=int, default=int(os.getenv("MAX_AGENT_STEPS", "15")), help="Max inspection steps")
    parser.add_argument("--offline", action="store_true", help="Force heuristic offline audit without LLM")

    args = parser.parse_args()

    repo_target = args.repo.strip()
    is_remote = repo_target.startswith("http://") or repo_target.startswith("https://") or repo_target.startswith("git@")

    if is_remote:
        work_dir = clone_target_repo(repo_target)
        cleanup = True
    else:
        work_dir = str(Path(repo_target).resolve())
        if not Path(work_dir).exists():
            sys.stderr.write(f"Target repository path '{repo_target}' does not exist.\n")
            sys.exit(1)
        cleanup = False

    try:
        if args.offline:
            tools = RepoTools(work_dir)
            report = run_heuristic_audit(tools, repo_target)
        else:
            report = run_agent_loop(
                repo_url=repo_target,
                repo_dir=work_dir,
                model=args.model,
                max_steps=args.max_steps
            )

        report_dict = report.to_clean_dict()

        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")

        print(f"Audited {repo_target}: found {len(report_dict['violations'])} violations. Report saved to {args.output}")
    except Exception as err:
        sys.stderr.write(f"Fatal audit error: {err}\n")
        sys.exit(1)
    finally:
        if cleanup and os.path.exists(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
