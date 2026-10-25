import os
import json
import logging
from typing import Dict, Any, List, Optional
from tools import RepoTools, redact_secrets
from agent_modules.schema import AuditReport, Violation
from agent_modules.llm import SYSTEM_PROMPT, TOOL_DEFINITIONS, create_llm_client
from agent_modules.rules import RULES

logger = logging.getLogger("audit_agent")


def run_heuristic_audit(tools: RepoTools, repo_url: str) -> AuditReport:
    # offline inspection fallback used during testing or without api key
    violations = []

    files_list = tools.list_files()
    all_files = set(f.strip() for f in files_list.splitlines())

    # hygiene checks
    has_readme = any("readme" in f.lower() for f in all_files)
    if not has_readme:
        violations.append(Violation(
            rule_id="HYG-001",
            category="repository_hygiene",
            severity="medium",
            file=None,
            line=None,
            description="Missing README file in repository",
            evidence="No README, README.md, or README.rst found in root directory",
            recommendation=RULES["HYG-001"]["recommendation"]
        ))

    if ".gitignore" not in all_files:
        violations.append(Violation(
            rule_id="HYG-002",
            category="repository_hygiene",
            severity="medium",
            file=None,
            line=None,
            description="Missing .gitignore file",
            evidence="Repository root lacks a .gitignore file",
            recommendation=RULES["HYG-002"]["recommendation"]
        ))

    # check tracked cache / local env files
    for f in all_files:
        if f.endswith(".pyc") or "__pycache__/" in f:
            violations.append(Violation(
                rule_id="HYG-003",
                category="repository_hygiene",
                severity="medium",
                file=f,
                line=None,
                description="Tracked Python bytecode or cache file",
                evidence=f"File {f} is committed to the repository",
                recommendation=RULES["HYG-003"]["recommendation"]
            ))
            break
        if f == ".env" or f.endswith("/.env"):
            violations.append(Violation(
                rule_id="CONF-002",
                category="configuration",
                severity="high",
                file=f,
                line=None,
                description="Committed environment file (.env) found in repository",
                evidence=f"Environment secrets file {f} is present in repository tree",
                recommendation=RULES["CONF-002"]["recommendation"]
            ))

    # security credentials search
    sec_matches = tools.search_code(r"(api[_-]?key|secret|password|private_key)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{8,}['\"]")
    if sec_matches and "No matches" not in sec_matches:
        first_line = sec_matches.splitlines()[0]
        parts = first_line.split(":", 2)
        target_file = parts[0] if len(parts) > 0 else None
        target_line = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        violations.append(Violation(
            rule_id="SEC-001",
            category="security",
            severity="critical",
            file=target_file,
            line=target_line,
            description="Potential hardcoded credential or secret detected in source",
            evidence="Pattern matching credential assignment detected in code",
            recommendation=RULES["SEC-001"]["recommendation"]
        ))

    # machine paths search
    path_matches = tools.search_code(r"(/home/[a-z0-9_-]+|/Users/[a-z0-9_-]+|[A-Za-z]:\\[Uu]sers\\[a-z0-9_-]+)")
    if path_matches and "No matches" not in path_matches:
        for line in path_matches.splitlines():
            if "SYSTEM_PROMPT" in line or "agent_modules" in line:
                continue
            parts = line.split(":", 2)
            target_file = parts[0] if len(parts) > 0 else None
            target_line = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            violations.append(Violation(
                rule_id="CONF-001",
                category="configuration",
                severity="high",
                file=target_file,
                line=target_line,
                description="Hardcoded machine-specific absolute path",
                evidence=f"Absolute machine path referenced in {target_file}",
                recommendation=RULES["CONF-001"]["recommendation"]
            ))
            break

    # CI checks
    ci_out = tools.inspect_ci_workflows()
    if "No GitHub Actions workflows found" in ci_out:
        if any(f.endswith(".py") or f.endswith(".js") or f.endswith(".go") for f in all_files):
            violations.append(Violation(
                rule_id="TEST-002",
                category="testing",
                severity="medium",
                file=None,
                line=None,
                description="No automated CI pipeline configured to run tests",
                evidence="Repository has source code but no CI workflow in .github/workflows",
                recommendation=RULES["TEST-002"]["recommendation"]
            ))
    else:
        if "pull_request_target" in ci_out and "actions/checkout" in ci_out:
            violations.append(Violation(
                rule_id="CI-001",
                category="github_actions_ci",
                severity="high",
                file=".github/workflows",
                line=None,
                description="Dangerous pull_request_target trigger checking out PR code",
                evidence="Workflow combines pull_request_target with checkout step",
                recommendation=RULES["CI-001"]["recommendation"]
            ))
        if "write-all" in ci_out:
            violations.append(Violation(
                rule_id="CI-002",
                category="github_actions_ci",
                severity="medium",
                file=".github/workflows",
                line=None,
                description="Overly broad write-all workflow permissions",
                evidence="Workflow grants write-all permissions",
                recommendation=RULES["CI-002"]["recommendation"]
            ))

    # dependency checks
    dep_out = tools.inspect_dependencies()
    if "Pipfile.lock is missing" in dep_out or "package-lock.json" in dep_out or "without poetry.lock" in dep_out:
        violations.append(Violation(
            rule_id="DEP-001",
            category="dependency_management",
            severity="medium",
            file=None,
            line=None,
            description="Missing dependency lockfile for reproducible installation",
            evidence=dep_out.splitlines()[0],
            recommendation=RULES["DEP-001"]["recommendation"]
        ))

    # testing check
    has_test_dir = any(f.startswith("tests/") or f.startswith("test/") or f.startswith("tests\\") for f in all_files)
    has_test_files = any(f.startswith("test_") or f.endswith("_test.py") for f in all_files)
    if not has_test_dir and not has_test_files:
        violations.append(Violation(
            rule_id="TEST-001",
            category="testing",
            severity="high",
            file=None,
            line=None,
            description="Missing automated test suite",
            evidence="No tests directory or test files detected in repository",
            recommendation=RULES["TEST-001"]["recommendation"]
        ))

    return AuditReport(repository=repo_url, violations=violations)


def execute_tool_call(tool_name: str, arguments: dict, tools: RepoTools) -> str:
    # dispatches tool call from llm
    if tool_name == "list_files":
        return tools.list_files(subpath=arguments.get("subpath", ""))
    elif tool_name == "read_file":
        return tools.read_file(
            path=arguments.get("path", ""),
            start_line=arguments.get("start_line", 1),
            end_line=arguments.get("end_line", 250)
        )
    elif tool_name == "search_code":
        return tools.search_code(
            pattern=arguments.get("pattern", ""),
            file_pattern=arguments.get("file_pattern")
        )
    elif tool_name == "git_log":
        return tools.git_log(max_count=arguments.get("max_count", 10))
    elif tool_name == "git_status":
        return tools.git_status()
    elif tool_name == "inspect_ci_workflows":
        return tools.inspect_ci_workflows()
    elif tool_name == "inspect_dependencies":
        return tools.inspect_dependencies()
    elif tool_name == "run_pytest":
        return tools.run_pytest()
    elif tool_name == "run_ruff":
        return tools.run_ruff()
    else:
        return f"Unknown tool: '{tool_name}'"


def run_agent_loop(
    repo_url: str,
    repo_dir: str,
    model: Optional[str] = None,
    max_steps: int = 15,
    client: Optional[Any] = None
) -> AuditReport:
    tools = RepoTools(repo_dir)

    if client is None:
        try:
            client = create_llm_client()
        except Exception:
            # fallback to heuristic inspector when api key is not set
            return run_heuristic_audit(tools, repo_url)

    target_model = model or os.getenv("OPENAI_MODEL") or "gpt-4o-mini"

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Begin your autonomous DevOps audit for repository: {repo_url}.\n"
                f"The repository is cloned and ready for inspection.\n"
                "Follow the observe-reason-select-execute-report cycle. Start by exploring the directory tree."
            )
        }
    ]

    for step in range(max_steps):
        try:
            response = client.chat.completions.create(
                model=target_model,
                messages=messages,
                tools=TOOL_DEFINITIONS,
                tool_choice="auto"
            )
        except Exception as e:
            logger.warning(f"LLM call failed at step {step}: {e}. Falling back to heuristic inspection.")
            return run_heuristic_audit(tools, repo_url)

        choice = response.choices[0]
        msg = choice.message
        tool_calls = msg.tool_calls

        # append model thought/response to message history
        messages.append(msg)

        if not tool_calls:
            # encourage llm to investigate further or finish
            messages.append({
                "role": "user",
                "content": "Please continue your inspection using tools, or call finish_audit if you have reached conclusions."
            })
            continue

        for tc in tool_calls:
            tool_name = tc.function.name
            try:
                args = json.loads(tc.function.arguments) if tc.function.arguments else {}
            except Exception:
                args = {}

            if tool_name == "finish_audit":
                raw_violations = args.get("violations", [])
                parsed = []
                for v in raw_violations:
                    try:
                        parsed.append(Violation(**v))
                    except Exception:
                        pass
                return AuditReport(repository=repo_url, violations=parsed)

            tool_result = execute_tool_call(tool_name, args, tools)

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": tool_result
            })

    # if max steps reached, request final report
    messages.append({
        "role": "user",
        "content": "Max steps reached. Call finish_audit now with all discovered violations."
    })
    try:
        final_resp = client.chat.completions.create(
            model=target_model,
            messages=messages,
            tools=TOOL_DEFINITIONS,
            tool_choice={"type": "function", "function": {"name": "finish_audit"}}
        )
        final_tc = final_resp.choices[0].message.tool_calls
        if final_tc:
            raw_args = json.loads(final_tc[0].function.arguments)
            raw_violations = raw_args.get("violations", [])
            parsed = [Violation(**v) for v in raw_violations if isinstance(v, dict)]
            return AuditReport(repository=repo_url, violations=parsed)
    except Exception:
        pass

    return run_heuristic_audit(tools, repo_url)
