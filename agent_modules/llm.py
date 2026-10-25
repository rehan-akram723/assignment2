import os
from openai import OpenAI


SYSTEM_PROMPT = """You are an expert DevOps Auditing Agent inspecting a GitHub repository.
Your mission is to autonomously inspect the repository, identify genuine DevOps violations, distinguish acceptable alternatives, and report findings with clear evidence and remediation.

Agent Cycle: Observe -> Reason -> Select Tool -> Execute Tool -> Interpret Results -> Report.

Follow these inspection areas:
1. Repository hygiene (missing README, missing/unsuitable .gitignore, tracked cache/temporary files)
2. Dependency management (absent required lockfile when lockfile is required, loose version constraints)
3. Code quality & linting (missing linting/formatting configs)
4. Testing (missing tests, failing tests, no CI test execution)
5. CI/CD & GitHub Actions (dangerous triggers like pull_request_target with checkout, overly broad permissions like write-all, ineffective gates like continue-on-error on critical checks)
6. Security (exposed credentials, private keys, tokens, curl | sh)
7. Configuration (hardcoded absolute machine paths like /home/user or C:\\Users, committed .env files)
8. Collaboration & Release (missing contribution guidelines, risky deployment)

Critical Rules:
- Do not treat an absent optional file/tool as proof of a defect when equivalent solutions exist.
- Do not infer remote branch protection settings from repository files alone.
- Never reproduce secret values in evidence or description; use [REDACTED] or describe the presence without leaking.
- On a mostly healthy repository, avoid false positives; an empty violations list is completely valid.
- When your investigation is complete, call finish_audit with all verified violations.
"""

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "Discover repository files and directory structure.",
            "parameters": {
                "type": "object",
                "properties": {
                    "subpath": {
                        "type": "string",
                        "description": "Optional subpath to list, defaults to root repository directory"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Inspect relevant source or configuration file lines.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative file path to read"},
                    "start_line": {"type": "integer", "description": "Starting line number (1-indexed)"},
                    "end_line": {"type": "integer", "description": "Ending line number (inclusive)"}
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Search code and config files for regex or text patterns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex or keyword pattern to search"},
                    "file_pattern": {"type": "string", "description": "Optional file name regex filter"}
                },
                "required": ["pattern"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "git_log",
            "description": "Inspect recent commit history and commit messages.",
            "parameters": {
                "type": "object",
                "properties": {
                    "max_count": {"type": "integer", "description": "Maximum number of commits to retrieve"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "git_status",
            "description": "Inspect git status for untracked or modified files.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_ci_workflows",
            "description": "Inspect CI workflow definitions in .github/workflows for permissions, triggers, and gates.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_dependencies",
            "description": "Inspect dependency configuration files for missing lockfiles, loose pins, or inconsistencies.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_pytest",
            "description": "Safely execute pytest to test if tests pass or fail.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_ruff",
            "description": "Safely execute ruff linter to inspect code quality and syntax issues.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "finish_audit",
            "description": "Finish the audit investigation and submit final verified violations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "violations": {
                        "type": "array",
                        "description": "List of verified violations discovered during the audit",
                        "items": {
                            "type": "object",
                            "properties": {
                                "rule_id": {"type": "string"},
                                "category": {"type": "string"},
                                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                                "file": {"type": ["string", "null"]},
                                "line": {"type": ["integer", "null"]},
                                "description": {"type": "string"},
                                "evidence": {"type": "string"},
                                "recommendation": {"type": "string"}
                            },
                            "required": ["rule_id", "category", "severity", "description", "evidence", "recommendation"]
                        }
                    }
                },
                "required": ["violations"]
            }
        }
    }
]


def create_llm_client() -> OpenAI:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable is missing. Set it in your environment or .env file.")
    base_url = os.getenv("OPENAI_BASE_URL") or None
    return OpenAI(api_key=api_key, base_url=base_url)
