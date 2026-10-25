RULES = {
    "SEC-001": {
        "category": "security",
        "severity": "critical",
        "description": "Hardcoded secret or credential exposed in repository",
        "recommendation": "Remove credential immediately, revoke it, and use environment variables or secret manager."
    },
    "SEC-002": {
        "category": "security",
        "severity": "high",
        "description": "Insecure remote script execution (e.g. curl | bash)",
        "recommendation": "Download, verify checksums or signatures, and review scripts before executing."
    },
    "CI-001": {
        "category": "github_actions_ci",
        "severity": "high",
        "description": "Unsafe GitHub Actions trigger with checkout (e.g. pull_request_target)",
        "recommendation": "Avoid checking out untrusted head code in pull_request_target workflows."
    },
    "CI-002": {
        "category": "github_actions_ci",
        "severity": "medium",
        "description": "Overly broad workflow permissions (write-all)",
        "recommendation": "Set least-privilege permissions at top-level and grant write access only where needed."
    },
    "CI-003": {
        "category": "github_actions_ci",
        "severity": "medium",
        "description": "Critical CI check suppressed using continue-on-error",
        "recommendation": "Remove continue-on-error from critical quality, test, or security gates."
    },
    "HYG-001": {
        "category": "repository_hygiene",
        "severity": "medium",
        "description": "Missing project README documentation",
        "recommendation": "Add a comprehensive README.md explaining project setup, architecture, and usage."
    },
    "HYG-002": {
        "category": "repository_hygiene",
        "severity": "medium",
        "description": "Missing or inadequate .gitignore configuration",
        "recommendation": "Add .gitignore to prevent committing build artifacts, cache, and environment secrets."
    },
    "HYG-003": {
        "category": "repository_hygiene",
        "severity": "medium",
        "description": "Tracked build, cache, or temporary files committed to git",
        "recommendation": "Remove tracked generated files from git history and add them to .gitignore."
    },
    "DEP-001": {
        "category": "dependency_management",
        "severity": "medium",
        "description": "Missing required lockfile for reproducible builds",
        "recommendation": "Commit the generated lockfile (e.g. package-lock.json, Pipfile.lock, poetry.lock)."
    },
    "DEP-002": {
        "category": "dependency_management",
        "severity": "low",
        "description": "Unpinned or loose dependency version constraints",
        "recommendation": "Pin dependencies or specify compatible version bounds to avoid upstream breakage."
    },
    "QUAL-001": {
        "category": "code_quality",
        "severity": "low",
        "description": "Missing linter or code formatting configuration",
        "recommendation": "Configure a code linter/formatter (e.g. ruff, flake8, eslint, pre-commit) to enforce standards."
    },
    "TEST-001": {
        "category": "testing",
        "severity": "high",
        "description": "Missing automated tests in repository",
        "recommendation": "Implement an automated test suite covering core application logic."
    },
    "TEST-002": {
        "category": "testing",
        "severity": "medium",
        "description": "No automated test execution in CI pipeline",
        "recommendation": "Add a CI job to run tests automatically on pull requests and commits."
    },
    "CONF-001": {
        "category": "configuration",
        "severity": "high",
        "description": "Machine-specific hardcoded absolute paths",
        "recommendation": "Use relative paths or configuration variables instead of absolute machine paths."
    },
    "CONF-002": {
        "category": "configuration",
        "severity": "high",
        "description": "Committed local environment configuration or .env file",
        "recommendation": "Remove committed environment file from git, ignore it, and use .env.example."
    },
    "COL-001": {
        "category": "collaboration",
        "severity": "low",
        "description": "Missing collaboration and contribution guidelines",
        "recommendation": "Add CONTRIBUTING.md or pull request templates to guide contributors."
    },
    "REL-001": {
        "category": "build_and_release",
        "severity": "medium",
        "description": "Missing build validation or risky automated release",
        "recommendation": "Ensure build steps are validated before automated deployment or release."
    }
}
