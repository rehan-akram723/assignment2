import pytest
from pydantic import ValidationError
from agent_modules.schema import Violation, AuditReport


def test_valid_violation():
    v = Violation(
        rule_id="SEC-001",
        category="security",
        severity="critical",
        file="config.py",
        line=10,
        description="Hardcoded key",
        evidence="api_key = 'xyz'",
        recommendation="Use env vars"
    )
    assert v.rule_id == "SEC-001"
    assert v.severity == "critical"


def test_invalid_severity():
    with pytest.raises(ValidationError):
        Violation(
            rule_id="SEC-001",
            category="security",
            severity="extreme",
            description="Bad severity",
            evidence="Something",
            recommendation="Fix"
        )


def test_audit_report_json_nulls():
    v = Violation(
        rule_id="HYG-001",
        category="repository_hygiene",
        severity="medium",
        file=None,
        line=None,
        description="Missing README",
        evidence="No file found",
        recommendation="Create README"
    )
    report = AuditReport(repository="https://github.com/example/repo", violations=[v])
    cleaned = report.to_clean_dict()
    assert cleaned["violations"][0]["file"] is None
    assert cleaned["violations"][0]["line"] is None


def test_report_deduplication():
    v1 = Violation(
        rule_id="SEC-001",
        category="security",
        severity="critical",
        file="config.py",
        line=5,
        description="Leak",
        evidence="test",
        recommendation="fix"
    )
    v2 = Violation(
        rule_id="SEC-001",
        category="security",
        severity="critical",
        file="config.py",
        line=5,
        description="Leak",
        evidence="test",
        recommendation="fix"
    )
    report = AuditReport(repository="https://github.com/example/repo", violations=[v1, v2])
    cleaned = report.to_clean_dict()
    assert len(cleaned["violations"]) == 1
