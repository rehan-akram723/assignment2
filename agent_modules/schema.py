from typing import List, Optional, Literal
from pydantic import BaseModel, Field
from tools import redact_secrets


SeverityType = Literal["critical", "high", "medium", "low"]


class Violation(BaseModel):
    rule_id: str = Field(..., description="Unique rule identifier e.g. SEC-001")
    category: str = Field(..., description="DevOps area category")
    severity: SeverityType = Field(..., description="critical, high, medium, or low")
    file: Optional[str] = Field(default=None, description="Path to affected file or null")
    line: Optional[int] = Field(default=None, description="Line number or null")
    description: str = Field(..., description="Brief description of the issue")
    evidence: str = Field(..., description="Specific evidence found in repo")
    recommendation: str = Field(..., description="Actionable remediation advice")

    def clean_secrets(self) -> "Violation":
        # strips secrets from text fields
        self.evidence = redact_secrets(self.evidence)
        self.description = redact_secrets(self.description)
        return self


class AuditReport(BaseModel):
    repository: str
    violations: List[Violation] = Field(default_factory=list)

    def to_clean_dict(self) -> dict:
        seen = set()
        cleaned_violations = []
        for v in self.violations:
            v.clean_secrets()
            key = (v.rule_id, v.file, v.line, v.description)
            if key not in seen:
                seen.add(key)
                cleaned_violations.append(v.model_dump(mode="json"))

        return {
            "repository": self.repository,
            "violations": cleaned_violations
        }
