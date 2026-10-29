"""Diagnostic tracking for compiler errors, warnings, and informational findings."""
from dataclasses import dataclass
from typing import Optional, Literal, Any


SeverityType = Literal["error", "warning", "info"]


@dataclass
class Diagnostic:
    severity: SeverityType
    message: str
    line: int
    column: int
    rule_name: Optional[str] = None
    suggestion: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "rule_name": self.rule_name,
            "suggestion": self.suggestion,
        }
