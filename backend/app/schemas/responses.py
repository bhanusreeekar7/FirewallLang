"""Pydantic response models for FirewallLang API."""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    engine: str = "FirewallLang Compiler & Risk Engine"


class TokenItem(BaseModel):
    type: str
    value: str
    line: int
    column: int


class DiagnosticItem(BaseModel):
    severity: str
    message: str
    line: int
    column: int
    rule_name: Optional[str] = None
    suggestion: Optional[str] = None


class LexResponse(BaseModel):
    success: bool
    tokens: List[TokenItem]
    diagnostics: List[DiagnosticItem]
    total_tokens: int


class ParseResponse(BaseModel):
    success: bool
    ast: Optional[Dict[str, Any]] = None
    diagnostics: List[DiagnosticItem]


class GenerateResponse(BaseModel):
    success: bool
    generated_code: Optional[str] = None
    structured_commands: List[Dict[str, str]] = []
    diagnostics: List[DiagnosticItem]
    nftables_code: Optional[str] = None


class RiskFactorItem(BaseModel):
    name: str
    impact: int
    description: str


class RiskAssessmentItem(BaseModel):
    score: int
    level: str
    factors: List[RiskFactorItem]
    explanation: str
    features: Dict[str, Any]


class AnalyzeResponse(BaseModel):
    success: bool
    has_errors: bool
    tokens: List[TokenItem]
    ast: Optional[Dict[str, Any]] = None
    optimized_ast: Optional[Dict[str, Any]] = None
    diagnostics: List[DiagnosticItem]
    generated_code: Optional[str] = None
    structured_commands: List[Dict[str, str]] = []
    nftables_code: Optional[str] = None
    optimization: Optional[Dict[str, Any]] = None
    topology: Optional[Dict[str, Any]] = None
    risk: RiskAssessmentItem
    ml_assessment: Dict[str, Any]
