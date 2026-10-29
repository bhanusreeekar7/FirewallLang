"""API endpoints for FirewallLang compiler and analysis."""
from fastapi import APIRouter, HTTPException, status
from app.schemas.requests import SourceCodeRequest
from app.schemas.responses import (
    HealthResponse,
    LexResponse,
    ParseResponse,
    GenerateResponse,
    AnalyzeResponse,
    TokenItem,
    DiagnosticItem,
    RiskAssessmentItem,
    RiskFactorItem,
)
from app.compiler.lexer import Lexer
from app.compiler.parser import Parser
from app.compiler.pipeline import CompilerPipeline
from app.compiler.codegen import CodeGenerator
from app.compiler.semantic import SemanticAnalyzer
from app.analysis.risk import RiskAnalyzer
from app.analysis.ml_model import ml_classifier
from app.analysis.topology import TopologyAnalyzer

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="ok",
        version="1.0.0",
        engine="FirewallLang Compiler & Risk Engine (v1.0.0 Final)",
    )


@router.post("/api/v1/lex", response_model=LexResponse)
async def lex_code(req: SourceCodeRequest):
    lexer = Lexer(req.source)
    tokens, diags = lexer.tokenize()
    has_errors = any(d.severity == "error" for d in diags)

    return LexResponse(
        success=not has_errors,
        tokens=[TokenItem(**t.to_dict()) for t in tokens],
        diagnostics=[DiagnosticItem(**d.to_dict()) for d in diags],
        total_tokens=len(tokens),
    )


@router.post("/api/v1/parse", response_model=ParseResponse)
async def parse_code(req: SourceCodeRequest):
    lexer = Lexer(req.source)
    tokens, lex_diags = lexer.tokenize()

    parser = Parser(tokens)
    ast, parse_diags = parser.parse()

    all_diags = lex_diags + parse_diags
    has_errors = any(d.severity == "error" for d in all_diags)

    return ParseResponse(
        success=not has_errors,
        ast=ast.to_dict() if ast else None,
        diagnostics=[DiagnosticItem(**d.to_dict()) for d in all_diags],
    )


@router.post("/api/v1/generate", response_model=GenerateResponse)
async def generate_code(req: SourceCodeRequest):
    pipeline = CompilerPipeline(req.source)
    res = pipeline.run(optimize=req.optimize or False, target=req.target or "iptables")

    if not res.success or not res.ast:
        return GenerateResponse(
            success=False,
            generated_code=None,
            structured_commands=[],
            diagnostics=[DiagnosticItem(**d.to_dict()) for d in res.diagnostics],
            nftables_code=None,
        )

    return GenerateResponse(
        success=True,
        generated_code=res.generated_code,
        structured_commands=res.structured_commands,
        diagnostics=[DiagnosticItem(**d.to_dict()) for d in res.diagnostics],
        nftables_code=res.nftables_code,
    )


@router.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze_code(req: SourceCodeRequest):
    pipeline = CompilerPipeline(req.source)
    result = pipeline.run(optimize=req.optimize or False, target=req.target or "iptables")

    # Deterministic Risk Evaluation
    risk_res = RiskAnalyzer.evaluate(result.ast, result.diagnostics)

    # Supplementary ML classification
    ml_res = ml_classifier.predict(risk_res.features)

    # Network Topology and Attack Surface Analysis
    topology_res = TopologyAnalyzer.analyze(result.ast)

    has_errors = not result.success

    return AnalyzeResponse(
        success=result.success,
        has_errors=has_errors,
        tokens=[TokenItem(**t.to_dict()) for t in result.tokens],
        ast=result.ast.to_dict() if result.ast else None,
        optimized_ast=result.optimized_ast.to_dict() if result.optimized_ast else None,
        diagnostics=[DiagnosticItem(**d.to_dict()) for d in result.diagnostics],
        generated_code=result.generated_code,
        structured_commands=result.structured_commands,
        nftables_code=result.nftables_code,
        optimization=result.optimization_report,
        topology=topology_res,
        risk=RiskAssessmentItem(
            score=risk_res.score,
            level=risk_res.level,
            factors=[RiskFactorItem(**f.to_dict()) for f in risk_res.factors],
            explanation=risk_res.explanation,
            features=risk_res.features.to_dict(),
        ),
        ml_assessment=ml_res,
    )
