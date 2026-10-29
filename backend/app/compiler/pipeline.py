"""Compiler Pipeline orchestrator for FirewallLang."""
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from app.compiler.tokens import Token
from app.compiler.diagnostics import Diagnostic
from app.compiler.lexer import Lexer
from app.compiler.parser import Parser
from app.compiler.ast_nodes import FirewallNode
from app.compiler.semantic import SemanticAnalyzer
from app.compiler.codegen import CodeGenerator
from app.compiler.optimizer import RuleOptimizer, OptimizationReport


@dataclass
class CompilationResult:
    success: bool
    tokens: List[Token]
    ast: Optional[FirewallNode]
    diagnostics: List[Diagnostic]
    generated_code: Optional[str]
    structured_commands: List[Dict[str, str]]
    optimized_ast: Optional[FirewallNode] = None
    optimization_report: Optional[Dict[str, Any]] = None
    nftables_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "tokens": [t.to_dict() for t in self.tokens],
            "ast": self.ast.to_dict() if self.ast else None,
            "optimized_ast": self.optimized_ast.to_dict() if self.optimized_ast else None,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "generated_code": self.generated_code,
            "structured_commands": self.structured_commands,
            "optimization": self.optimization_report,
            "nftables_code": self.nftables_code,
        }


class CompilerPipeline:
    def __init__(self, source: str):
        self.source = source

    def run(self, optimize: bool = False, target: str = "iptables") -> CompilationResult:
        all_diagnostics: List[Diagnostic] = []

        # 1. Lexing phase
        lexer = Lexer(self.source)
        tokens, lex_diags = lexer.tokenize()
        all_diagnostics.extend(lex_diags)

        # 2. Parsing phase
        parser = Parser(tokens)
        ast, parse_diags = parser.parse()
        all_diagnostics.extend(parse_diags)

        # Check for fatal syntax/lexical errors
        has_fatal_errors = any(d.severity == "error" for d in all_diagnostics)

        # 3. Semantic Analysis phase (run if AST exists)
        sem_diags: List[Diagnostic] = []
        if ast:
            analyzer = SemanticAnalyzer(ast)
            sem_diags = analyzer.analyze()
            all_diagnostics.extend(sem_diags)
            has_fatal_errors = any(d.severity == "error" for d in all_diagnostics)

        # 4. Optimizer Phase (Optional AST Rewriting)
        optimized_ast: Optional[FirewallNode] = None
        opt_report_dict: Optional[Dict[str, Any]] = None

        if ast and not any(d.severity == "error" for d in (lex_diags + parse_diags)):
            opt_ast, opt_report = RuleOptimizer.optimize(ast, all_diagnostics)
            optimized_ast = opt_ast
            opt_report_dict = opt_report.to_dict()

        # Decide which AST to emit code from
        codegen_ast = (optimized_ast if (optimize and optimized_ast) else ast)

        # 5. Code Generation phase (only if no fatal syntax errors and AST is available)
        generated_code = None
        structured_commands = []
        nft_code = None

        if not has_fatal_errors and codegen_ast:
            codegen = CodeGenerator(codegen_ast)
            code, commands, gen_diags = codegen.generate(target=target)
            all_diagnostics.extend(gen_diags)

            if not any(d.severity == "error" for d in gen_diags):
                generated_code = code
                structured_commands = commands

            # Always pre-compute nftables code for multi-target inspection
            try:
                nft_code, _, _ = codegen.generate_nftables()
            except Exception:
                pass

        success = not any(d.severity == "error" for d in all_diagnostics)

        return CompilationResult(
            success=success,
            tokens=tokens,
            ast=ast,
            diagnostics=all_diagnostics,
            generated_code=generated_code,
            structured_commands=structured_commands,
            optimized_ast=optimized_ast,
            optimization_report=opt_report_dict,
            nftables_code=nft_code,
        )
