"""Intermediate Compiler Optimizer for FirewallLang.

Performs dead code elimination (DCE), redundancy suppression, and rule-set compaction
on the Abstract Syntax Tree (AST) before target code generation.
"""
from typing import List, Dict, Tuple, Set, Optional, Any
from dataclasses import dataclass, field
import copy

from app.compiler.ast_nodes import FirewallNode, RuleNode
from app.compiler.diagnostics import Diagnostic


@dataclass
class PrunedRuleRecord:
    rule_name: str
    line: int
    reason: str
    category: str  # "DEAD_CODE_SHADOWED", "REDUNDANT", "CONTRADICTORY"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "line": self.line,
            "reason": self.reason,
            "category": self.category,
        }


@dataclass
class OptimizationReport:
    is_optimized: bool
    original_rule_count: int
    optimized_rule_count: int
    rules_pruned_count: int
    reduction_percentage: float
    pruned_rules: List[PrunedRuleRecord] = field(default_factory=list)
    estimated_traversal_speedup: str = "0.0%"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_optimized": self.is_optimized,
            "original_rule_count": self.original_rule_count,
            "optimized_rule_count": self.optimized_rule_count,
            "rules_pruned_count": self.rules_pruned_count,
            "reduction_percentage": round(self.reduction_percentage, 1),
            "estimated_traversal_speedup": self.estimated_traversal_speedup,
            "pruned_rules": [p.to_dict() for p in self.pruned_rules],
        }


class RuleOptimizer:
    """AST Optimizer Pass for Firewall Rulesets."""

    @classmethod
    def optimize(
        cls,
        ast: Optional[FirewallNode],
        diagnostics: List[Diagnostic],
    ) -> Tuple[Optional[FirewallNode], OptimizationReport]:
        """Prunes shadowed, redundant, and contradictory rules from the AST."""
        if not ast or not ast.rules:
            return ast, OptimizationReport(
                is_optimized=False,
                original_rule_count=0,
                optimized_rule_count=0,
                rules_pruned_count=0,
                reduction_percentage=0.0,
                pruned_rules=[],
                estimated_traversal_speedup="0.0%",
            )

        original_count = len(ast.rules)
        pruned_records: List[PrunedRuleRecord] = []
        rules_to_prune: Set[str] = set()

        # Identify rules to eliminate based on semantic diagnostics
        for diag in diagnostics:
            if not diag.rule_name:
                continue

            msg = diag.message.lower()
            if "shadowed rule" in msg:
                rules_to_prune.add(diag.rule_name)
                pruned_records.append(
                    PrunedRuleRecord(
                        rule_name=diag.rule_name,
                        line=diag.line,
                        reason="Dead Code Elimination: Rule is unreachable due to prior broader rule.",
                        category="DEAD_CODE_SHADOWED",
                    )
                )
            elif "redundant rule" in msg:
                rules_to_prune.add(diag.rule_name)
                pruned_records.append(
                    PrunedRuleRecord(
                        rule_name=diag.rule_name,
                        line=diag.line,
                        reason="Redundancy Compaction: Rule conditions are already satisfied by an earlier rule.",
                        category="REDUNDANT",
                    )
                )
            elif "contradictory rule" in msg:
                rules_to_prune.add(diag.rule_name)
                pruned_records.append(
                    PrunedRuleRecord(
                        rule_name=diag.rule_name,
                        line=diag.line,
                        reason="Conflict Elimination: Rule contradicts an earlier established rule.",
                        category="CONTRADICTORY",
                    )
                )

        # Build clean optimized AST
        optimized_rules = [
            copy.deepcopy(r) for r in ast.rules if r.name not in rules_to_prune
        ]

        optimized_ast = copy.deepcopy(ast)
        optimized_ast.rules = optimized_rules

        optimized_count = len(optimized_rules)
        pruned_count = len(rules_to_prune)
        reduction = (
            (float(pruned_count) / float(original_count) * 100.0)
            if original_count > 0
            else 0.0
        )

        # Estimate worst-case sequential packet inspection speedup
        speedup_str = f"+{reduction:.1f}% packet traversal throughput" if reduction > 0 else "0.0%"

        report = OptimizationReport(
            is_optimized=pruned_count > 0,
            original_rule_count=original_count,
            optimized_rule_count=optimized_count,
            rules_pruned_count=pruned_count,
            reduction_percentage=reduction,
            pruned_rules=pruned_records,
            estimated_traversal_speedup=speedup_str,
        )

        return optimized_ast, report
