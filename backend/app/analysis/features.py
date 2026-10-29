"""Feature Extraction for Firewall Policy Risk Assessment.

Extracts numeric features from the AST and semantic diagnostics for use by deterministic
heuristics and machine learning classifiers.
"""
from typing import Dict, Any, List
from dataclasses import dataclass
from app.compiler.ast_nodes import FirewallNode
from app.compiler.diagnostics import Diagnostic
from app.compiler.semantic import HIGH_RISK_PORTS


@dataclass
class FirewallFeatures:
    total_rules: int
    allow_count: int
    block_count: int
    unrestricted_source_count: int      # 'from: any'
    unrestricted_destination_count: int # 'to: any'
    high_risk_port_count: int           # telnet, rdp, etc.
    high_risk_allow_count: int          # allow + high_risk port
    shadowed_rule_count: int
    redundant_rule_count: int
    contradictory_rule_count: int
    allow_block_ratio: float
    error_count: int
    warning_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_rules": self.total_rules,
            "allow_count": self.allow_count,
            "block_count": self.block_count,
            "unrestricted_source_count": self.unrestricted_source_count,
            "unrestricted_destination_count": self.unrestricted_destination_count,
            "high_risk_port_count": self.high_risk_port_count,
            "high_risk_allow_count": self.high_risk_allow_count,
            "shadowed_rule_count": self.shadowed_rule_count,
            "redundant_rule_count": self.redundant_rule_count,
            "contradictory_rule_count": self.contradictory_rule_count,
            "allow_block_ratio": round(self.allow_block_ratio, 2),
            "error_count": self.error_count,
            "warning_count": self.warning_count,
        }

    def to_vector(self) -> List[float]:
        """Returns ordered feature vector for scikit-learn models."""
        return [
            float(self.total_rules),
            float(self.allow_count),
            float(self.block_count),
            float(self.unrestricted_source_count),
            float(self.unrestricted_destination_count),
            float(self.high_risk_port_count),
            float(self.high_risk_allow_count),
            float(self.shadowed_rule_count),
            float(self.redundant_rule_count),
            float(self.contradictory_rule_count),
            float(self.allow_block_ratio),
            float(self.error_count),
            float(self.warning_count),
        ]


class FeatureExtractor:
    FEATURE_NAMES = [
        "total_rules",
        "allow_count",
        "block_count",
        "unrestricted_source_count",
        "unrestricted_destination_count",
        "high_risk_port_count",
        "high_risk_allow_count",
        "shadowed_rule_count",
        "redundant_rule_count",
        "contradictory_rule_count",
        "allow_block_ratio",
        "error_count",
        "warning_count",
    ]

    @classmethod
    def extract(
        cls,
        ast: FirewallNode | None,
        diagnostics: List[Diagnostic],
    ) -> FirewallFeatures:
        if not ast:
            return FirewallFeatures(
                total_rules=0,
                allow_count=0,
                block_count=0,
                unrestricted_source_count=0,
                unrestricted_destination_count=0,
                high_risk_port_count=0,
                high_risk_allow_count=0,
                shadowed_rule_count=0,
                redundant_rule_count=0,
                contradictory_rule_count=0,
                allow_block_ratio=0.0,
                error_count=sum(1 for d in diagnostics if d.severity == "error"),
                warning_count=sum(1 for d in diagnostics if d.severity == "warning"),
            )

        total_rules = len(ast.rules)
        allow_count = 0
        block_count = 0
        unrestricted_source = 0
        unrestricted_dest = 0
        high_risk_ports_seen = 0
        high_risk_allow = 0

        for r in ast.rules:
            is_allow = r.action and r.action.value == "allow"
            is_block = r.action and r.action.value == "block"

            if is_allow:
                allow_count += 1
            elif is_block:
                block_count += 1

            if r.source and r.source.is_any:
                unrestricted_source += 1

            if r.destination and r.destination.is_any:
                unrestricted_dest += 1

            port_val = r.port.value if r.port else None
            if port_val and port_val in HIGH_RISK_PORTS:
                high_risk_ports_seen += 1
                if is_allow:
                    high_risk_allow += 1

        # Diagnostic-derived counts
        shadowed_count = sum(1 for d in diagnostics if "Shadowed rule" in d.message)
        redundant_count = sum(1 for d in diagnostics if "Redundant rule" in d.message)
        contradictory_count = sum(1 for d in diagnostics if "Contradictory rule" in d.message)
        error_count = sum(1 for d in diagnostics if d.severity == "error")
        warning_count = sum(1 for d in diagnostics if d.severity == "warning")

        ratio = float(allow_count) / max(1.0, float(block_count))

        return FirewallFeatures(
            total_rules=total_rules,
            allow_count=allow_count,
            block_count=block_count,
            unrestricted_source_count=unrestricted_source,
            unrestricted_destination_count=unrestricted_dest,
            high_risk_port_count=high_risk_ports_seen,
            high_risk_allow_count=high_risk_allow,
            shadowed_rule_count=shadowed_count,
            redundant_rule_count=redundant_count,
            contradictory_rule_count=contradictory_count,
            allow_block_ratio=ratio,
            error_count=error_count,
            warning_count=warning_count,
        )
