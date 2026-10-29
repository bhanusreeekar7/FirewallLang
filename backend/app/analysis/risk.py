"""Deterministic Risk Assessment Engine for FirewallLang."""
from typing import Dict, Any, List
from dataclasses import dataclass
from app.compiler.ast_nodes import FirewallNode
from app.compiler.diagnostics import Diagnostic
from app.analysis.features import FeatureExtractor, FirewallFeatures


@dataclass
class RiskFactor:
    name: str
    impact: int  # Positive adds risk, negative reduces risk
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "impact": self.impact,
            "description": self.description,
        }


@dataclass
class RiskAssessmentResult:
    score: int
    level: str  # "Low" | "Medium" | "High"
    factors: List[RiskFactor]
    explanation: str
    features: FirewallFeatures

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "factors": [f.to_dict() for f in self.factors],
            "explanation": self.explanation,
            "features": self.features.to_dict(),
        }


class RiskAnalyzer:
    @classmethod
    def evaluate(
        cls,
        ast: FirewallNode | None,
        diagnostics: List[Diagnostic],
    ) -> RiskAssessmentResult:
        features = FeatureExtractor.extract(ast, diagnostics)

        if not ast or features.total_rules == 0:
            return RiskAssessmentResult(
                score=0,
                level="Low",
                factors=[],
                explanation="No valid rules to assess.",
                features=features,
            )

        score = 15  # baseline score for active policy
        factors: List[RiskFactor] = []

        # 1. High-risk port exposure with 'allow'
        if features.high_risk_allow_count > 0:
            impact = min(features.high_risk_allow_count * 25, 50)
            score += impact
            factors.append(
                RiskFactor(
                    name="High-Risk Services Allowed",
                    impact=impact,
                    description=f"{features.high_risk_allow_count} rule(s) explicitly allow traffic to known vulnerable ports (e.g. Telnet, SMB, RDP, unencrypted DB).",
                )
            )

        # 2. Unrestricted source ('from: any') on allow rules
        if features.unrestricted_source_count > 0:
            impact = min(features.unrestricted_source_count * 8, 25)
            score += impact
            factors.append(
                RiskFactor(
                    name="Unrestricted Source IPs",
                    impact=impact,
                    description=f"{features.unrestricted_source_count} rule(s) permit ingress from wildcard source ('from: any') without IP filtering.",
                )
            )

        # 3. Policy defects: Contradictions
        if features.contradictory_rule_count > 0:
            impact = min(features.contradictory_rule_count * 20, 40)
            score += impact
            factors.append(
                RiskFactor(
                    name="Contradictory Rules Detected",
                    impact=impact,
                    description=f"{features.contradictory_rule_count} rule conflict(s) where opposing actions are assigned to identical traffic conditions.",
                )
            )

        # 4. Policy defects: Shadowed rules
        if features.shadowed_rule_count > 0:
            impact = min(features.shadowed_rule_count * 10, 20)
            score += impact
            factors.append(
                RiskFactor(
                    name="Shadowed / Dead Rules",
                    impact=impact,
                    description=f"{features.shadowed_rule_count} rule(s) will never execute because earlier rules match all of their traffic first.",
                )
            )

        # 5. Proportion of allow vs block
        if features.block_count == 0 and features.allow_count >= 3:
            score += 15
            factors.append(
                RiskFactor(
                    name="Zero Explicit Block Rules",
                    impact=15,
                    description="Policy relies entirely on permissive allow statements without explicit boundary blocks.",
                )
            )
        elif features.block_count > 0:
            # Good security hygiene bonus
            score -= 5
            factors.append(
                RiskFactor(
                    name="Explicit Block Hygiene",
                    impact=-5,
                    description=f"Policy contains {features.block_count} explicit block rule(s) enforcing boundary restrictions.",
                )
            )

        # Clamp score between 0 and 100
        final_score = max(0, min(100, score))

        # Risk categories
        if final_score < 30:
            level = "Low"
            summary = "Policy appears well-constrained with minimal exposure to critical services."
        elif final_score <= 65:
            level = "Medium"
            summary = "Policy exhibits moderate risk due to broad wildcards or overlapping rule definitions."
        else:
            level = "High"
            summary = "Significant misconfigurations or open vulnerable services detected. Immediate review required."

        explanation = (
            f"Calculated heuristic risk score of {final_score}/100 ({level} Risk). {summary}"
        )

        return RiskAssessmentResult(
            score=final_score,
            level=level,
            factors=factors,
            explanation=explanation,
            features=features,
        )
