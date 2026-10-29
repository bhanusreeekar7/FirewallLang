"""Tests for Risk Analyzer and Feature Extractor."""
import pytest
from app.compiler.pipeline import CompilerPipeline
from app.analysis.risk import RiskAnalyzer
from app.analysis.features import FeatureExtractor
from app.analysis.ml_model import ml_classifier


def test_risk_score_boundaries():
    # Insecure policy with multiple open vulnerable ports & contradictions
    source = """firewall "HighRisk" {
    rule open_telnet {
        action: allow;
        protocol: tcp;
        port: 23;
        from: any;
        to: any;
    }
    rule open_rdp {
        action: allow;
        protocol: tcp;
        port: 3389;
        from: any;
        to: any;
    }
    rule conflict {
        action: block;
        protocol: tcp;
        port: 23;
        from: any;
        to: any;
    }
}"""
    res = CompilerPipeline(source).run()
    risk = RiskAnalyzer.evaluate(res.ast, res.diagnostics)

    assert 0 <= risk.score <= 100
    assert risk.level == "High"
    assert len(risk.factors) > 0
    assert any("High-Risk Services Allowed" in f.name for f in risk.factors)


def test_low_risk_policy():
    source = """firewall "SecurePolicy" {
    rule allow_internal_app {
        action: allow;
        protocol: tcp;
        port: 8080;
        from: lan;
        to: app;
    }
    rule drop_all_others {
        action: block;
        protocol: tcp;
        port: 8080;
        from: any;
        to: any;
    }
}"""
    res = CompilerPipeline(source).run()
    risk = RiskAnalyzer.evaluate(res.ast, res.diagnostics)

    assert 0 <= risk.score <= 100
    assert risk.level in ("Low", "Medium")


def test_feature_extractor_metrics():
    source = """firewall "MetricsTest" {
    rule r1 {
        action: allow;
        protocol: tcp;
        port: 80;
        from: any;
        to: web;
    }
    rule r2 {
        action: block;
        protocol: tcp;
        port: 443;
        from: any;
        to: web;
    }
}"""
    res = CompilerPipeline(source).run()
    features = FeatureExtractor.extract(res.ast, res.diagnostics)

    assert features.total_rules == 2
    assert features.allow_count == 1
    assert features.block_count == 1
    assert features.unrestricted_source_count == 2
    assert features.allow_block_ratio == 1.0


def test_ml_classifier_prediction():
    source = """firewall "MLTest" {
    rule web {
        action: allow;
        protocol: tcp;
        port: 80;
        from: any;
        to: web;
    }
}"""
    res = CompilerPipeline(source).run()
    features = FeatureExtractor.extract(res.ast, res.diagnostics)
    ml_result = ml_classifier.predict(features)

    assert "available" in ml_result
    if ml_result["available"]:
        assert ml_result["predicted_level"] in ("Low", "Medium", "High")
        assert 0.0 <= ml_result["confidence"] <= 1.0
