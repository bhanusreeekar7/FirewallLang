"""Unit tests for ML Risk Classifier."""
from app.compiler.pipeline import CompilerPipeline
from app.analysis.risk import RiskAnalyzer
from app.analysis.ml_model import ml_classifier


def test_real_ml_classifier_predicts_probabilities():
    source = """firewall "VulnTest" {
    rule open_rdp {
        action: allow;
        protocol: tcp;
        port: 3389;
        from: any;
        to: mgmt;
    }
    rule open_telnet {
        action: allow;
        protocol: tcp;
        port: 23;
        from: any;
        to: internal;
    }
}"""
    pipeline = CompilerPipeline(source)
    res = pipeline.run()
    risk_res = RiskAnalyzer.evaluate(res.ast, res.diagnostics)

    ml_out = ml_classifier.predict(risk_res.features)
    assert ml_out["available"] is True
    assert ml_out["predicted_level"] in ["Low", "Medium", "High"]
    assert "class_probabilities" in ml_out
    assert "Low" in ml_out["class_probabilities"]
    assert "High" in ml_out["class_probabilities"]
    assert ml_out["confidence"] is not None
    assert isinstance(ml_out["top_features"], list)
