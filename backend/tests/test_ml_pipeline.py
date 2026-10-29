"""Unit tests for ML Risk Classifier and Topology Graph Analysis."""
from app.compiler.pipeline import CompilerPipeline
from app.analysis.risk import RiskAnalyzer
from app.analysis.ml_model import ml_classifier
from app.analysis.topology import TopologyAnalyzer


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


def test_topology_analyzer_detects_nodes_and_critical_paths():
    source = """firewall "TopologyTest" {
    rule web_traffic {
        action: allow;
        protocol: tcp;
        port: 80;
        from: any;
        to: web;
    }
    rule direct_db_access {
        action: allow;
        protocol: tcp;
        port: 3306;
        from: any;
        to: db;
    }
}"""
    pipeline = CompilerPipeline(source)
    res = pipeline.run()

    topo = TopologyAnalyzer.analyze(res.ast)
    assert len(topo["nodes"]) >= 2
    assert len(topo["edges"]) == 2
    assert "mermaid_diagram" in topo
    assert "graph LR" in topo["mermaid_diagram"]

    # MySQL (3306) from any to db must be flagged as critical path
    assert len(topo["high_risk_paths"]) >= 1
    assert any("3306" in p["reason"] or p["port"] == 3306 for p in topo["high_risk_paths"])
