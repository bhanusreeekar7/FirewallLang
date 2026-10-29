"""Unit tests for Compiler Rule Optimizer (DCE and Redundancy Elimination)."""
from app.compiler.pipeline import CompilerPipeline


def test_optimizer_prunes_shadowed_and_redundant_rules():
    source = """firewall "OptimizationTest" {
    rule broad_permit {
        action: allow;
        protocol: tcp;
        port: 8080;
        from: any;
        to: any;
    }

    # Shadowed rule (unreachable)
    rule dead_rule {
        action: allow;
        protocol: tcp;
        port: 8080;
        from: lan;
        to: app;
    }

    # Redundant rule
    rule dup_rule {
        action: allow;
        protocol: tcp;
        port: 8080;
        from: any;
        to: any;
    }

    # Distinct valid rule
    rule distinct_ssh {
        action: block;
        protocol: tcp;
        port: 22;
        from: any;
        to: mgmt;
    }
}"""
    pipeline = CompilerPipeline(source)
    res = pipeline.run(optimize=True)

    assert res.optimization_report is not None
    assert res.optimization_report["is_optimized"] is True
    assert res.optimization_report["original_rule_count"] == 4
    assert res.optimization_report["optimized_rule_count"] < 4
    assert res.optimization_report["rules_pruned_count"] >= 1

    # Verify that the optimized AST excluded the dead rule
    optimized_rule_names = [r.name for r in res.optimized_ast.rules]
    assert "dead_rule" not in optimized_rule_names
    assert "distinct_ssh" in optimized_rule_names


def test_optimizer_leaves_clean_ruleset_untouched():
    source = """firewall "CleanPolicy" {
    rule allow_http {
        action: allow;
        protocol: tcp;
        port: 80;
        from: any;
        to: web;
    }
    rule allow_https {
        action: allow;
        protocol: tcp;
        port: 443;
        from: any;
        to: web;
    }
}"""
    pipeline = CompilerPipeline(source)
    res = pipeline.run(optimize=True)

    assert res.optimization_report is not None
    assert res.optimization_report["is_optimized"] is False
    assert res.optimization_report["rules_pruned_count"] == 0
    assert len(res.optimized_ast.rules) == 2
