"""Unit tests for Multi-target Code Generator (nftables & JSON IR)."""
import json
from app.compiler.pipeline import CompilerPipeline
from app.compiler.codegen import CodeGenerator


def test_codegen_emits_valid_nftables_syntax():
    source = """firewall "NFTablesTest" {
    rule web_http {
        action: allow;
        protocol: tcp;
        port: 80;
        from: lan;
        to: web;
    }
    rule drop_telnet {
        action: block;
        protocol: tcp;
        port: 23;
        from: any;
        to: internal;
    }
}"""
    pipeline = CompilerPipeline(source)
    res = pipeline.run(target="nftables")

    assert res.success is True
    assert res.generated_code is not None
    assert "table inet filter" in res.generated_code
    assert "chain input" in res.generated_code
    assert "tcp dport 80 accept" in res.generated_code
    assert "tcp dport 23 drop" in res.generated_code


def test_codegen_emits_valid_json_ir():
    source = """firewall "JsonTest" {
    rule web_rule {
        action: allow;
        protocol: tcp;
        port: 443;
        from: any;
        to: web;
    }
}"""
    pipeline = CompilerPipeline(source)
    codegen = CodeGenerator(pipeline.run().ast)
    json_str, _, _ = codegen.generate_json_ir()

    data = json.loads(json_str)
    assert data["policy_name"] == "JsonTest"
    assert data["default_policy"] == "DROP"
    assert len(data["rules"]) == 1
    assert data["rules"][0]["destination_port"] == 443
    assert data["rules"][0]["action"] == "ALLOW"
