"""Tests for iptables Code Generator."""
import pytest
from app.compiler.pipeline import CompilerPipeline


def test_codegen_tcp_udp_and_actions():
    source = """firewall "MultiProtocol" {
    rule web_traffic {
        action: allow;
        protocol: tcp;
        port: 80;
        from: any;
        to: web;
    }
    rule dns_query {
        action: allow;
        protocol: udp;
        port: 53;
        from: lan;
        to: any;
    }
    rule block_smb {
        action: block;
        protocol: tcp;
        port: 445;
        from: any;
        to: any;
    }
}"""
    res = CompilerPipeline(source).run()
    assert res.success is True
    assert res.generated_code is not None

    code = res.generated_code
    # TCP rule with allow to mapped zone 'web' (192.168.10.10)
    assert "-p tcp --dport 80" in code
    assert "-d 192.168.10.10 -j ACCEPT" in code

    # UDP rule with allow from mapped zone 'lan' (192.168.1.0/24)
    assert "-p udp --dport 53" in code
    assert "-s 192.168.1.0/24 -j ACCEPT" in code

    # Block rule
    assert "-p tcp --dport 445 -j DROP" in code

    # Structured commands verification
    assert len(res.structured_commands) == 3
    assert res.structured_commands[0]["rule_name"] == "web_traffic"
    assert res.structured_commands[1]["rule_name"] == "dns_query"
    assert res.structured_commands[2]["rule_name"] == "block_smb"


def test_codegen_prevented_on_fatal_error():
    source = """firewall "Broken" {
    rule bad_rule {
        action: allow;
        protocol: tcp;
        port: 99999; # Invalid port
        from: any;
        to: any;
    }
}"""
    res = CompilerPipeline(source).run()
    assert res.success is False
    assert res.generated_code is None
    assert len(res.structured_commands) == 0
