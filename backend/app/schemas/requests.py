"""Pydantic request models for FirewallLang API."""
from pydantic import BaseModel, Field
from typing import Optional


class SourceCodeRequest(BaseModel):
    source: str = Field(
        ...,
        description="FirewallLang DSL source code string",
        examples=[
            """firewall "WebServer" {
    rule allow_http {
        action: allow;
        protocol: tcp;
        port: 80;
        from: any;
        to: web;
    }
}"""
        ],
    )
    optimize: Optional[bool] = Field(
        default=False,
        description="Perform intermediate compiler optimization pass (DCE and redundancy elimination)",
    )
    target: Optional[str] = Field(
        default="iptables",
        description="Code generator target backend: 'iptables', 'nftables', or 'json'",
    )
