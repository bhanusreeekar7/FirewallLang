"""Network Topology and Attack Surface Graph Analyzer.

Constructs directed graph topology models from FirewallLang ASTs to map inter-zone
communication channels, highlight attack surface exposures, and emit Mermaid/JSON representations.
"""
from typing import List, Dict, Any, Set
from app.compiler.ast_nodes import FirewallNode
from app.compiler.semantic import HIGH_RISK_PORTS, STANDARD_ZONES


class TopologyAnalyzer:
    @classmethod
    def analyze(cls, ast: FirewallNode | None) -> Dict[str, Any]:
        """Builds zone topology graph, detects high-risk traversal paths, and formats Mermaid syntax."""
        if not ast or not ast.rules:
            return {
                "nodes": [],
                "edges": [],
                "high_risk_paths": [],
                "mermaid_diagram": "graph LR\n    Empty[No Rules Defined]",
            }

        nodes_set: Set[str] = set()
        edges: List[Dict[str, Any]] = []
        high_risk_paths: List[Dict[str, Any]] = []

        for rule in ast.rules:
            if not (rule.source and rule.destination and rule.action and rule.protocol and rule.port):
                continue

            src = rule.source.value.lower()
            dst = rule.destination.value.lower()
            proto = rule.protocol.value.upper()
            port = rule.port.value
            action = rule.action.value.upper()

            nodes_set.add(src)
            nodes_set.add(dst)

            is_high_risk_port = port in HIGH_RISK_PORTS
            is_unrestricted_ingress = rule.source.is_any and dst in ("internal", "db", "mgmt")
            is_critical_path = action == "ALLOW" and (is_high_risk_port or is_unrestricted_ingress)

            edge_data = {
                "id": f"{src}_{dst}_{port}_{proto}",
                "rule_name": rule.name,
                "source": src,
                "destination": dst,
                "protocol": proto,
                "port": port,
                "action": action,
                "is_critical": is_critical_path,
                "service_description": HIGH_RISK_PORTS.get(port, f"Port {port}"),
            }
            edges.append(edge_data)

            if is_critical_path:
                high_risk_paths.append({
                    "rule_name": rule.name,
                    "path": f"{src} -> {dst}",
                    "port": port,
                    "protocol": proto,
                    "reason": f"Allows ingress to sensitive zone '{dst}' on port {port} ({HIGH_RISK_PORTS.get(port, 'custom')})",
                })

        # Format Nodes with IP subnet annotations
        nodes: List[Dict[str, Any]] = []
        for n in sorted(nodes_set):
            nodes.append({
                "id": n,
                "label": n.upper(),
                "cidr": "0.0.0.0/0" if n == "any" else STANDARD_ZONES.get(n, "Private IP"),
                "is_perimeter": n == "any",
            })

        # Generate clean Mermaid flowchart syntax
        mermaid_lines = ["graph LR"]
        mermaid_lines.append("    classDef allow fill:#dcfce7,stroke:#16a34a,stroke-width:2px;")
        mermaid_lines.append("    classDef block fill:#fee2e2,stroke:#dc2626,stroke-width:2px;")
        mermaid_lines.append("    classDef critical fill:#fef08a,stroke:#ca8a04,stroke-width:3px;")

        for edge in edges:
            arrow = "-->" if edge["action"] == "ALLOW" else "-. x .->"
            label = f"{edge['protocol']}:{edge['port']}"
            mermaid_lines.append(f"    {edge['source']}[\"{edge['source'].upper()}\"] {arrow}|\"{label}\"| {edge['destination']}[\"{edge['destination'].upper()}\"]")

        mermaid_diagram = "\n".join(mermaid_lines)

        return {
            "nodes": nodes,
            "edges": edges,
            "high_risk_paths": high_risk_paths,
            "mermaid_diagram": mermaid_diagram,
        }
