"""Synthetic Dataset Generator for Firewall Policy Risk Classification.

Generates thousands of realistic, varied FirewallLang policies across corporate,
DMZ, cloud, and edge archetypes. Computes compiler AST features and assigns
ground-truth risk levels (Low, Medium, High).
"""
import csv
import os
import random
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Any

# Ensure backend root is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.compiler.pipeline import CompilerPipeline
from app.analysis.risk import RiskAnalyzer
from app.analysis.features import FeatureExtractor

ZONES = ["web", "db", "app", "lan", "dmz", "internal", "mgmt", "any"]
PROTOCOLS = ["tcp", "udp"]
SAFE_PORTS = [80, 443, 8080, 8443, 53, 123, 8000, 9000, 3000, 5000]
RISK_PORTS = [21, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 27017]


def generate_single_policy(archetype: str, seed: int) -> str:
    """Generates a synthetic FirewallLang program string based on an archetype."""
    rng = random.Random(seed)
    lines: List[str] = [f'firewall "Synth_{archetype}_{seed}" {{']

    num_rules = rng.randint(2, 9)

    if archetype == "hardened_secure":
        # Low risk: strict ports, specific zones, high proportion of blocks
        for i in range(num_rules):
            act = "block" if rng.random() < 0.4 else "allow"
            proto = rng.choice(PROTOCOLS)
            port = rng.choice(SAFE_PORTS)
            src = rng.choice(["lan", "mgmt", "dmz", "internal"])
            dst = rng.choice(["web", "app", "db"])
            lines.append(f"""    rule sec_rule_{i} {{
        action: {act};
        protocol: {proto};
        port: {port};
        from: {src};
        to: {dst};
    }}""")

    elif archetype == "standard_enterprise":
        # Low to Medium risk: web server ingress, standard zones
        for i in range(num_rules):
            act = "allow" if rng.random() < 0.75 else "block"
            proto = "tcp"
            port = rng.choice(SAFE_PORTS)
            src = "any" if rng.random() < 0.3 else rng.choice(["lan", "dmz", "internal"])
            dst = rng.choice(["web", "app"])
            lines.append(f"""    rule ent_rule_{i} {{
        action: {act};
        protocol: {proto};
        port: {port};
        from: {src};
        to: {dst};
    }}""")

    elif archetype == "shadowed_redundant":
        # Medium to High risk: contains policy defects like broad rules followed by specific ones
        base_port = rng.choice(SAFE_PORTS)
        lines.append(f"""    rule broad_permit {{
        action: allow;
        protocol: tcp;
        port: {base_port};
        from: any;
        to: any;
    }}""")
        lines.append(f"""    rule shadowed_specific {{
        action: {"block" if rng.random() < 0.5 else "allow"};
        protocol: tcp;
        port: {base_port};
        from: lan;
        to: web;
    }}""")
        for i in range(num_rules - 2):
            lines.append(f"""    rule sub_rule_{i} {{
        action: {rng.choice(["allow", "block"])};
        protocol: tcp;
        port: {rng.choice(SAFE_PORTS + RISK_PORTS)};
        from: {rng.choice(ZONES)};
        to: {rng.choice(ZONES)};
    }}""")

    elif archetype == "vulnerable_exposed":
        # High risk: exposed critical management/database ports with 'from: any'
        for i in range(num_rules):
            is_critical = rng.random() < 0.6
            port = rng.choice(RISK_PORTS) if is_critical else rng.choice(SAFE_PORTS)
            act = "allow" if is_critical else rng.choice(["allow", "block"])
            src = "any" if (is_critical and rng.random() < 0.7) else rng.choice(ZONES)
            dst = rng.choice(["internal", "db", "mgmt", "any"])
            lines.append(f"""    rule vuln_rule_{i} {{
        action: {act};
        protocol: tcp;
        port: {port};
        from: {src};
        to: {dst};
    }}""")

    elif archetype == "contradictory_chaos":
        # High risk: directly conflicting opposing rules
        conflict_port = rng.choice([80, 443, 22, 3389, 8080])
        lines.append(f"""    rule conflict_allow {{
        action: allow;
        protocol: tcp;
        port: {conflict_port};
        from: any;
        to: any;
    }}""")
        lines.append(f"""    rule conflict_block {{
        action: block;
        protocol: tcp;
        port: {conflict_port};
        from: any;
        to: any;
    }}""")
        for i in range(num_rules - 2):
            lines.append(f"""    rule chaos_rule_{i} {{
        action: {rng.choice(["allow", "block"])};
        protocol: {rng.choice(PROTOCOLS)};
        port: {rng.choice(SAFE_PORTS + RISK_PORTS)};
        from: {rng.choice(ZONES)};
        to: {rng.choice(ZONES)};
    }}""")

    lines.append("}")
    return "\n".join(lines)


def generate_dataset(
    output_path: str = "dataset_firewall_rules.csv",
    total_samples: int = 4000,
    random_seed: int = 42,
) -> str:
    """Generates synthetic dataset and writes to CSV."""
    archetypes = [
        "hardened_secure",
        "standard_enterprise",
        "shadowed_redundant",
        "vulnerable_exposed",
        "contradictory_chaos",
    ]

    weights = [0.25, 0.25, 0.20, 0.20, 0.10]
    rng = random.Random(random_seed)

    rows: List[List[Any]] = []
    class_counts = {"Low": 0, "Medium": 0, "High": 0}

    print(f"[*] Generating {total_samples} synthetic firewall policies across 5 archetypes...")

    for i in range(total_samples):
        arch = rng.choices(archetypes, weights=weights)[0]
        source = generate_single_policy(arch, seed=i)

        pipeline = CompilerPipeline(source)
        res = pipeline.run()

        # Extract features and ground truth risk evaluation
        risk_res = RiskAnalyzer.evaluate(res.ast, res.diagnostics)
        feats = risk_res.features
        label = risk_res.level  # "Low", "Medium", "High"
        class_counts[label] += 1

        row = [
            f"Policy_{i:05d}",
            arch,
            feats.total_rules,
            feats.allow_count,
            feats.block_count,
            feats.unrestricted_source_count,
            feats.unrestricted_destination_count,
            feats.high_risk_port_count,
            feats.high_risk_allow_count,
            feats.shadowed_rule_count,
            feats.redundant_rule_count,
            feats.contradictory_rule_count,
            feats.allow_block_ratio,
            feats.error_count,
            feats.warning_count,
            risk_res.score,
            label,
        ]
        rows.append(row)

    # Ensure output directory exists
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    header = [
        "policy_id",
        "archetype",
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
        "continuous_risk_score",
        "risk_level",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)

    print(f"[+] Dataset successfully created at: {output_path}")
    print(f"    Total Records: {len(rows)}")
    print(f"    Class Balance: Low={class_counts['Low']} ({class_counts['Low']/len(rows):.1%}), "
          f"Medium={class_counts['Medium']} ({class_counts['Medium']/len(rows):.1%}), "
          f"High={class_counts['High']} ({class_counts['High']/len(rows):.1%})")

    return output_path


if __name__ == "__main__":
    target_csv = os.path.join(os.path.dirname(__file__), "data", "dataset_firewall_rules.csv")
    generate_dataset(target_csv, total_samples=4000)
