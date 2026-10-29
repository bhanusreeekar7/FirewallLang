#  FirewallLang

> **A compiler-based Domain Specific Language (DSL) for declaring firewall policies, catching configuration bugs before they hit production, and evaluating security risk using Machine Learning.**

Built for our **Compiler Design Lab**, FirewallLang treats firewall configuration the same way modern compilers treat C++ or Rust: with strict lexical analysis, abstract syntax trees, static semantic checks, dead-code elimination, multi-target code generation, and intelligent diagnostics.

---

##  Why Did We Build This?

If you have ever had to configure Linux network security manually, you already know the pain:

- **Raw `iptables` and `nftables` syntax is cryptic and verbose.** A single command can span 5 flags, and chaining them together by hand is exhausting.
- **Rule ordering is a silent killer.** Linux firewalls evaluate rules from top to bottom. If you write a broad `ACCEPT` rule on line 2, your strict security rule on line 10 becomes completely unreachable (*shadowed*). The kernel won't warn you—it just silently leaves your servers vulnerable.
- **Auditing large policies is humanly impossible.** When a company has 200+ firewall rules, no human can mentally calculate subnet intersections to know if database port `3306` is accidentally exposed to the public internet.

### The Solution:
FirewallLang replaces manual command-line wrangling with a **clean, human-readable DSL**. You write intent in high-level language; our compiler validates the logic, strips unreachable rules, catches security blunders, and generates bulletproof low-level scripts automatically.

```text
# Before: A messy tangle of manual iptables commands
iptables -A INPUT -p tcp -s 192.168.1.0/24 -d 10.0.0.5 --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -s 0.0.0.0/0 -d 10.0.0.5 --dport 80 -j DROP  # Oops, shadowed!

# After: Clean, declarative FirewallLang policy
firewall "ProductionEdge" {
    rule AllowInternalWeb {
        action: allow;
        protocol: tcp;
        from: internal_net;
        to: web_server;
        port: 80;
    }
}
```

---

##  Key Features at a Glance

-  **Strict Front-End Compiler:** Written from scratch using recursive-descent parsing with exact line and column error reporting.
-  **Static Semantic Analysis:** Automatically flags **shadowed rules** (dead code), **redundancies**, **contradictions**, and invalid port ranges (outside `1-65535`).
-  **Intermediate Optimizer (`-O1`):** Features a **Dead Code Elimination (DCE)** pass that removes unreachable rules, compacting rule chains for faster kernel packet evaluation.
-  **Multi-Target Code Generation:** Compiles down to **Linux `iptables`**, modern **`nftables`**, and **JSON IR** for CI/CD pipelines.
-  **ML-Powered Risk Engine:** A trained Random Forest classifier (**99.12% accuracy**) that analyzes 13 structural features to give an instant security risk rating (Low, Medium, High).
-  **Full-Stack Web IDE + Standalone CLI:** Built with a minimal pure-black React interface (with live editor and Auto-Fix) alongside a zero-dependency terminal CLI.

---

##  Quickstart Guide

Get the entire project running in under a minute!

### Prerequisites
- Python 3.10+ (Standard Library + packages in `backend/requirements.txt`)
- Node.js 18+ (for the Web UI)

---

### Option 1: Launch the Web IDE (Recommended for Demos)

Run our single-command launcher. It spins up the FastAPI backend, starts the Vite frontend, and opens your browser:

```bash
python run_project.py
```

- **Frontend Web UI:** [http://127.0.0.1:5173](http://127.0.0.1:5173)
- **Backend API Docs (Swagger):** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

In the web interface, you can write policies, toggle the `-O1` optimizer on and off, switch between `iptables` and `nftables` targets, view ML risk scores, and click **Auto-Fix** to prune bad rules automatically.

---

### Option 2: Run via Terminal CLI (Zero GUI needed)

If you are grading on a headless server or prefer working in the terminal:

```bash
# Run the built-in demo with full optimizer and nftables output:
python cli.py --demo --optimize --target nftables

# Compile your own .fwl file:
python cli.py my_policy.fwl --optimize
```

---

### Option 3: Run the Automated Test Suite

We built a comprehensive test suite covering the lexer, parser, semantic analyzer, optimizer, and ML model:

```bash
python run_project.py --test
```

> **Result:** `32 passed in ~1.9s` (100% test pass rate).

---

##  How It Works (The 6 Pipeline Stages)

FirewallLang follows classic compiler architecture principles taught in Compiler Design:

```text
Source Code (.fwl)
       │
       ▼
 1. Lexical Analyzer (lexer.py)
       │  Token Stream + (Line, Column) Coordinates
       ▼
 2. Recursive-Descent Parser (parser.py)
       │  Abstract Syntax Tree (AST)
       ▼
 3. Semantic Analyzer (semantic.py)
       │  Subnet overlap, Port checks, Shadowing detection
       ▼
 4. Intermediate Optimizer (optimizer.py)
       │  Dead Code Elimination (-O1)
       ▼
 5. Code Generator (codegen.py)
       │  Emits iptables / nftables / JSON IR
       ▼
 6. ML Risk Engine (ml_model.py)
       │  13-Feature Vector -> Random Forest Risk Rating
```

### Stage 1: Lexical Analysis (`lexer.py`)
Scans source code character by character. Strips comments (`# ...`) and whitespace, produces typed tokens (`TOKEN_KEYWORD`, `TOKEN_IDENTIFIER`, `TOKEN_INT`, etc.), and tracks 1-indexed line and column numbers so any typo produces an exact, friendly error message.

### Stage 2: Parsing & AST Construction (`parser.py`)
Uses LL(1) recursive-descent parsing based on a formal grammar. Constructs a strongly typed Abstract Syntax Tree composed of `FirewallNode`, `RuleNode`, and parameter fields.

### Stage 3: Static Semantic Analysis (`semantic.py`)
This is where the compiler gets smart. It inspects rules pairwise and runs static interval analysis to catch real networking bugs before any packet is ever filtered:
- **Shadowed Rules:** If Rule 1 matches all TCP traffic on port 80 and *blocks* it, a later Rule 5 trying to *allow* port 80 is physically unreachable. The analyzer flags this immediately.
- **Redundant Rules:** Two identical or nested rules doing the exact same action.
- **Contradictory Rules:** Competing instructions with conflicting actions.
- **Port Boundary Checks:** Flags any port numbers outside the legitimate `1-65535` range.

### Stage 4: Intermediate Optimization (`optimizer.py`)
Just like `gcc` strips unreachable code with `-O1`, FirewallLang performs **Dead Code Elimination (DCE)** on the AST. It prunes shadowed rules and merges redundant declarations, directly reducing packet inspection latency in Linux kernel netfilter.

### Stage 5: Multi-Target Code Generation (`codegen.py`)
Traverses the optimized AST and outputs production-ready firewall syntax for:
- **Linux `iptables`**: Generates clean, comment-free rule additions (`iptables -A INPUT ...`).
- **Modern `nftables`**: Emits modern Linux rule tables (`add rule inet filter input ...`).
- **JSON IR**: Emits a standardized JSON representation suitable for cloud orchestration or CI/CD pipelines.

### Stage 6: Machine Learning Risk Assessment (`ml_model.py`)
Extracts a **13-dimensional feature vector** from the AST (measuring wildcards, sensitive port exposures like SSH/RDP/MySQL, allow-to-block ratios, and semantic warning counts). Feeds it into a trained Random Forest model to output an overall configuration risk level: **Low**, **Medium**, or **High**.

---

## The Machine Learning Subsystem

### Why Machine Learning?
Traditional static linters only check binary logic (e.g., *"Is this rule unreachable?"*). But a firewall policy can be 100% syntactically valid and still be an **operational disaster** (e.g., leaving Telnet port 23 open to the entire world). Our ML model acts as an automated security auditor trained to spot dangerous patterns.

### Benchmark & Training Data
- **Dataset:** 4,000 synthetic firewall configurations generated across 5 security archetypes (*Hardened Secure*, *Standard Enterprise*, *Shadowed/Redundant*, *Vulnerable Exposed*, and *Contradictory Chaos*).
- **Model:** `RandomForestClassifier` (`n_estimators=100`, `max_depth=10`, `random_state=42`).
- **Accuracy:** **`99.12%`** on an unseen 800-sample test set.

| Risk Class | Precision | Recall | F1-Score |
|:---|:---:|:---:|:---:|
| **Low Risk** | 1.00 | 1.00 | 1.00 |
| **Medium Risk** | 0.97 | 1.00 | 0.98 |
| **High Risk** | 1.00 | 0.98 | 0.99 |

### What Features Matter Most? (Gini Importance)
1. **`high_risk_allow_count` (29.3%)**: Explicitly allowing dangerous ports (21 FTP, 23 Telnet, 445 SMB, 3389 RDP).
2. **`unrestricted_source_count` (15.8%)**: Ingress rules with `from: any` instead of a restricted subnet.
3. **`high_risk_port_count` (14.1%)**: Presence of sensitive ports regardless of action.
4. **`block_count` (8.5%)**: Proportion of defensive drop rules.
5. **`unrestricted_destination_count` (7.0%)**: Rules with unrestricted egress destinations.

---

## 📝 FirewallLang Syntax Reference

Writing policies in FirewallLang is intuitive and readable:

```text
firewall "CorporateGateway" {
    # Define a rule to allow web traffic
    rule AllowHTTP {
        action: allow;
        protocol: tcp;
        from: any;
        to: web_tier;
        port: 80;
    }

    # Block insecure telnet attempts
    rule BlockTelnet {
        action: block;
        protocol: tcp;
        from: any;
        to: any;
        port: 23;
    }

    # Restrict SSH access to the management subnet only
    rule AllowAdminSSH {
        action: allow;
        protocol: tcp;
        from: admin_vpn;
        to: server_cluster;
        port: 22;
    }
}
```

---

##  Project Directory Structure

```text
compiler/
├── run_project.py               # Master 1-click launcher (Web, CLI, Test)
├── cli.py                       # Standalone terminal CLI entrypoint
├── README.md                    # Project documentation
│
├── backend/                     # FastAPI Backend & Compiler Core
│   ├── app/
│   │   ├── main.py              # FastAPI server bootstrap & CORS
│   │   ├── api/routes.py        # REST endpoints (/lex, /parse, /generate, /analyze)
│   │   ├── compiler/
│   │   │   ├── lexer.py         # Lexical analyzer & token scanner
│   │   │   ├── parser.py        # Recursive-descent grammar parser
│   │   │   ├── ast_nodes.py     # Typed AST dataclass definitions
│   │   │   ├── semantic.py      # Semantic interval analysis (shadowing/redundancy)
│   │   │   ├── optimizer.py     # -O1 Dead Code Elimination pass
│   │   │   └── codegen.py       # iptables, nftables, and JSON code generator
│   │   ├── analysis/
│   │   │   ├── features.py      # 13-dimensional AST feature extractor
│   │   │   ├── risk.py          # Deterministic risk scoring
│   │   │   ├── ml_model.py      # Random Forest inference engine
│   │   │   ├── generate_dataset.py # 4,000 policy dataset generator
│   │   │   ├── train_model.py   # Training script & evaluation metrics
│   │   │   └── models/          # Saved .pkl model & metadata
│   └── tests/                   # 31 Automated unit & integration tests
│
└── frontend/                    # React 19 + TypeScript Web Interface
    ├── src/
    │   ├── App.tsx              # Minimal dark IDE, optimizer toggle & inspector
    │   └── types.ts             # TypeScript interfaces
    └── vite.config.ts           # Frontend build setup
```

---

## 🎓 Academic Lab Details

- **Course:** Compiler Design Laboratory
- **Domain:** Domain-Specific Languages (DSL), Static Code Analysis, Intermediate Optimizations, Machine Learning for Software Security
- **Deliverables:** Working Compiler, Optimizer Pass, Multi-Target Generator, ML Classifier, Web GUI, CLI Driver, and 32 Unit Tests.

---

*Made with dedication for our Compiler Design Lab evaluation.*
