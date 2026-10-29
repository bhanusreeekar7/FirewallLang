import React, { useState, useEffect, useRef } from "react";
import type { AnalyzeResponse } from "./types";

const SAMPLES = {
  web_server: `firewall "WebServer" {
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

    rule block_telnet {
        action: block;
        protocol: tcp;
        port: 23;
        from: any;
        to: web;
    }
}`,

  shadowed_and_conflicts: `firewall "InternalBorder" {
    rule broad_permit {
        action: allow;
        protocol: tcp;
        port: 8080;
        from: any;
        to: any;
    }

    # This rule is shadowed because broad_permit matches all traffic on 8080 earlier
    rule dead_rule {
        action: allow;
        protocol: tcp;
        port: 8080;
        from: lan;
        to: app;
    }

    # This rule directly contradicts broad_permit with an opposite action on identical port/traffic
    rule contradict_rule {
        action: block;
        protocol: tcp;
        port: 8080;
        from: any;
        to: any;
    }
}`,

  high_risk_exposure: `firewall "VulnerableGateway" {
    rule open_telnet {
        action: allow;
        protocol: tcp;
        port: 23;
        from: any;
        to: internal;
    }

    rule open_rdp {
        action: allow;
        protocol: tcp;
        port: 3389;
        from: any;
        to: mgmt;
    }

    rule open_mysql {
        action: allow;
        protocol: tcp;
        port: 3306;
        from: any;
        to: db;
    }
}`,

  syntax_error: `firewall "Malformed" {
    rule broken_rule {
        action: allow;
        protocol: tcp;
        port: not_a_number;
        # missing from, to, and closing brace
`,
};

const BACKEND_BASE = "http://127.0.0.1:8000";

export default function App() {
  const [sourceCode, setSourceCode] = useState<string>(SAMPLES.web_server);
  const [loading, setLoading] = useState<boolean>(false);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [results, setResults] = useState<AnalyzeResponse | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [copyFeedback, setCopyFeedback] = useState<boolean>(false);

  // Optimizer & Target selection
  const [optimize, setOptimize] = useState<boolean>(false);
  const [target, setTarget] = useState<"iptables" | "nftables" | "json">("iptables");

  // Track latest request sequence to prevent stale overwriting
  const requestSeq = useRef<number>(0);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);

  // Check backend health on load and periodically
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch(`${BACKEND_BASE}/health`, { signal: AbortSignal.timeout(2000) });
        if (res.ok) {
          setBackendOnline(true);
        } else {
          setBackendOnline(false);
        }
      } catch {
        setBackendOnline(false);
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  // Compute line numbers for gutter
  const lineCount = Math.max(1, sourceCode.split("\n").length);
  const lineNumbers = Array.from({ length: lineCount }, (_, i) => i + 1);

  const handleScroll = (e: React.UIEvent<HTMLTextAreaElement>) => {
    if (gutterRef.current) {
      gutterRef.current.scrollTop = e.currentTarget.scrollTop;
    }
  };

  const handleAnalyze = async (overrideOptimize?: boolean, overrideTarget?: "iptables" | "nftables" | "json") => {
    if (!sourceCode.trim()) {
      setApiError("Source editor cannot be empty. Enter FirewallLang rules or load a sample.");
      return;
    }

    setLoading(true);
    setApiError(null);
    const currentReq = ++requestSeq.current;

    const optVal = overrideOptimize !== undefined ? overrideOptimize : optimize;
    const tgtVal = overrideTarget !== undefined ? overrideTarget : target;

    try {
      const response = await fetch(`${BACKEND_BASE}/api/v1/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source: sourceCode,
          optimize: optVal,
          target: tgtVal,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data: AnalyzeResponse = await response.json();

      if (currentReq === requestSeq.current) {
        setResults(data);
      }
    } catch (err: any) {
      if (currentReq === requestSeq.current) {
        setApiError(
          err.message || "Failed to communicate with FirewallLang backend. Ensure backend is running."
        );
      }
    } finally {
      if (currentReq === requestSeq.current) {
        setLoading(false);
      }
    }
  };

  const handleCopyCommands = (textToCopy?: string) => {
    const text = textToCopy || results?.generated_code;
    if (text) {
      navigator.clipboard.writeText(text);
      setCopyFeedback(true);
      setTimeout(() => setCopyFeedback(false), 2000);
    }
  };

  const loadPreset = (key: keyof typeof SAMPLES) => {
    setSourceCode(SAMPLES[key]);
    setApiError(null);
  };

  // Auto-Fix Code: automatically prunes rules flagged as shadowed or redundant from source
  const handleAutoFix = () => {
    if (!results || !results.optimization?.pruned_rules.length) return;

    const deadRuleNames = new Set(results.optimization.pruned_rules.map((p) => p.rule_name));
    const lines = sourceCode.split("\n");
    const newLines: string[] = [];
    let skipping = false;
    let braceCount = 0;

    for (const line of lines) {
      const trimmed = line.trim();
      const ruleMatch = trimmed.match(/^rule\s+([a-zA-Z0-9_]+)\s*\{/);

      if (ruleMatch && deadRuleNames.has(ruleMatch[1])) {
        skipping = true;
        braceCount = 1;
        newLines.push(`    # [AUTO-PRUNED DEAD RULE: ${ruleMatch[1]}]`);
        continue;
      }

      if (skipping) {
        if (line.includes("{")) braceCount++;
        if (line.includes("}")) braceCount--;
        if (braceCount <= 0) {
          skipping = false;
        }
        continue;
      }

      newLines.push(line);
    }

    const updated = newLines.join("\n");
    setSourceCode(updated);
    setTimeout(() => {
      handleAnalyze();
    }, 50);
  };

  return (
    <div className="app-container">
      {/* Header */}
      <header className="app-header">
        <div className="brand">
          <h1 className="brand-title">FirewallLang</h1>
          <span className="brand-subtitle">Firewall Rule Compiler &amp; Analyzer</span>
        </div>
        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          <div className="status-pill">
            <span
              className={`status-dot ${
                backendOnline === true ? "online" : backendOnline === false ? "offline" : ""
              }`}
            />
            <span>
              {backendOnline === true
                ? "Backend Connected"
                : backendOnline === false
                ? "Backend Offline (Port 8000)"
                : "Connecting..."}
            </span>
          </div>
        </div>
      </header>

      {/* Main Two-Column Layout */}
      <main className="main-layout">
        {/* Editor Panel */}
        <section className="editor-panel">
          <div className="panel-header">
            <span className="panel-title">Source Program (.fwl)</span>
            <div className="editor-actions">
              <button
                type="button"
                className="btn"
                onClick={() => loadPreset("web_server")}
                title="Standard Web Server Policy"
              >
                Sample
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => loadPreset("shadowed_and_conflicts")}
                title="Shadowed & Conflicting Policy Demo"
              >
                Conflicts
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => loadPreset("high_risk_exposure")}
                title="Vulnerable High-Risk Ports"
              >
                High Risk
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => setSourceCode("")}
              >
                Clear
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => handleAnalyze()}
                disabled={loading}
              >
                {loading ? "Analyzing..." : "Analyze Rules"}
              </button>
            </div>
          </div>

          {/* Optimizer & Target Controls Bar */}
          <div className="editor-toolbar">
            <label style={{ display: "flex", alignItems: "center", gap: "6px", cursor: "pointer", fontWeight: 600 }}>
              <input
                type="checkbox"
                checked={optimize}
                onChange={(e) => {
                  setOptimize(e.target.checked);
                  handleAnalyze(e.target.checked);
                }}
              />
              <span>Optimizer Pass (-O1 DCE &amp; Redundancy Elimination)</span>
            </label>

            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <span style={{ color: "var(--text-muted)" }}>Target:</span>
              <select
                value={target}
                onChange={(e) => {
                  const t = e.target.value as any;
                  setTarget(t);
                  handleAnalyze(optimize, t);
                }}
                style={{
                  padding: "3px 8px",
                  borderRadius: "4px",
                  border: "1px solid var(--border-color)",
                  fontSize: "11px",
                  fontWeight: 600,
                  background: "var(--surface-secondary)",
                  color: "var(--text-main)",
                  outline: "none",
                }}
              >
                <option value="iptables">Linux iptables</option>
                <option value="nftables">Linux nftables</option>
                <option value="json">JSON IR</option>
              </select>
            </div>
          </div>

          <div className="editor-wrapper">
            <div className="editor-gutter" ref={gutterRef}>
              {lineNumbers.map((num) => (
                <div key={num}>{num}</div>
              ))}
            </div>
            <textarea
              ref={textareaRef}
              className="code-textarea"
              value={sourceCode}
              onChange={(e) => setSourceCode(e.target.value)}
              onScroll={handleScroll}
              spellCheck={false}
              placeholder="Write or paste FirewallLang rules here..."
            />
          </div>

          <div className="editor-shortcuts">
            <span>Syntax: firewall &quot;&lt;name&gt;&quot; &#123; rule &lt;id&gt; &#123; action: allow|block; protocol: tcp|udp; port: 1-65535; from: any|zone; to: any|zone; &#125; &#125;</span>
            {results?.optimization && results.optimization.rules_pruned_count > 0 && (
              <button
                type="button"
                onClick={handleAutoFix}
                style={{
                  color: "#3b82f6",
                  background: "none",
                  border: "none",
                  fontWeight: 600,
                  cursor: "pointer",
                  fontSize: "11px",
                  textDecoration: "underline",
                }}
              >
                Auto-Fix: Prune {results.optimization.rules_pruned_count} Dead Rule(s)
              </button>
            )}
          </div>

          {apiError && (
            <div className="diag-item error" style={{ marginTop: 8 }}>
              <strong>Error:</strong> {apiError}
            </div>
          )}
        </section>

        {/* Results Panel */}
        <section className="results-panel">
          {!results ? (
            <div className="empty-results">
              <p>No analysis performed yet.</p>
              <p style={{ fontSize: 12, marginTop: 6 }}>
                Click <strong>Analyze Rules</strong> to run the compiler pipeline: Lexer &rarr; Parser &rarr; AST &rarr; Semantic Analysis &rarr; Code Generation &rarr; Risk Evaluation.
              </p>
            </div>
          ) : (
            <>
              {/* 1. Compilation Status */}
              <div
                className={`status-badge ${
                  results.has_errors
                    ? "error"
                    : results.diagnostics.some((d) => d.severity === "warning")
                    ? "warning"
                    : "success"
                }`}
              >
                <span>
                  {results.has_errors
                    ? "Compilation Failed: Syntax or Semantic Errors Found"
                    : results.diagnostics.some((d) => d.severity === "warning")
                    ? "Compiled with Warnings"
                    : "Compilation Successful: Valid Policy"}
                </span>
              </div>

              {/* 2. Compiler Optimizer Report (-O1 Pass) */}
              {results.optimization && (
                <div
                  className="section-box"
                  style={{
                    borderLeft: results.optimization.is_optimized ? "4px solid var(--success-color)" : "4px solid var(--border-color)",
                    background: results.optimization.is_optimized ? "var(--success-bg)" : "var(--surface-color)",
                  }}
                >
                  <div className="section-head">
                    <span className="section-heading">Intermediate Compiler Optimizer (-O1)</span>
                    <span
                      style={{
                        fontSize: 11,
                        padding: "2px 8px",
                        borderRadius: "12px",
                        fontWeight: 600,
                        background: results.optimization.is_optimized ? "var(--success-border)" : "var(--surface-secondary)",
                        color: results.optimization.is_optimized ? "var(--success-color)" : "var(--text-muted)",
                      }}
                    >
                      {results.optimization.is_optimized
                        ? `Optimized: ${results.optimization.original_rule_count} -> ${results.optimization.optimized_rule_count} Rules (-${results.optimization.reduction_percentage}%)`
                        : "Ruleset is Fully Compact"}
                    </span>
                  </div>
                  {results.optimization.is_optimized ? (
                    <div>
                      <div style={{ fontSize: 12, color: "var(--success-color)", marginBottom: 6 }}>
                        Estimated Worst-Case Traversal Improvement: <strong>{results.optimization.estimated_traversal_speedup}</strong>
                      </div>
                      <div className="diag-list">
                        {results.optimization.pruned_rules.map((pr, idx) => (
                          <div
                            key={idx}
                            style={{
                              padding: "4px 8px",
                              fontSize: 11,
                              borderRadius: "4px",
                              background: "var(--surface-color)",
                              border: "1px solid var(--success-border)",
                              marginBottom: 4,
                              color: "var(--text-main)",
                            }}
                          >
                            <strong>Rule &apos;{pr.rule_name}&apos; (Line {pr.line}):</strong> {pr.reason}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <p style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      No shadowed or redundant rules detected. Policy is minimal.
                    </p>
                  )}
                </div>
              )}

              {/* 3. Semantic & Syntax Diagnostics */}
              {results.diagnostics.length > 0 && (
                <div className="section-box">
                  <div className="section-head">
                    <span className="section-heading">
                      Diagnostics ({results.diagnostics.length})
                    </span>
                  </div>
                  <div className="diag-list">
                    {results.diagnostics.map((diag, idx) => (
                      <div key={idx} className={`diag-item ${diag.severity}`}>
                        <div className="diag-meta">
                          <span>[{diag.severity.toUpperCase()}]</span>
                          <span>Line {diag.line}:{diag.column}</span>
                          {diag.rule_name && <span>Rule: &apos;{diag.rule_name}&apos;</span>}
                        </div>
                        <div>{diag.message}</div>
                        {diag.suggestion && (
                          <div className="diag-suggestion">
                            Suggestion: {diag.suggestion}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 4. Generated Commands */}
              {results.generated_code && (
                <div className="section-box">
                  <div className="section-head">
                    <span className="section-heading">Generated {target.toUpperCase()} Commands</span>
                    <button
                      type="button"
                      className="btn"
                      style={{ fontSize: 11, padding: "3px 8px" }}
                      onClick={() => handleCopyCommands()}
                    >
                      {copyFeedback ? "Copied!" : "Copy Commands"}
                    </button>
                  </div>
                  <div className="code-block-wrapper">
                    <pre className="code-pre">{results.generated_code}</pre>
                  </div>
                  <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                    Commands generated for inspection only. Not executed on host machine.
                  </p>
                </div>
              )}

              {/* 5. Risk Assessment */}
              <div className="section-box">
                <div className="section-head">
                  <span className="section-heading">Security Risk Assessment</span>
                  <span
                    className={`risk-level-tag ${results.risk.level.toLowerCase()}`}
                  >
                    {results.risk.level} Risk
                  </span>
                </div>
                <div className="risk-header">
                  <div className="risk-score-display">{results.risk.score} / 100</div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                    Deterministic Static Misconfiguration Score
                  </div>
                </div>
                <div className="risk-bar">
                  <div
                    className={`risk-bar-fill ${results.risk.level.toLowerCase()}`}
                    style={{ width: `${Math.min(100, results.risk.score)}%` }}
                  />
                </div>
                <p className="risk-explanation">{results.risk.explanation}</p>

                {results.risk.factors.length > 0 && (
                  <div style={{ marginTop: 10 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                      Contributing Factors:
                    </div>
                    <ul className="factors-list">
                      {results.risk.factors.map((f, i) => (
                        <li key={i}>
                          <span
                            className={`factor-impact ${
                              f.impact > 0 ? "pos" : "neg"
                            }`}
                          >
                            {f.impact > 0 ? `+${f.impact}` : f.impact}
                          </span>
                          <span>
                            <strong>{f.name}:</strong> {f.description}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Supplementary ML Classifier Assessment */}
                {results.ml_assessment && results.ml_assessment.available && (
                  <div
                    style={{
                      marginTop: 12,
                      paddingTop: 10,
                      borderTop: "1px solid var(--border-color)",
                      fontSize: 12,
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                      <span>
                        <strong style={{ fontWeight: 600 }}>ML Classifier: </strong>
                        Predicted <strong>{results.ml_assessment.predicted_level}</strong> (Confidence:{" "}
                        {((results.ml_assessment.confidence || 0) * 100).toFixed(1)}%)
                      </span>
                      <span style={{ color: "var(--text-muted)", fontSize: 11 }}>
                        [{results.ml_assessment.model_type}]
                      </span>
                    </div>

                    {results.ml_assessment.class_probabilities && (
                      <div style={{ display: "flex", gap: "8px", marginTop: 4 }}>
                        {Object.entries(results.ml_assessment.class_probabilities).map(([cName, prob]) => (
                          <div key={cName} style={{ flex: 1, fontSize: 11 }}>
                            <div style={{ display: "flex", justifyContent: "space-between" }}>
                              <span>{cName}:</span>
                              <span>{(prob * 100).toFixed(0)}%</span>
                            </div>
                            <div style={{ height: 4, background: "#27272a", borderRadius: 2, overflow: "hidden", marginTop: 2 }}>
                              <div
                                style={{
                                  height: "100%",
                                  width: `${prob * 100}%`,
                                  background: cName === "Low" ? "#22c55e" : cName === "Medium" ? "#f59e0b" : "#ef4444",
                                }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* 6. Network Topology View */}
              {results.topology && results.topology.nodes.length > 0 && (
                <div className="section-box">
                  <div className="section-head">
                    <span className="section-heading">Network Zone Topology &amp; Attack Surface</span>
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                      {results.topology.nodes.length} Zones | {results.topology.edges.length} Active Paths
                    </span>
                  </div>

                  {results.topology.high_risk_paths.length > 0 && (
                    <div
                      style={{
                        padding: "8px 12px",
                        background: "var(--error-bg)",
                        border: "1px solid var(--error-border)",
                        borderRadius: "4px",
                        marginBottom: 10,
                        fontSize: 12,
                      }}
                    >
                      <strong style={{ color: "var(--error-color)" }}>High-Risk Attack Surface Exposures:</strong>
                      <ul style={{ paddingLeft: 18, marginTop: 4 }}>
                        {results.topology.high_risk_paths.map((hrp, i) => (
                          <li key={i} style={{ color: "#fca5a5" }}>
                            <strong>{hrp.path}</strong> ({hrp.protocol}:{hrp.port}) &mdash; {hrp.reason}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                    {results.topology.nodes.map((node) => (
                      <div
                        key={node.id}
                        style={{
                          padding: "4px 8px",
                          border: "1px solid var(--border-color)",
                          borderRadius: "4px",
                          background: node.is_perimeter ? "var(--info-bg)" : "var(--surface-secondary)",
                          fontSize: 11,
                        }}
                      >
                        <strong style={{ color: node.is_perimeter ? "var(--info-color)" : "inherit" }}>{node.label}</strong>
                        <span style={{ color: "var(--text-muted)", marginLeft: 4 }}>({node.cidr})</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 7. AST View (Collapsible) */}
              {results.ast && (
                <details>
                  <summary>Abstract Syntax Tree (AST JSON)</summary>
                  <div className="collapsible-content">
                    <pre className="json-pre">
                      {JSON.stringify(results.ast, null, 2)}
                    </pre>
                  </div>
                </details>
              )}

              {/* 8. Tokens View (Collapsible) */}
              {results.tokens.length > 0 && (
                <details>
                  <summary>Tokens Stream ({results.tokens.length} Tokens)</summary>
                  <div className="collapsible-content">
                    <table className="token-table">
                      <thead>
                        <tr>
                          <th>#</th>
                          <th>Type</th>
                          <th>Value</th>
                          <th>Line:Col</th>
                        </tr>
                      </thead>
                      <tbody>
                        {results.tokens.map((tok, i) => (
                          <tr key={i}>
                            <td>{i + 1}</td>
                            <td>
                              <code>{tok.type}</code>
                            </td>
                            <td>
                              <code>{tok.value || "—"}</code>
                            </td>
                            <td>
                              {tok.line}:{tok.column}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </details>
              )}
            </>
          )}
        </section>
      </main>
    </div>
  );
}
