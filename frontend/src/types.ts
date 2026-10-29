export interface TokenItem {
  type: string;
  value: string;
  line: number;
  column: number;
}

export interface DiagnosticItem {
  severity: "error" | "warning" | "info";
  message: string;
  line: number;
  column: number;
  rule_name?: string | null;
  suggestion?: string | null;
}

export interface RiskFactorItem {
  name: string;
  impact: number;
  description: string;
}

export interface RiskAssessmentItem {
  score: number;
  level: "Low" | "Medium" | "High";
  factors: RiskFactorItem[];
  explanation: string;
  features: Record<string, any>;
}

export interface StructuredCommand {
  rule_name: string;
  command: string;
  comment: string;
  line: string;
}

export interface PrunedRuleRecord {
  rule_name: string;
  line: number;
  reason: string;
  category: string;
}

export interface OptimizationReport {
  is_optimized: boolean;
  original_rule_count: number;
  optimized_rule_count: number;
  rules_pruned_count: number;
  reduction_percentage: number;
  estimated_traversal_speedup: string;
  pruned_rules: PrunedRuleRecord[];
}

export interface TopFeatureItem {
  feature: string;
  value: number;
  importance_weight: number;
  impact_score: number;
}

export interface AnalyzeResponse {
  success: boolean;
  has_errors: boolean;
  tokens: TokenItem[];
  ast: any;
  optimized_ast?: any;
  diagnostics: DiagnosticItem[];
  generated_code: string | null;
  structured_commands: StructuredCommand[];
  nftables_code?: string | null;
  optimization?: OptimizationReport | null;
  risk: RiskAssessmentItem;
  ml_assessment: {
    available: boolean;
    model_type?: string;
    accuracy?: number;
    predicted_level?: string | null;
    confidence?: number | null;
    class_probabilities?: Record<string, number>;
    top_features?: TopFeatureItem[];
    reason?: string;
  };
}
