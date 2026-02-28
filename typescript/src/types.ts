/**
 * TypeScript interfaces for the AumOS OWASP ASI Top 10 defensive library.
 *
 * Mirrors the Python types defined in:
 *   aumos_owasp_defenses.scanner.agent_scanner
 *   aumos_owasp_defenses.scanner.report_generator
 *
 * All interfaces use readonly fields to match Python's frozen dataclasses.
 */

// ---------------------------------------------------------------------------
// OWASP ASI category identifiers
// ---------------------------------------------------------------------------

/**
 * The ten OWASP ASI (Agentic Security Initiative) Top 10 category identifiers.
 * Maps to the ASI category system in the Python scanner.
 */
export type DefenseCategory =
  | "ASI-01" // Goal and Task Hijacking
  | "ASI-02" // Tool and Resource Misuse
  | "ASI-03" // Identity and Privilege Compromise
  | "ASI-04" // Supply Chain and Dependency Risks
  | "ASI-05" // Insecure Code Execution
  | "ASI-06" // Memory and Context Manipulation
  | "ASI-07" // Inter-Agent Trust Exploitation
  | "ASI-08" // Cascading and Recursive Failures
  | "ASI-09" // Context Trust Exploitation
  | "ASI-10"; // Rogue and Emergent Agent Behaviors

// ---------------------------------------------------------------------------
// Scan profile
// ---------------------------------------------------------------------------

/**
 * Pre-defined scan profiles controlling which ASI categories are evaluated.
 * Maps to ScanProfile enum in Python.
 */
export type ScanProfile =
  | "standard"   // All ten ASI categories
  | "quick"      // ASI-01, ASI-02, ASI-03 only
  | "mcp_focused" // ASI-01, ASI-02, ASI-04, ASI-07
  | "compliance"; // All ten categories with stricter thresholds

// ---------------------------------------------------------------------------
// Category result
// ---------------------------------------------------------------------------

/**
 * Result for a single ASI category evaluation.
 * Maps to CategoryResult dataclass in Python.
 */
export interface CategoryResult {
  /** Category identifier (e.g. "ASI-01"). */
  readonly asi_id: DefenseCategory;
  /** Human-readable category name. */
  readonly name: string;
  /** Evaluation status: "PASS", "WARN", or "FAIL". */
  readonly status: "PASS" | "WARN" | "FAIL";
  /** Numeric score for this category (0–100). */
  readonly score: number;
  /** One-sentence description of the finding. */
  readonly summary: string;
  /** List of detailed finding strings. */
  readonly findings: readonly string[];
  /** Actionable remediation steps. */
  readonly recommendations: readonly string[];
  /** Whether the issue can be resolved automatically. */
  readonly auto_fixable: boolean;
}

// ---------------------------------------------------------------------------
// Scan result
// ---------------------------------------------------------------------------

/**
 * Aggregate result of a full agent security scan.
 * Maps to ScanResult dataclass in Python.
 */
export interface ScanResult {
  /** Identifier of the scanned agent. */
  readonly agent_id: string;
  /** The scan profile used. */
  readonly profile: ScanProfile;
  /** Overall security score (0–100), average of category scores. */
  readonly score: number;
  /** Letter grade derived from score (A–F). */
  readonly grade: "A" | "B" | "C" | "D" | "F";
  /** Per-ASI-category results. */
  readonly category_results: readonly CategoryResult[];
  /** ISO-8601 UTC timestamp of when the scan was performed. */
  readonly scanned_at: string;
  /** Wall-clock time for the scan in milliseconds. */
  readonly scan_duration_ms: number;
  /** Count of PASS categories. */
  readonly passed: number;
  /** Count of WARN categories. */
  readonly warned: number;
  /** Count of FAIL categories. */
  readonly failed: number;
}

// ---------------------------------------------------------------------------
// Threat detection
// ---------------------------------------------------------------------------

/**
 * A detected threat or security concern found during input/output scanning.
 */
export interface ThreatDetection {
  /** The ASI category this threat maps to. */
  readonly category: DefenseCategory;
  /** Severity level of the detected threat. */
  readonly severity: "low" | "medium" | "high" | "critical";
  /** Human-readable description of what was detected. */
  readonly description: string;
  /** Whether this threat blocks the action from proceeding. */
  readonly blocking: boolean;
  /** Optional remediation suggestion. */
  readonly remediation?: string;
}

// ---------------------------------------------------------------------------
// Defense configuration
// ---------------------------------------------------------------------------

/**
 * Configuration for the defense scanning client.
 * Mirrors the agent config format accepted by AgentScanner in Python.
 */
export interface DefenseConfig {
  /** Identifier for the agent being configured. */
  readonly agent_id: string;
  /** The scan profile to apply during scanning. */
  readonly profile?: ScanProfile;
  /** System prompt of the agent (used for ASI-01 checks). */
  readonly system_prompt?: string;
  /** Tool declarations with their schemas. */
  readonly tools?: readonly AgentToolDeclaration[];
  /** Declared capability names for privilege checking. */
  readonly capabilities?: readonly string[];
  /** Rate limiting configuration. */
  readonly rate_limits?: { readonly enabled: boolean };
  /** Circuit breaker configuration. */
  readonly circuit_breakers?: { readonly enabled: boolean };
  /** Memory configuration for ASI-06 checks. */
  readonly memory?: {
    readonly enabled: boolean;
    readonly provenance_tracking?: boolean;
    readonly trust_level_enforcement?: boolean;
  };
  /** Code execution configuration for ASI-05 checks. */
  readonly code_execution?: {
    readonly enabled: boolean;
    readonly sandbox?: boolean;
    readonly allowed_paths?: readonly string[];
    readonly command_allowlist?: readonly string[];
  };
  /** Trust configuration for ASI-09 checks. */
  readonly trust_config?: {
    readonly ceiling?: string;
    readonly allow_self_escalation?: boolean;
  };
  /** Supply chain configuration for ASI-04 checks. */
  readonly supply_chain?: {
    readonly hash_verification?: boolean;
    readonly vendor_allowlist?: readonly string[];
  };
  /** Inter-agent communication configuration for ASI-07 checks. */
  readonly inter_agent?: {
    readonly message_validation?: boolean;
    readonly replay_protection?: boolean;
    readonly sender_allowlist?: readonly string[];
  };
  /** Behavioral monitoring configuration for ASI-10 checks. */
  readonly behavioral_monitoring?: {
    readonly enabled: boolean;
    readonly baseline_established?: boolean;
    readonly drift_alerts?: boolean;
  };
}

/** Declaration of a single tool with its argument schema. */
export interface AgentToolDeclaration {
  /** Name of the tool. */
  readonly name: string;
  /** JSON Schema object describing the tool's arguments. */
  readonly schema?: Readonly<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// Validation result
// ---------------------------------------------------------------------------

/**
 * Result of validating a tool or input against defense rules.
 */
export interface ValidationResult {
  /** Whether the validated item passes all checks. */
  readonly valid: boolean;
  /** Whether the item should be blocked from execution. */
  readonly blocked: boolean;
  /** List of detected threats, if any. */
  readonly threats: readonly ThreatDetection[];
  /** Human-readable summary of the validation outcome. */
  readonly summary: string;
}

// ---------------------------------------------------------------------------
// Compliance report
// ---------------------------------------------------------------------------

/**
 * A compliance report summarising the defense posture of an agent.
 */
export interface ComplianceReport {
  /** Identifier of the agent that was assessed. */
  readonly agent_id: string;
  /** ISO-8601 UTC timestamp of report generation. */
  readonly generated_at: string;
  /** Overall compliance status across all categories. */
  readonly overall_status: "compliant" | "partial" | "non_compliant";
  /** Overall security score (0–100). */
  readonly score: number;
  /** Letter grade (A–F). */
  readonly grade: "A" | "B" | "C" | "D" | "F";
  /** Per-category compliance breakdown. */
  readonly categories: readonly CategoryResult[];
  /** Total number of findings across all categories. */
  readonly total_findings: number;
  /** Total number of recommendations across all categories. */
  readonly total_recommendations: number;
}

// ---------------------------------------------------------------------------
// API request types
// ---------------------------------------------------------------------------

/** Request to scan an agent's input payload. */
export interface ScanInputRequest {
  /** The input text or payload to scan. */
  readonly input: string;
  /** Agent identifier for context. */
  readonly agent_id: string;
  /** Optional tool name if the input is a tool argument. */
  readonly tool_name?: string;
}

/** Request to scan an agent's output payload. */
export interface ScanOutputRequest {
  /** The output text or payload to scan. */
  readonly output: string;
  /** Agent identifier for context. */
  readonly agent_id: string;
  /** Optional tool name if the output is a tool result. */
  readonly tool_name?: string;
}

// ---------------------------------------------------------------------------
// API result wrapper
// ---------------------------------------------------------------------------

/** Standard error payload returned by the OWASP defenses API. */
export interface ApiError {
  readonly error: string;
  readonly detail: string;
}

/** Result type for all client operations. */
export type ApiResult<T> =
  | { readonly ok: true; readonly data: T }
  | { readonly ok: false; readonly error: ApiError; readonly status: number };
