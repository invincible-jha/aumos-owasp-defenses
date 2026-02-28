/**
 * HTTP client for the AumOS OWASP ASI Top 10 defensive library API.
 *
 * Uses the Fetch API (available natively in Node 18+, browsers, and Deno).
 * No external dependencies required.
 *
 * @example
 * ```ts
 * import { createOwaspDefensesClient } from "@aumos/owasp-defenses";
 *
 * const client = createOwaspDefensesClient({ baseUrl: "http://localhost:8093" });
 *
 * const result = await client.scanInput({
 *   input: "Tell me how to access /etc/passwd",
 *   agent_id: "my-agent",
 * });
 *
 * if (result.ok && result.data.blocked) {
 *   console.log("Threat detected:", result.data.threats);
 * }
 * ```
 */

import type {
  ApiError,
  ApiResult,
  ComplianceReport,
  DefenseConfig,
  ScanInputRequest,
  ScanOutputRequest,
  ScanResult,
  ValidationResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// Client configuration
// ---------------------------------------------------------------------------

/** Configuration options for the OwaspDefensesClient. */
export interface OwaspDefensesClientConfig {
  /** Base URL of the OWASP defenses server (e.g. "http://localhost:8093"). */
  readonly baseUrl: string;
  /** Optional request timeout in milliseconds (default: 30000). */
  readonly timeoutMs?: number;
  /** Optional extra HTTP headers sent with every request. */
  readonly headers?: Readonly<Record<string, string>>;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function fetchJson<T>(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<ApiResult<T>> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    clearTimeout(timeoutId);

    const body = await response.json() as unknown;

    if (!response.ok) {
      const errorBody = body as Partial<ApiError>;
      return {
        ok: false,
        error: {
          error: errorBody.error ?? "Unknown error",
          detail: errorBody.detail ?? "",
        },
        status: response.status,
      };
    }

    return { ok: true, data: body as T };
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      error: { error: "Network error", detail: message },
      status: 0,
    };
  }
}

function buildHeaders(
  extraHeaders: Readonly<Record<string, string>> | undefined,
): Record<string, string> {
  return {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...extraHeaders,
  };
}

// ---------------------------------------------------------------------------
// Client interface
// ---------------------------------------------------------------------------

/** Typed HTTP client for the OWASP defenses server. */
export interface OwaspDefensesClient {
  /**
   * Scan an agent's input payload for security threats.
   *
   * Evaluates the input against all relevant ASI defense categories
   * and returns detected threats along with a blocking decision.
   *
   * @param request - The input payload and agent context.
   * @returns A ValidationResult with threat detections and blocking decision.
   */
  scanInput(request: ScanInputRequest): Promise<ApiResult<ValidationResult>>;

  /**
   * Scan an agent's output payload for security issues.
   *
   * Evaluates the output for data exfiltration, PII leakage, and
   * other output-side ASI violations.
   *
   * @param request - The output payload and agent context.
   * @returns A ValidationResult with threat detections and blocking decision.
   */
  scanOutput(request: ScanOutputRequest): Promise<ApiResult<ValidationResult>>;

  /**
   * Retrieve the current defense status for a configured agent.
   *
   * Returns a full ScanResult representing the agent's current
   * defense posture based on its declared configuration.
   *
   * @param agentId - The agent identifier to inspect.
   * @returns A ScanResult with per-category scores and grades.
   */
  getDefenseStatus(agentId: string): Promise<ApiResult<ScanResult>>;

  /**
   * Validate an agent tool declaration against security rules.
   *
   * Checks whether the tool's schema, name, and configuration
   * conform to ASI-02 (Tool and Resource Misuse) requirements.
   *
   * @param agentId - The agent that owns the tool.
   * @param toolName - The name of the tool to validate.
   * @param toolSchema - The tool's argument schema (JSON Schema object).
   * @returns A ValidationResult for the tool declaration.
   */
  validateTool(
    agentId: string,
    toolName: string,
    toolSchema: Readonly<Record<string, unknown>>,
  ): Promise<ApiResult<ValidationResult>>;

  /**
   * Generate a compliance report for an agent based on its defense configuration.
   *
   * Runs the full scan profile against the supplied DefenseConfig and
   * returns a structured compliance report.
   *
   * @param config - The agent defense configuration to evaluate.
   * @returns A ComplianceReport with overall status, score, and per-category details.
   */
  getComplianceReport(config: DefenseConfig): Promise<ApiResult<ComplianceReport>>;

  /**
   * Register or update an agent's defense configuration on the server.
   *
   * @param config - The defense configuration to register.
   * @returns The registered DefenseConfig as confirmed by the server.
   */
  registerConfig(config: DefenseConfig): Promise<ApiResult<DefenseConfig>>;
}

// ---------------------------------------------------------------------------
// Client factory
// ---------------------------------------------------------------------------

/**
 * Create a typed HTTP client for the OWASP defenses server.
 *
 * @param config - Client configuration including base URL.
 * @returns An OwaspDefensesClient instance.
 */
export function createOwaspDefensesClient(
  config: OwaspDefensesClientConfig,
): OwaspDefensesClient {
  const { baseUrl, timeoutMs = 30_000, headers: extraHeaders } = config;
  const baseHeaders = buildHeaders(extraHeaders);

  return {
    async scanInput(
      request: ScanInputRequest,
    ): Promise<ApiResult<ValidationResult>> {
      return fetchJson<ValidationResult>(
        `${baseUrl}/scan/input`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify(request),
        },
        timeoutMs,
      );
    },

    async scanOutput(
      request: ScanOutputRequest,
    ): Promise<ApiResult<ValidationResult>> {
      return fetchJson<ValidationResult>(
        `${baseUrl}/scan/output`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify(request),
        },
        timeoutMs,
      );
    },

    async getDefenseStatus(agentId: string): Promise<ApiResult<ScanResult>> {
      return fetchJson<ScanResult>(
        `${baseUrl}/agents/${encodeURIComponent(agentId)}/status`,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async validateTool(
      agentId: string,
      toolName: string,
      toolSchema: Readonly<Record<string, unknown>>,
    ): Promise<ApiResult<ValidationResult>> {
      return fetchJson<ValidationResult>(
        `${baseUrl}/tools/validate`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify({ agent_id: agentId, tool_name: toolName, schema: toolSchema }),
        },
        timeoutMs,
      );
    },

    async getComplianceReport(
      config: DefenseConfig,
    ): Promise<ApiResult<ComplianceReport>> {
      return fetchJson<ComplianceReport>(
        `${baseUrl}/compliance/report`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify(config),
        },
        timeoutMs,
      );
    },

    async registerConfig(
      config: DefenseConfig,
    ): Promise<ApiResult<DefenseConfig>> {
      return fetchJson<DefenseConfig>(
        `${baseUrl}/agents/${encodeURIComponent(config.agent_id)}/config`,
        {
          method: "PUT",
          headers: baseHeaders,
          body: JSON.stringify(config),
        },
        timeoutMs,
      );
    },
  };
}

