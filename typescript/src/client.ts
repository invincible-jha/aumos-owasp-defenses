/**
 * HTTP client for the AumOS OWASP ASI Top 10 defensive library API.
 *
 * Delegates all HTTP transport to `@aumos/sdk-core` which provides
 * automatic retry with exponential back-off, timeout management via
 * `AbortSignal.timeout`, interceptor support, and a typed error hierarchy.
 *
 * The public-facing `ApiResult<T>` envelope is preserved for full
 * backward compatibility with existing callers.
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

import {
  createHttpClient,
  HttpError,
  NetworkError,
  TimeoutError,
  AumosError,
  type HttpClient,
} from "@aumos/sdk-core";

import type {
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
// Internal adapter
// ---------------------------------------------------------------------------

async function callApi<T>(
  operation: () => Promise<{ readonly data: T; readonly status: number }>,
): Promise<ApiResult<T>> {
  try {
    const response = await operation();
    return { ok: true, data: response.data };
  } catch (error: unknown) {
    if (error instanceof HttpError) {
      return {
        ok: false,
        error: { error: error.message, detail: String(error.body ?? "") },
        status: error.statusCode,
      };
    }
    if (error instanceof TimeoutError) {
      return {
        ok: false,
        error: { error: "Request timed out", detail: error.message },
        status: 0,
      };
    }
    if (error instanceof NetworkError) {
      return {
        ok: false,
        error: { error: "Network error", detail: error.message },
        status: 0,
      };
    }
    if (error instanceof AumosError) {
      return {
        ok: false,
        error: { error: error.code, detail: error.message },
        status: error.statusCode ?? 0,
      };
    }
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      error: { error: "Unexpected error", detail: message },
      status: 0,
    };
  }
}

// ---------------------------------------------------------------------------
// Client interface
// ---------------------------------------------------------------------------

/** Typed HTTP client for the OWASP defenses server. */
export interface OwaspDefensesClient {
  /**
   * Scan an agent's input payload for security threats.
   *
   * @param request - The input payload and agent context.
   * @returns A ValidationResult with threat detections and blocking decision.
   */
  scanInput(request: ScanInputRequest): Promise<ApiResult<ValidationResult>>;

  /**
   * Scan an agent's output payload for security issues.
   *
   * @param request - The output payload and agent context.
   * @returns A ValidationResult with threat detections and blocking decision.
   */
  scanOutput(request: ScanOutputRequest): Promise<ApiResult<ValidationResult>>;

  /**
   * Retrieve the current defense status for a configured agent.
   *
   * @param agentId - The agent identifier to inspect.
   * @returns A ScanResult with per-category scores and grades.
   */
  getDefenseStatus(agentId: string): Promise<ApiResult<ScanResult>>;

  /**
   * Validate an agent tool declaration against security rules.
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
  const http: HttpClient = createHttpClient({
    baseUrl: config.baseUrl,
    timeout: config.timeoutMs ?? 30_000,
    defaultHeaders: config.headers,
  });

  return {
    scanInput(request: ScanInputRequest): Promise<ApiResult<ValidationResult>> {
      return callApi(() => http.post<ValidationResult>("/scan/input", request));
    },

    scanOutput(request: ScanOutputRequest): Promise<ApiResult<ValidationResult>> {
      return callApi(() => http.post<ValidationResult>("/scan/output", request));
    },

    getDefenseStatus(agentId: string): Promise<ApiResult<ScanResult>> {
      return callApi(() =>
        http.get<ScanResult>(`/agents/${encodeURIComponent(agentId)}/status`),
      );
    },

    validateTool(
      agentId: string,
      toolName: string,
      toolSchema: Readonly<Record<string, unknown>>,
    ): Promise<ApiResult<ValidationResult>> {
      return callApi(() =>
        http.post<ValidationResult>("/tools/validate", {
          agent_id: agentId,
          tool_name: toolName,
          schema: toolSchema,
        }),
      );
    },

    getComplianceReport(config: DefenseConfig): Promise<ApiResult<ComplianceReport>> {
      return callApi(() =>
        http.post<ComplianceReport>("/compliance/report", config),
      );
    },

    registerConfig(config: DefenseConfig): Promise<ApiResult<DefenseConfig>> {
      return callApi(() =>
        http.put<DefenseConfig>(
          `/agents/${encodeURIComponent(config.agent_id)}/config`,
          config,
        ),
      );
    },
  };
}
