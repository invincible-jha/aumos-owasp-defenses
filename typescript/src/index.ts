/**
 * @aumos/owasp-defenses
 *
 * TypeScript client for the AumOS OWASP ASI Top 10 defensive library.
 * Provides HTTP client and security type definitions for agent input/output
 * scanning, threat detection, tool validation, and compliance reporting.
 */

// Client and configuration
export type { OwaspDefensesClient, OwaspDefensesClientConfig } from "./client.js";
export { createOwaspDefensesClient } from "./client.js";

// Core types
export type {
  DefenseCategory,
  ScanProfile,
  CategoryResult,
  ScanResult,
  ThreatDetection,
  DefenseConfig,
  AgentToolDeclaration,
  ValidationResult,
  ComplianceReport,
  ScanInputRequest,
  ScanOutputRequest,
  ApiError,
  ApiResult,
} from "./types.js";
