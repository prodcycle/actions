// =============================================================================
// ProdCycle Compliance Code Scanner: Shared Types
// =============================================================================

/** Action inputs parsed from action.yml */
export interface ActionInputs {
  apiKey: string;
  apiUrl: string;
  frameworks: string[];
  failOn: string[];
  severityThreshold: string;
  include: string[];
  exclude: string[];
  scanMode: "auto" | "diff" | "full";
  annotate: boolean;
  comment: boolean;
  /**
   * Resolved PR review behavior. `"none"` skips posting a review.
   * `"auto"` means: COMMENT when passed, REQUEST_CHANGES when failed.
   */
  reviewEvent: "auto" | "comment" | "request-changes" | "none";
  excludeAcceptedRisk: boolean;
}

/** A single changed file with its content */
export interface ChangedFile {
  path: string;
  content: string;
  /** Unified diff for the file (only in diff scan mode) */
  diff?: string;
}

// -- API request/response types matching ProdCycle /v1/compliance/validate --

export interface ValidateRequest {
  files: Record<string, string>;
  /** When present, the API receives diffs instead of full file contents */
  diffs?: Record<string, string>;
  frameworks?: string[];
  /** GitHub username of the user who opened the PR */
  actor?: string;
  options?: {
    severity_threshold?: string;
    fail_on?: string[];
    include_prompt?: boolean;
    exclude_accepted_risk?: boolean;
  };
}

export interface ValidateResponse {
  passed: boolean;
  findingsCount: number;
  findings: ScanFinding[];
  prompt?: string;
  summary: ValidateSummary;
  scanId: string;
}

export interface ScanFinding {
  /** Rule ID — mapped from controlId if not present in API response */
  ruleId: string;
  controlId: string;
  severity: string;
  confidence: string;
  engine: string;
  framework: string;
  resourceType: string;
  resourcePath: string;
  resourceName: string;
  startLine: number;
  endLine: number;
  /** API returns `line` — mapped to `startLine` during deserialization */
  line?: number | null;
  message: string;
  remediation: string;
}

export interface ValidateSummary {
  total: number;
  passed: number;
  failed: number;
  bySeverity: Record<string, number>;
  byFramework: Record<string, number>;
}

/** Standard ProdCycle API envelope */
export interface ApiResponse<T> {
  status: "success" | "error";
  statusCode: number;
  data?: T;
  error?: {
    type: string;
    message: string;
    details?: unknown;
  };
}
