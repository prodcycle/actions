// =============================================================================
// ProdCycle Compliance Code Scanner — Shared Types
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
  annotate: boolean;
  comment: boolean;
}

/** A single changed file with its content */
export interface ChangedFile {
  path: string;
  content: string;
}

// -- API request/response types matching ProdCycle /v1/compliance/validate --

export interface ValidateRequest {
  files: Record<string, string>;
  frameworks?: string[];
  options?: {
    severity_threshold?: string;
    fail_on?: string[];
    include_prompt?: boolean;
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
  ruleId: string;
  controlId: string;
  severity: string;
  confidence: string;
  engine: string;
  framework: string;
  resourceType: string;
  resourcePath: string;
  resourceName: string;
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
