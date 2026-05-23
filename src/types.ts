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
  /**
   * Who PR comments are authored by.
   * - `auto`: post as prodcycle[bot] when the ProdCycle App token is
   *   available, otherwise github-actions[bot].
   * - `app`: require the ProdCycle App identity (warn + fall back if missing).
   * - `github-token`: always github-actions[bot].
   */
  commentIdentity: "auto" | "app" | "github-token";
  /**
   * ProdCycle product the repo maps to. When set, the scan respects findings
   * accepted-as-risk (and, with excludeResolved, resolved) for that product.
   * Either productId or syncConfigId identifies the product server-side.
   */
  productId?: string;
  syncConfigId?: string;
  /**
   * Also suppress findings marked RESOLVED in ProdCycle (opt-in). Requires a
   * product to be identified (productId/syncConfigId). Accepted-risk is always
   * respected; this extends suppression to manually-resolved findings.
   */
  excludeResolved: boolean;
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
  frameworks?: string[];
  /** ProdCycle product association (drives accepted-risk/resolved filtering) */
  product_id?: string;
  sync_config_id?: string;
  options?: {
    severity_threshold?: string;
    fail_on?: string[];
    include_prompt?: boolean;
    exclude_accepted_risk?: boolean;
    exclude_resolved?: boolean;
    /**
     * Whether the server should reconcile this scan against the product's prior
     * scan. The action sends `false` for partial (diff) scans so unchanged-file
     * findings aren't wrongly marked resolved; `true` for full-repo scans.
     */
    reconcile?: boolean;
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
  /**
   * When true, the finding is informational and does NOT block the scan
   * (the API excludes it from `summary.failed` and the pass/fail verdict).
   * Surfaced as a notice, never as a blocking error / request-changes.
   */
  advisory?: boolean;
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
