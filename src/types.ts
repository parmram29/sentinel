export interface Finding {
  /** The title or short description of the vulnerability found. */
  finding: string;
  /** The specific CompTIA domain this finding relates to (e.g., Sec+ 3.2). */
  domain: string;
  /** The severity level (e.g., Low, Medium, High, Critical). */
  severity: string;
  /** A brief summary of how to fix the vulnerability. */
  remediation: string;
  /** The exact snippet of code or log entry that triggered this finding. */
  affectedCode?: string;
  /** Step-by-step instructions to fix the issue. Required for High/Critical severity. */
  detailedSteps?: string[];
}

export interface ManagementSummary {
  /** Overall compliance status (e.g., Pass/Fail). */
  complianceStatus: string;
  /** The legal jurisdiction applied (e.g., EU, California, Global). */
  legalJurisdiction: string;
  /** Whether executive action is required (Yes/No) and why. */
  executiveActionRequired: string;
  /** A unique auto-generated hash for the audit trail. */
  auditTrailId: string;
}

export interface AuditResult {
  /** Indicates if the payload is entirely secure with no findings. */
  isSecure: boolean;
  /** Legacy field for backwards compatibility. */
  Secure: boolean;
  /** A list of all vulnerabilities found during the audit. */
  findings: Finding[];
  /** Advanced tips, tricks, and best practices from a senior developer perspective. */
  seniorDeveloperTips: string[];
  /** The management workflow output summary. */
  managementSummary: ManagementSummary;
}

export interface CliExecutionResult {
  /** Standard output from the CLI command. */
  stdout: string;
  /** Standard error output from the CLI command. */
  stderr: string;
  /** Any system-level error message if the command failed to execute. */
  error: string | null;
}
// TypeScript interfaces for the CompTIA Sentinel application 