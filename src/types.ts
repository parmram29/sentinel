export interface Finding {
  finding: string;
  domain: string;
  severity: string;
  remediation: string;
  affectedCode?: string;
  detailedSteps?: string[];
}

export interface ManagementSummary {
  complianceStatus: string;
  legalJurisdiction: string;
  executiveActionRequired: string;
  auditTrailId: string;
}

export interface AuditResult {
  isSecure: boolean;
  Secure: boolean;
  findings: Finding[];
  seniorDeveloperTips: string[];
  managementSummary: ManagementSummary;
}

export interface CliExecutionResult {
  stdout: string;
  stderr: string;
  error: string | null;
}

export interface HistoryEntry {
  id: string;
  timestamp: number;
  trailId: string;
  complianceStatus: string;
  isSecure: boolean;
  findingCount: number;
  inputSummary: string;
  result: AuditResult;
}
