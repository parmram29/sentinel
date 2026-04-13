import { AuditResult } from "../types";

export function exportReport(auditResult: AuditResult | null) {
  if (!auditResult) return;

  let md = `# CompTIA Sentinel - Remediation Sheet\n\n`;
  md += `**Audit Trail ID:** ${auditResult.managementSummary.auditTrailId}\n`;
  md += `**Compliance Status:** ${auditResult.managementSummary.complianceStatus}\n`;
  md += `**Legal Jurisdiction:** ${auditResult.managementSummary.legalJurisdiction}\n`;
  md += `**Executive Action Required:** ${auditResult.managementSummary.executiveActionRequired}\n\n`;
  md += `---\n\n`;

  if (auditResult.isSecure) {
    md += `## Scan Complete\nNo violations of Security+ or Cloud+ standards detected in the provided payload.\n`;
  } else {
    md += `## Detected Vulnerabilities\n\n`;
    auditResult.findings.forEach((f, idx) => {
      md += `### ${idx + 1}. ${f.finding}\n`;
      md += `- **Domain:** ${f.domain}\n`;
      md += `- **Severity:** ${f.severity}\n\n`;

      if (f.affectedCode) {
        md += `**Affected Code / Log Snippet:**\n\`\`\`\n${f.affectedCode}\n\`\`\`\n\n`;
      }

      md += `**Remediation Summary:**\n${f.remediation}\n\n`;

      if (f.detailedSteps && f.detailedSteps.length > 0) {
        md += `**Step-by-Step Fix:**\n`;
        f.detailedSteps.forEach((step, stepIdx) => {
          md += `${stepIdx + 1}. ${step}\n`;
        });
        md += `\n`;
      }
      md += `---\n\n`;
    });
  }

  if (
    auditResult.seniorDeveloperTips &&
    auditResult.seniorDeveloperTips.length > 0
  ) {
    md += `## Senior Developer Tips & Tricks\n\n`;
    auditResult.seniorDeveloperTips.forEach((tip, idx) => {
      md += `- 💡 ${tip}\n`;
    });
    md += `\n---\n\n`;
  }

  const blob = new Blob([md], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `Sentinel_Remediation_Sheet_${auditResult.managementSummary.auditTrailId}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
