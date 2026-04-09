import { AuditResult, CliExecutionResult } from '../types';
import { SYSTEM_INSTRUCTION, AUDIT_RESPONSE_SCHEMA } from '../constants';

/**
 * Sends the user's code/logs to the backend for AI auditing.
 * @param inputCode The raw text payload to be analyzed.
 * @returns A Promise that resolves to the AuditResult object.
 */
export async function performAudit(inputCode: string): Promise<AuditResult> {
  if (!inputCode) {
    throw new Error("No input code provided.");
  }

  try {
    const response = await fetch('/api/audit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        inputCode,
        systemInstruction: SYSTEM_INSTRUCTION,
        responseSchema: AUDIT_RESPONSE_SCHEMA,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || "Failed to perform audit.");
    }

    return response.json();
  } catch (error: any) {
    console.error("Audit Error:", error);
    throw new Error(error.message || "An error occurred during the audit.");
  }
}

/**
 * Fetches a public URL and extracts its HTML/JS content for auditing.
 */
export async function fetchUrlContent(url: string): Promise<{ content: string; scriptCount: number; url: string }> {
  const response = await fetch('/api/url-scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error || "Failed to fetch URL.");
  }
  return response.json();
}

/**
 * Sends a shell command to the backend to be executed on the container.
 * @param command The shell command to run (e.g., 'npm audit').
 * @returns A Promise that resolves to the CliExecutionResult object containing stdout/stderr.
 */
export async function executeCliCommand(command: string): Promise<CliExecutionResult> {
  const response = await fetch('/api/execute', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ command }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || "Failed to execute command.");
  }

  return response.json();
}
