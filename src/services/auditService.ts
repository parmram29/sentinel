import { AuditResult, CliExecutionResult } from '../types';
import { supabase } from '../lib/supabase';


async function getAuthHeader(): Promise<Record<string, string>> {
  const { data: { session } } = await supabase.auth.getSession();
  if (!session?.access_token) return {};
  return { 'Authorization': `Bearer ${session.access_token}` };
}

export async function performAudit(inputCode: string): Promise<AuditResult> {
  if (!inputCode) throw new Error("No input code provided.");

  const authHeader = await getAuthHeader();
  const response = await fetch('/api/audit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeader },
    body: JSON.stringify({ inputCode }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || "Failed to perform audit.");
  }
  return response.json();
}

export async function fetchUrlContent(url: string): Promise<{ content: string; scriptCount: number; url: string }> {
  const authHeader = await getAuthHeader();
  const response = await fetch('/api/url-scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeader },
    body: JSON.stringify({ url }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error || "Failed to fetch URL.");
  }
  return response.json();
}

export async function executeCliCommand(command: string): Promise<CliExecutionResult> {
  const authHeader = await getAuthHeader();
  const response = await fetch('/api/execute', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeader },
    body: JSON.stringify({ command }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || "Failed to execute command.");
  }
  return response.json();
}
