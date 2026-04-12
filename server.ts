import express, { Request, Response, NextFunction } from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { exec } from "child_process";
import { promisify } from "util";
import crypto from "crypto";
import Anthropic from "@anthropic-ai/sdk";
import { createClient } from "@supabase/supabase-js";

const execAsync = promisify(exec);

// ============================================================
// SUPABASE ADMIN CLIENT — JWT verification
// ============================================================
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

// ============================================================
// SIEM — STRUCTURED SECURITY EVENT LOGGER
// ============================================================
type Severity = "INFO" | "WARN" | "HIGH" | "CRITICAL";

interface SecurityEvent {
  ts: string;
  severity: Severity;
  event: string;
  ip: string;
  rid: string;
  details?: Record<string, unknown>;
}

const eventLog: SecurityEvent[] = [];
const MAX_LOG = 5_000;

function siem(severity: Severity, event: string, ip: string, rid: string, details?: Record<string, unknown>) {
  const entry: SecurityEvent = { ts: new Date().toISOString(), severity, event, ip, rid, details };
  if (eventLog.length >= MAX_LOG) eventLog.shift();
  eventLog.push(entry);
  const icon = severity === "CRITICAL" ? "🚨" : severity === "HIGH" ? "⚠️" : severity === "WARN" ? "⚡" : "ℹ️";
  console.log(`${icon} [SIEM] ${JSON.stringify(entry)}`);
}

// ============================================================
// IP REPUTATION ENGINE
// ============================================================
const blockedIPs = new Map<string, { reason: string; at: number }>();
const strikeMap = new Map<string, number>();
const STRIKE_LIMIT = 3;
const BLOCK_TTL = 60 * 60 * 1_000;

function blockIP(ip: string, reason: string, rid: string) {
  blockedIPs.set(ip, { reason, at: Date.now() });
  strikeMap.delete(ip);
  siem("CRITICAL", "IP_BLOCKED", ip, rid, { reason });
}

function strike(ip: string, reason: string, rid: string) {
  const n = (strikeMap.get(ip) ?? 0) + 1;
  strikeMap.set(ip, n);
  siem("HIGH", "STRIKE", ip, rid, { reason, strikes: n, threshold: STRIKE_LIMIT });
  if (n >= STRIKE_LIMIT) blockIP(ip, `Auto-blocked: ${reason} (${n} strikes)`, rid);
}

function isBlocked(ip: string): boolean {
  const b = blockedIPs.get(ip);
  if (!b) return false;
  if (Date.now() - b.at > BLOCK_TTL) { blockedIPs.delete(ip); return false; }
  return true;
}

// ============================================================
// CROWDSEC — Crowd-sourced IP threat intelligence
// ============================================================
const crowdSecCache = new Map<string, { blocked: boolean; at: number }>();
const CROWDSEC_CACHE_TTL = 60 * 60 * 1_000;

async function crowdSecCheck(ip: string, rid: string): Promise<boolean> {
  const cached = crowdSecCache.get(ip);
  if (cached && Date.now() - cached.at < CROWDSEC_CACHE_TTL) return cached.blocked;

  const apiKey = process.env.CROWDSEC_API_KEY;
  if (!apiKey) return false;

  try {
    const res = await fetch(`https://cti.api.crowdsec.net/v2/smoke/${ip}`, {
      headers: { "X-Api-Key": apiKey, "User-Agent": "Sentinel-Lite/2.0" },
    });
    if (!res.ok) return false;
    const data = await res.json();
    const blocked = data.reputation === "malicious" || data.reputation === "suspicious";
    crowdSecCache.set(ip, { blocked, at: Date.now() });
    if (blocked) siem("HIGH", "CROWDSEC_BLOCK", ip, rid, { reputation: data.reputation, scores: data.scores });
    return blocked;
  } catch {
    return false;
  }
}

// ============================================================
// REQUEST ID MIDDLEWARE
// ============================================================
function attachRequestId(req: Request, res: Response, next: NextFunction) {
  const rid = crypto.randomUUID();
  (req as any).rid = rid;
  res.setHeader("X-Request-Id", rid);
  next();
}

function getRid(req: Request): string { return (req as any).rid ?? "no-rid"; }
function getIP(req: Request): string {
  return (req.ip ?? req.socket.remoteAddress ?? "unknown").replace(/^::ffff:/, "");
}

// ============================================================
// IP GUARD — with CrowdSec integration
// ============================================================
async function ipGuard(req: Request, res: Response, next: NextFunction) {
  const ip = getIP(req);
  const rid = getRid(req);
  if (isBlocked(ip)) {
    siem("WARN", "BLOCKED_IP_HIT", ip, rid, { path: req.path, method: req.method });
    return res.status(403).json({ error: "Access denied." });
  }
  const crowdBlocked = await crowdSecCheck(ip, rid);
  if (crowdBlocked) {
    blockIP(ip, "CrowdSec: malicious/suspicious reputation", rid);
    return res.status(403).json({ error: "Access denied." });
  }
  next();
}

// ============================================================
// SCANNER USER-AGENT FILTER
// ============================================================
const SCANNER_UA = /sqlmap|nikto|nmap|masscan|dirsearch|gobuster|wfuzz|burpsuite|zgrab|nuclei|python-requests\/2\.[01]/i;

function uaGuard(req: Request, res: Response, next: NextFunction) {
  const ua = req.headers["user-agent"] ?? "";
  if (SCANNER_UA.test(ua)) {
    const ip = getIP(req);
    blockIP(ip, `Scanner UA: ${ua.slice(0, 80)}`, getRid(req));
    return res.status(403).json({ error: "Access denied." });
  }
  next();
}

// ============================================================
// RATE LIMITER
// ============================================================
const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

function rateLimit(maxRequests: number, windowMs: number) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = getIP(req);
    const now = Date.now();
    const record = rateLimitStore.get(ip);
    if (!record || now > record.resetAt) {
      rateLimitStore.set(ip, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (record.count >= maxRequests) {
      strike(ip, "RateLimit exceeded", getRid(req));
      res.setHeader("Retry-After", Math.ceil((record.resetAt - now) / 1000).toString());
      return res.status(429).json({ error: "Rate limit exceeded. Please wait before retrying." });
    }
    record.count++;
    next();
  };
}

// ============================================================
// SUPABASE JWT VERIFICATION
// ============================================================
async function verifySupabaseToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authentication required." });
  }
  const token = authHeader.slice(7);
  const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !user) {
    strike(getIP(req), "Invalid auth token", getRid(req));
    return res.status(401).json({ error: "Invalid or expired session." });
  }
  (req as any).user = user;
  next();
}

// ============================================================
// COMMAND ALLOWLIST
// ============================================================
const ALLOWED_COMMANDS: readonly string[] = [
  "npm audit", "npm audit --json", "npm outdated", "npx snyk test",
  "pip-audit", "pip-audit --json", "bandit -r .", "semgrep --config auto .",
  "trivy fs .", "git log --oneline -20", "git diff HEAD",
  "cat package.json", "cat requirements.txt", "cat pyproject.toml",
  "cat Pipfile", "cat Gemfile", "cat go.sum", "cat go.mod", "ls -la", "ls",
];

function isCommandAllowed(command: string): boolean {
  const t = command.trim();
  return ALLOWED_COMMANDS.some((a) => t === a || t.startsWith(a + " "));
}

// ============================================================
// ANOMALY SCANNER
// ============================================================
const THREAT_SIGNATURES: { label: string; pattern: RegExp }[] = [
  { label: "SQLi",              pattern: /(\bUNION\b.{0,20}\bSELECT\b|\bDROP\b.{0,10}\bTABLE\b)/i },
  { label: "XSS",               pattern: /<script[\s\S]*?>[\s\S]*?<\/script>/i },
  { label: "PathTraversal",     pattern: /\.\.[/\\]/ },
  { label: "TemplateInjection", pattern: /\$\{[\s\S]{0,80}\}|#\{[\s\S]{0,80}\}/ },
  { label: "SSRF",              pattern: /(wget|curl)\s+https?:\/\//i },
  { label: "CodeInjection",     pattern: /\b(eval|exec|system|passthru|shell_exec)\s*\(/i },
  { label: "XXE",               pattern: /<!ENTITY\s/i },
  { label: "LDAP_Injection",    pattern: /[)(|*\\].*(?:uid|cn|dc)=/i },
];

function scanForThreats(payload: string): string[] {
  return THREAT_SIGNATURES.filter(({ pattern }) => pattern.test(payload)).map(({ label }) => label);
}

// ============================================================
// CIRCUIT BREAKER
// ============================================================
type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";
const circuit = { failures: 0, lastFailure: 0, state: "CLOSED" as CircuitState };
const CB_THRESHOLD = 3;
const CB_RESET_MS = 30_000;

function circuitAllow(): boolean {
  if (circuit.state === "CLOSED" || circuit.state === "HALF_OPEN") return true;
  if (Date.now() - circuit.lastFailure > CB_RESET_MS) { circuit.state = "HALF_OPEN"; return true; }
  return false;
}
function circuitSuccess() { circuit.failures = 0; circuit.state = "CLOSED"; }
function circuitFailure() {
  circuit.failures++;
  circuit.lastFailure = Date.now();
  if (circuit.failures >= CB_THRESHOLD) {
    circuit.state = "OPEN";
    console.error("[Sentinel] ⚡ Circuit OPEN — Claude API degraded. Auto-recovery in 30s.");
  }
}

// ============================================================
// SECURITY HEADERS
// ============================================================
function securityHeaders(_req: Request, res: Response, next: NextFunction) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Content-Security-Policy",
    ["default-src 'self'", "script-src 'self' 'unsafe-inline'", "style-src 'self' 'unsafe-inline'",
     "img-src 'self' data:", "connect-src 'self' https://*.supabase.co", "font-src 'self'",
     "object-src 'none'", "base-uri 'self'", "form-action 'self'", "frame-ancestors 'none'",
     "upgrade-insecure-requests"].join("; "));
  res.removeHeader("X-Powered-By");
  next();
}

// ============================================================
// CORS
// ============================================================
const ALLOWED_ORIGINS = new Set(["http://localhost:3000", "http://127.0.0.1:3000", ...(process.env.ALLOWED_ORIGIN ? [process.env.ALLOWED_ORIGIN] : [])]);

function corsMiddleware(req: Request, res: Response, next: NextFunction) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Max-Age", "86400");
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
}

// ============================================================
// HONEYPOT PATHS
// ============================================================
const HONEYPOT_PATHS = new Set([
  "/admin", "/admin/", "/admin/login",
  "/.env", "/.env.local", "/.env.production",
  "/.git/config", "/.git/HEAD",
  "/config", "/config.json", "/config.yml",
  "/wp-admin", "/wp-login.php", "/wp-config.php",
  "/phpmyadmin", "/pma", "/mysql",
  "/api/keys", "/api/credentials", "/api/tokens",
  "/api/admin", "/api/users", "/api/debug",
  "/api/config", "/api/env", "/api/secrets",
  "/actuator", "/actuator/env", "/actuator/health",
  "/console", "/h2-console",
  "/server-status", "/server-info",
  "/api/v1/admin", "/api/v2/admin",
  "/passwords.txt", "/secrets.txt", "/backup.sql",
  "/debug", "/trace", "/metrics",
]);

// ============================================================
// SERVER
// ============================================================
async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;

  app.set("trust proxy", 1);
  app.use(attachRequestId);
  app.use(securityHeaders);
  app.use(corsMiddleware);
  app.use(ipGuard);
  app.use(uaGuard);
  app.use(express.json({ limit: "5mb" }));

  // HONEYPOT TRAP
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (!HONEYPOT_PATHS.has(req.path)) return next();
    const ip = getIP(req);
    const rid = getRid(req);
    blockIP(ip, `Honeypot: ${req.path}`, rid);
    siem("CRITICAL", "HONEYPOT_HIT", ip, rid, {
      path: req.path, method: req.method,
      ua: req.headers["user-agent"]?.slice(0, 120),
    });
    res.status(200).json({
      status: "ok",
      _token: crypto.randomBytes(32).toString("hex"),
      _note: "This endpoint is monitored.",
    });
  });

  // POST /api/audit — requires auth
  app.post("/api/audit", rateLimit(10, 60_000), verifySupabaseToken, async (req: Request, res: Response) => {
    const ip = getIP(req);
    const rid = getRid(req);
    try {
      const { inputCode, systemInstruction, responseSchema } = req.body;

      if (!inputCode || typeof inputCode !== "string")
        return res.status(400).json({ error: "Input code is required." });
      if (inputCode.length > 500_000)
        return res.status(413).json({ error: "Payload exceeds 500,000 character limit." });
      if (typeof systemInstruction !== "string" || !systemInstruction)
        return res.status(400).json({ error: "System instruction is missing." });

      const threats = scanForThreats(inputCode);
      if (threats.length > 0)
        siem("WARN", "SUSPICIOUS_PAYLOAD", ip, rid, { threats, payloadLength: inputCode.length });

      if (!circuitAllow()) {
        siem("HIGH", "CIRCUIT_OPEN_REJECT", ip, rid, {});
        return res.status(503).json({ error: "Audit service temporarily unavailable. Please retry in 30 seconds." });
      }

      const apiKey = process.env.ANTHROPIC_API_KEY;
      if (!apiKey) return res.status(503).json({ error: "Audit service unavailable." });

      const client = new Anthropic({ apiKey });
      let response;
      try {
        response = await client.messages.create({
          model: "claude-opus-4-6",
          max_tokens: 16000,
          system: systemInstruction,
          messages: [{ role: "user", content: `Audit the following payload:\n\n${inputCode}` }],
          tools: [{ name: "audit_report", description: "Return the structured security audit report.", input_schema: responseSchema as any }],
          tool_choice: { type: "tool", name: "audit_report" },
        });
        circuitSuccess();
      } catch (apiErr: any) {
        circuitFailure();
        siem("HIGH", "CLAUDE_API_ERROR", ip, rid, { error: apiErr?.message });
        throw apiErr;
      }

      const toolUseBlock = response.content.find((b) => b.type === "tool_use");
      if (!toolUseBlock || toolUseBlock.type !== "tool_use")
        return res.status(502).json({ error: "Invalid response from audit model." });

      siem("INFO", "AUDIT_COMPLETE", ip, rid, { payloadLength: inputCode.length, threats, user: (req as any).user?.email });
      res.json(toolUseBlock.input);
    } catch (error: any) {
      console.error("[Sentinel] Audit Error:", error?.message ?? error);
      res.status(500).json({ error: "An internal error occurred during the audit." });
    }
  });

  // POST /api/url-scan — requires auth
  app.post("/api/url-scan", rateLimit(10, 60_000), verifySupabaseToken, async (req: Request, res: Response) => {
    const ip = getIP(req);
    const rid = getRid(req);
    try {
      const { url } = req.body;
      if (!url || typeof url !== "string")
        return res.status(400).json({ error: "URL is required." });

      let parsed: URL;
      try { parsed = new URL(url); } catch { return res.status(400).json({ error: "Invalid URL." }); }

      if (!["http:", "https:"].includes(parsed.protocol))
        return res.status(400).json({ error: "Only http/https URLs allowed." });

      const hostname = parsed.hostname.toLowerCase();
      const BLOCKED = [/^127\./, /^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^169\.254\./, /^::1$/, /^localhost$/i, /^0\.0\.0\.0$/];
      if (BLOCKED.some(r => r.test(hostname))) {
        strike(ip, `SSRF attempt: ${hostname}`, rid);
        return res.status(403).json({ error: "Private/internal URLs are not allowed." });
      }

      siem("INFO", "URL_SCAN_REQUEST", ip, rid, { url: url.slice(0, 200) });

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      let html: string;
      try {
        const r = await fetch(url, { signal: controller.signal, headers: { "User-Agent": "Sentinel-Lite/2.0 Security-Auditor" } });
        clearTimeout(timeout);
        if (!r.ok) return res.status(502).json({ error: `URL returned ${r.status}.` });
        html = (await r.text()).slice(0, 200_000);
      } catch (e: any) {
        clearTimeout(timeout);
        return res.status(502).json({ error: e.name === "AbortError" ? "Request timed out." : "Failed to fetch URL." });
      }

      const scriptMatches = [...html.matchAll(/<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/gi)];
      const inlineScripts = scriptMatches.map(m => m[1].trim()).filter(s => s.length > 0).join("\n\n");
      const srcMatches = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)];
      const scriptSrcs = srcMatches.map(m => m[1]).filter(s => !s.includes("cdn") && !s.includes("analytics")).slice(0, 5);

      const origin = `${parsed.protocol}//${parsed.host}`;
      const fetchedScripts: string[] = [];
      for (const src of scriptSrcs.slice(0, 3)) {
        try {
          const fullSrc = src.startsWith("http") ? src : `${origin}${src.startsWith("/") ? "" : "/"}${src}`;
          const r = await fetch(fullSrc, { headers: { "User-Agent": "Sentinel-Lite/2.0" } });
          if (r.ok) fetchedScripts.push(`--- External Script: ${src} ---\n${(await r.text()).slice(0, 50_000)}`);
        } catch {}
      }

      const content = [`--- Page HTML: ${url} ---\n${html}`, inlineScripts ? `--- Inline Scripts ---\n${inlineScripts}` : "", ...fetchedScripts].filter(Boolean).join("\n\n");
      res.json({ content, scriptCount: scriptMatches.length + fetchedScripts.length, url });
    } catch (err: any) {
      siem("HIGH", "URL_SCAN_ERROR", ip, rid, { error: err?.message });
      res.status(500).json({ error: "Failed to scan URL." });
    }
  });

  // POST /api/execute — requires auth
  app.post("/api/execute", rateLimit(20, 60_000), verifySupabaseToken, async (req: Request, res: Response) => {
    const ip = getIP(req);
    const rid = getRid(req);
    try {
      const { command } = req.body;
      if (!command || typeof command !== "string")
        return res.status(400).json({ error: "No command provided." });

      if (!isCommandAllowed(command)) {
        strike(ip, `Disallowed command: ${command.slice(0, 80)}`, rid);
        siem("HIGH", "COMMAND_BLOCKED", ip, rid, { command: command.slice(0, 200) });
        return res.status(403).json({ error: "Command not permitted. Only security audit tools are allowed." });
      }

      siem("INFO", "COMMAND_EXEC", ip, rid, { command, user: (req as any).user?.email });
      const { stdout, stderr } = await execAsync(command, { timeout: 30_000, maxBuffer: 1024 * 1024 * 5 });
      res.json({ stdout, stderr, error: null });
    } catch (error: any) {
      res.json({ stdout: error.stdout ?? "", stderr: error.stderr ?? "", error: error.message ?? "Command execution failed." });
    }
  });

  // POST /api/webhook — GitHub CI/CD, HMAC-SHA256 verified
  app.post("/api/webhook",
    express.raw({ type: "application/json" }),
    rateLimit(30, 60_000),
    async (req: Request, res: Response) => {
      const ip = getIP(req);
      const rid = getRid(req);
      const secret = process.env.GITHUB_WEBHOOK_SECRET;
      if (!secret) return res.status(503).json({ error: "Webhook not configured." });

      const signature = req.headers["x-hub-signature-256"] as string | undefined;
      if (!signature) { strike(ip, "Webhook missing signature", rid); return res.status(401).json({ error: "Missing signature." }); }

      const expected = "sha256=" + crypto.createHmac("sha256", secret).update(req.body).digest("hex");
      let match = false;
      try { match = crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature)); } catch {}
      if (!match) {
        strike(ip, "Webhook invalid signature", rid);
        siem("HIGH", "WEBHOOK_SIG_FAIL", ip, rid, {});
        return res.status(401).json({ error: "Invalid signature." });
      }

      const event = req.headers["x-github-event"] as string;
      if (event !== "push") return res.status(200).json({ message: `Event '${event}' acknowledged.` });

      let payload: any;
      try { payload = JSON.parse(req.body.toString()); }
      catch { return res.status(400).json({ error: "Invalid JSON payload." }); }

      const repo = payload.repository?.full_name;
      const branch = (payload.ref as string)?.replace("refs/heads/", "");
      const commitSha = payload.after;
      const pusher = payload.pusher?.name ?? "unknown";

      const changedFiles = new Set<string>();
      for (const commit of payload.commits ?? [])
        [...(commit.added ?? []), ...(commit.modified ?? [])].forEach((f: string) => changedFiles.add(f));

      const filesToAudit = [...changedFiles]
        .filter((f) => /\.(ts|tsx|js|jsx|py|go|rb|java|cs|php|tf|yaml|yml|json|toml|sh)$/i.test(f))
        .slice(0, 10);

      if (filesToAudit.length === 0) return res.json({ message: "No auditable files.", branch, pusher });

      const headers: Record<string, string> = { "User-Agent": "Sentinel-Lite/2.0" };
      if (process.env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;

      const fileContents: string[] = [];
      for (const file of filesToAudit) {
        try {
          const r = await fetch(`https://raw.githubusercontent.com/${repo}/${commitSha}/${file}`, { headers });
          if (r.ok) fileContents.push(`--- File: ${file} ---\n${(await r.text()).slice(0, 50_000)}`);
        } catch {}
      }

      if (fileContents.length === 0) return res.json({ message: "Could not fetch file contents." });

      const apiKey = process.env.ANTHROPIC_API_KEY;
      if (!apiKey) return res.status(503).json({ error: "Audit service unavailable." });

      res.json({ message: "Audit started.", repo, branch, pusher, files: filesToAudit, commitSha });

      try {
        const { SYSTEM_INSTRUCTION, AUDIT_RESPONSE_SCHEMA } = await import("./src/constants.js");
        const client = new Anthropic({ apiKey });
        const response = await client.messages.create({
          model: "claude-opus-4-6", max_tokens: 16000, system: SYSTEM_INSTRUCTION,
          messages: [{ role: "user", content: `Audit push from ${pusher} on ${repo}:${branch}:\n\n${fileContents.join("\n\n")}` }],
          tools: [{ name: "audit_report", description: "Return structured audit report.", input_schema: AUDIT_RESPONSE_SCHEMA as any }],
          tool_choice: { type: "tool", name: "audit_report" },
        });
        const toolBlock = response.content.find((b) => b.type === "tool_use");
        if (toolBlock?.type === "tool_use") {
          const result = toolBlock.input as any;
          const status = result.isSecure ? "PASS" : `FAIL (${result.findings?.length} findings)`;
          siem("INFO", "WEBHOOK_AUDIT_COMPLETE", ip, rid, { repo, branch, status });
        }
      } catch (err: any) {
        siem("HIGH", "WEBHOOK_AUDIT_ERROR", ip, rid, { error: err?.message });
      }
    }
  );

  // GET /api/security/events — SIEM dashboard (passphrase-gated)
  app.get("/api/security/events", (req: Request, res: Response) => {
    const passphrase = req.headers["x-sentinel-passphrase"] as string | undefined;
    const expected = process.env.VITE_DEV_PASSPHRASE;
    if (!expected || !passphrase) return res.status(401).json({ error: "Unauthorized." });
    let match = false;
    try { match = crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(passphrase)); } catch {}
    if (!match) {
      strike(getIP(req), "SIEM unauthorized attempt", getRid(req));
      return res.status(401).json({ error: "Unauthorized." });
    }
    const severity = req.query.severity as string | undefined;
    const limit = Math.min(parseInt(req.query.limit as string ?? "200"), 1000);
    const events = severity
      ? eventLog.filter((e) => e.severity === severity.toUpperCase()).slice(-limit)
      : eventLog.slice(-limit);
    res.json({ total: eventLog.length, returned: events.length, circuitState: circuit.state, blockedIPs: blockedIPs.size, events });
  });

  // Vite dev / static production
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true, allowedHosts: [".up.railway.app"] },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath, { dotfiles: "deny" }));
    app.get("*", (_req: Request, res: Response) => res.sendFile(path.join(distPath, "index.html")));
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[Sentinel] Server          → http://localhost:${PORT}`);
    console.log(`[Sentinel] Auth            : Supabase JWT verification active`);
    console.log(`[Sentinel] CrowdSec        : ${process.env.CROWDSEC_API_KEY ? "active" : "disabled (no API key)"}`);
    console.log(`[Sentinel] Rate limits     : 10 audits/min · 20 exec/min · 30 webhook/min`);
    console.log(`[Sentinel] Honeypot paths  : ${HONEYPOT_PATHS.size} traps armed`);
    console.log(`[Sentinel] Threat sigs     : ${THREAT_SIGNATURES.length} patterns loaded`);
    console.log(`[Sentinel] Circuit breaker : CLOSED (threshold: ${CB_THRESHOLD} failures)`);
    console.log(`[Sentinel] SIEM            : active (max ${MAX_LOG} events in-memory)`);
  });
}

startServer();
