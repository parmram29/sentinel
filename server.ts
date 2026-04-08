import express, { Request, Response, NextFunction } from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { exec } from "child_process";
import { promisify } from "util";
import crypto from "crypto";
import Anthropic from "@anthropic-ai/sdk";

const execAsync = promisify(exec);

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

function rateLimit(maxRequests: number, windowMs: number) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = (req.ip ?? req.socket.remoteAddress ?? "unknown").replace(/^::ffff:/, "");
    const now = Date.now();
    const record = rateLimitStore.get(ip);
    if (!record || now > record.resetAt) {
      rateLimitStore.set(ip, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (record.count >= maxRequests) {
      res.setHeader("Retry-After", Math.ceil((record.resetAt - now) / 1000).toString());
      return res.status(429).json({ error: "Rate limit exceeded. Please wait before retrying." });
    }
    record.count++;
    next();
  };
}

const ALLOWED_COMMANDS: readonly string[] = [
  "npm audit", "npm audit --json", "npm outdated", "npx snyk test",
  "pip-audit", "pip-audit --json", "bandit -r .", "semgrep --config auto .",
  "trivy fs .", "git log --oneline -20", "git diff HEAD",
  "cat package.json", "cat requirements.txt", "cat pyproject.toml",
  "cat Pipfile", "cat Gemfile", "cat go.sum", "cat go.mod", "ls -la", "ls",
];

function isCommandAllowed(command: string): boolean {
  const trimmed = command.trim();
  return ALLOWED_COMMANDS.some((a) => trimmed === a || trimmed.startsWith(a + " "));
}

function securityHeaders(_req: Request, res: Response, next: NextFunction) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("Content-Security-Policy",
    ["default-src 'self'", "script-src 'self' 'unsafe-inline'", "style-src 'self' 'unsafe-inline'",
     "img-src 'self' data:", "connect-src 'self'", "font-src 'self'", "object-src 'none'",
     "base-uri 'self'", "form-action 'self'", "frame-ancestors 'none'"].join("; "));
  res.removeHeader("X-Powered-By");
  next();
}

const ALLOWED_ORIGINS = new Set(["http://localhost:3000", "http://127.0.0.1:3000"]);

function corsMiddleware(req: Request, res: Response, next: NextFunction) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "86400");
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
}

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;

  app.set("trust proxy", 1);
  app.use(securityHeaders);
  app.use(corsMiddleware);
  app.use(express.json({ limit: "5mb" }));

  app.post("/api/audit", rateLimit(10, 60_000), async (req: Request, res: Response) => {
    try {
      const { inputCode, systemInstruction, responseSchema } = req.body;
      if (!inputCode || typeof inputCode !== "string")
        return res.status(400).json({ error: "Input code is required." });
      if (inputCode.length > 500_000)
        return res.status(413).json({ error: "Payload exceeds 500,000 character limit." });
      if (typeof systemInstruction !== "string" || !systemInstruction)
        return res.status(400).json({ error: "System instruction is missing." });

      const apiKey = process.env.ANTHROPIC_API_KEY;
      if (!apiKey) return res.status(503).json({ error: "Audit service unavailable." });

      const client = new Anthropic({ apiKey });
      const response = await client.messages.create({
        model: "claude-opus-4-6",
        max_tokens: 16000,
        system: systemInstruction,
        messages: [{ role: "user", content: `Audit the following payload:\n\n${inputCode}` }],
        tools: [{ name: "audit_report", description: "Return the structured audit report.", input_schema: responseSchema as any,  }],
        tool_choice: { type: "tool", name: "audit_report" },
      });

      const toolUseBlock = response.content.find((b) => b.type === "tool_use");
      if (!toolUseBlock || toolUseBlock.type !== "tool_use")
        return res.status(502).json({ error: "Invalid response from audit model." });

      res.json(toolUseBlock.input);
    } catch (error: any) {
      console.error("[Sentinel] Audit Error:", error?.message ?? error);
      res.status(500).json({ error: "An internal error occurred during the audit." });
    }
  });

  app.post("/api/execute", rateLimit(20, 60_000), async (req: Request, res: Response) => {
    try {
      const { command } = req.body;
      if (!command || typeof command !== "string")
        return res.status(400).json({ error: "No command provided." });
      if (!isCommandAllowed(command)) {
        console.warn(`[Sentinel] BLOCKED command from ${req.ip}: "${command}"`);
        return res.status(403).json({ error: "Command not permitted.", allowed: ALLOWED_COMMANDS });
      }
      const { stdout, stderr } = await execAsync(command, { timeout: 30_000, maxBuffer: 1024 * 1024 * 5 });
      res.json({ stdout, stderr, error: null });
    } catch (error: any) {
      res.json({ stdout: error.stdout ?? "", stderr: error.stderr ?? "", error: error.message ?? "Command execution failed." });
    }
  });

  app.post("/api/webhook",
    express.raw({ type: "application/json" }),
    rateLimit(30, 60_000),
    async (req: Request, res: Response) => {
      const secret = process.env.GITHUB_WEBHOOK_SECRET;
      if (!secret) return res.status(503).json({ error: "Webhook not configured." });

      const signature = req.headers["x-hub-signature-256"] as string | undefined;
      if (!signature) return res.status(401).json({ error: "Missing signature." });

      const expected = "sha256=" + crypto.createHmac("sha256", secret).update(req.body).digest("hex");
      let match = false;
      try { match = crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature)); } catch {}
      if (!match) return res.status(401).json({ error: "Invalid signature." });

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

      if (filesToAudit.length === 0)
        return res.json({ message: "No auditable files.", branch, pusher });

      const headers: Record<string, string> = { "User-Agent": "CompTIA-Sentinel" };
      if (process.env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;

      const fileContents: string[] = [];
      for (const file of filesToAudit) {
        try {
          const r = await fetch(`https://raw.githubusercontent.com/${repo}/${commitSha}/${file}`, { headers });
          if (r.ok) fileContents.push(`--- File: ${file} ---\n${(await r.text()).slice(0, 50_000)}`);
        } catch {}
      }

      if (fileContents.length === 0)
        return res.json({ message: "Could not fetch file contents." });

      const apiKey = process.env.ANTHROPIC_API_KEY;
      if (!apiKey) return res.status(503).json({ error: "Audit service unavailable." });

      res.json({ message: "Audit started.", repo, branch, pusher, files: filesToAudit, commitSha });

      try {
        const { SYSTEM_INSTRUCTION, AUDIT_RESPONSE_SCHEMA } = await import("./src/constants.js");
        const client = new Anthropic({ apiKey });
        const response = await client.messages.create({
          model: "claude-opus-4-6", max_tokens: 16000, system: SYSTEM_INSTRUCTION,
          messages: [{ role: "user", content: `Audit push from ${pusher} on ${repo}:${branch}:\n\n${fileContents.join("\n\n")}` }],
          tools: [{ name: "audit_report", description: "Return the structured audit report.", input_schema: AUDIT_RESPONSE_SCHEMA as any,         }],
          tool_choice: { type: "tool", name: "audit_report" },
        });
        const toolBlock = response.content.find((b) => b.type === "tool_use");
        if (toolBlock?.type === "tool_use") {
          const result = toolBlock.input as any;
          console.log(`[Sentinel] Webhook audit: ${repo}:${branch} → ${result.isSecure ? "PASS" : `FAIL (${result.findings?.length} findings)`}`);
        }
      } catch (err: any) {
        console.error("[Sentinel] Webhook audit error:", err?.message ?? err);
      }
    }
  );

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: "spa" });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath, { dotfiles: "deny" }));
    app.get("*", (_req: Request, res: Response) => res.sendFile(path.join(distPath, "index.html")));
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[Sentinel] Server → http://localhost:${PORT}`);
  });
}

startServer();
