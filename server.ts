import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { exec } from "child_process";
import { promisify } from "util";
import Anthropic from "@anthropic-ai/sdk";

const execAsync = promisify(exec);

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: "50mb" }));

  // ---------------------------------------------------------------------------
  // API Route: /api/audit
  // Description: Handles Claude API calls securely on the backend.
  // ---------------------------------------------------------------------------
  app.post("/api/audit", async (req, res) => {
    try {
      const { inputCode, systemInstruction, responseSchema } = req.body;
      if (!inputCode) {
        return res.status(400).json({ error: "No input code provided." });
      }

      const apiKey = process.env.ANTHROPIC_API_KEY;
      if (!apiKey) {
        return res.status(500).json({ error: "API key is missing on the server." });
      }

      const client = new Anthropic({ apiKey });

      const response = await client.messages.create({
        model: "claude-opus-4-6",
        max_tokens: 16000,
        system: systemInstruction,
        messages: [
          { role: "user", content: `Audit the following payload:\n\n${inputCode}` }
        ],
        tools: [
          {
            name: "audit_report",
            description: "Return the structured CompTIA security audit report.",
            input_schema: responseSchema,
          }
        ],
        tool_choice: { type: "tool", name: "audit_report" },
      });

      const toolUseBlock = response.content.find((block) => block.type === "tool_use");
      if (!toolUseBlock || toolUseBlock.type !== "tool_use") {
        return res.status(500).json({ error: "No structured report received from the model." });
      }

      res.json(toolUseBlock.input);
    } catch (error: any) {
      console.error("Audit Error:", error);
      res.status(500).json({ error: error.message || "An error occurred during the audit." });
    }
  });

  // ---------------------------------------------------------------------------
  // API Route: /api/execute
  // ---------------------------------------------------------------------------
  app.post("/api/execute", async (req, res) => {
    try {
      const { command } = req.body;
      if (!command) {
        return res.status(400).json({ error: "No command provided." });
      }

      const { stdout, stderr } = await execAsync(command, { timeout: 30000 });
      res.json({ stdout, stderr, error: null });
    } catch (error: any) {
      console.error("CLI Execution Error:", error);
      res.json({
        stdout: error.stdout || "",
        stderr: error.stderr || "",
        error: error.message || "Command execution failed."
      });
    }
  });

  // ---------------------------------------------------------------------------
  // Vite Middleware & Static File Serving
  // ---------------------------------------------------------------------------
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
