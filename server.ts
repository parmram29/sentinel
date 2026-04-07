import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { exec } from "child_process";
import { promisify } from "util";

// Convert the callback-based exec function to a Promise-based one for easier async/await usage
const execAsync = promisify(exec);

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Middleware to parse JSON bodies. Limit increased to 50mb to handle large code payloads.
  app.use(express.json({ limit: "50mb" }));

  // ---------------------------------------------------------------------------
  // API Route: /api/audit
  // Description: Handles Gemini API calls securely on the backend.
  // ---------------------------------------------------------------------------
  app.post("/api/audit", async (req, res) => {
    try {
      const { inputCode, systemInstruction, responseSchema } = req.body;
      if (!inputCode) {
        return res.status(400).json({ error: "No input code provided." });
      }

      const apiKey = process.env.GEMINI_API_KEY || process.env.API_KEY;
      if (!apiKey) {
        return res.status(500).json({ error: "API key is missing on the server." });
      }

      // Dynamic import to avoid issues with CommonJS/ESM if needed, or just import at top
      const { GoogleGenAI } = await import("@google/genai");
      const ai = new GoogleGenAI({ apiKey });

      const response = await ai.models.generateContent({
        model: "gemini-3.1-pro-preview",
        contents: `Audit the following payload:\n\n${inputCode}`,
        config: {
          systemInstruction: systemInstruction,
          responseMimeType: "application/json",
          responseSchema: responseSchema,
        },
      });

      if (!response.text) {
        return res.status(500).json({ error: "No response received from the model." });
      }

      const result = JSON.parse(response.text);
      res.json(result);
    } catch (error: any) {
      console.error("Audit Error:", error);
      res.status(500).json({ error: error.message || "An error occurred during the audit." });
    }
  });

  // ---------------------------------------------------------------------------
  // API Route: /api/execute
  // Description: Executes shell commands (CLI) directly on the container.
  // This is used for running tools like `npm audit` or custom scripts.
  // ---------------------------------------------------------------------------
  app.post("/api/execute", async (req, res) => {
    try {
      const { command } = req.body;
      if (!command) {
        return res.status(400).json({ error: "No command provided." });
      }

      // Execute the command with a 30-second timeout to prevent hanging processes
      const { stdout, stderr } = await execAsync(command, { timeout: 30000 });
      
      res.json({ stdout, stderr, error: null });
    } catch (error: any) {
      console.error("CLI Execution Error:", error);
      // If the command fails (e.g., exit code 1), execAsync throws an error that contains stdout/stderr
      res.json({ 
        stdout: error.stdout || "", 
        stderr: error.stderr || "", 
        error: error.message || "Command execution failed." 
      });
    }
  });

  // ---------------------------------------------------------------------------
  // Vite Middleware & Static File Serving
  // Description: Handles serving the React frontend. In development, it uses Vite's
  // middleware for HMR. In production, it serves the compiled static files from /dist.
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
