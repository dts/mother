/**
 * Persistent Agent Server
 *
 * Runs as a background daemon and handles permission evaluation requests
 * over a Unix socket. Uses Claude Code Agent SDK with a persistent session.
 *
 * Usage:
 *   bun agent-server.ts        # Start the server
 *   bun agent-server.ts stop   # Stop a running server
 */

import { query } from "@anthropic-ai/claude-agent-sdk";
import { readFile, unlink } from "fs/promises";

const SOCKET_PATH = process.env.MOTHER_SOCKET || "/tmp/mother.sock";
const PID_FILE = "/tmp/mother.pid";

interface EvalRequest {
  type: "eval";
  args: string[];
  stdin: string;
  cwd: string;
  hookEventName: string;
  permissionMode: string;
  toolName: string;
}

interface EvalResponse {
  type: "result";
  triage: {
    promptInjectionScore: number;
    regexFlags: string[];
    reasoning: string;
  };
  explanation: {
    summary: string;
    affectedPaths: string[];
    relativeToProject: string;
  };
  preferenceCheck: {
    violatedRules: string[];
    matchedAllowedActions: string[];
    requiresReview: string[];
    decision: "allow" | "deny" | "review";
    reasoning: string;
  };
  hookOutput: object;
}

// Regex patterns for structural prompt injection sequences
const SUSPICIOUS_PATTERNS = [
  { pattern: /\]\]\s*\[\[/i, flag: "bracket-injection" },
  { pattern: /<\/?system>/i, flag: "xml-system-tag" },
  { pattern: /<\/?system-prompt>/i, flag: "xml-system-tag" },
  { pattern: /<\/?assistant>/i, flag: "xml-role-tag" },
  { pattern: /<\/?human>/i, flag: "xml-role-tag" },
  { pattern: /<\/?user>/i, flag: "xml-role-tag" },
  { pattern: /---\s*(END|BEGIN)\s+(SYSTEM|USER|ASSISTANT)/i, flag: "fake-delimiter" },
];

// Query using Claude Code Agent SDK (uses subscription, not API credits)
async function queryText(prompt: string): Promise<string> {
  const q = query({
    prompt,
    options: {
      model: "claude-haiku-4-5-20251001",
      maxTurns: 1,
      tools: [],
      persistSession: false,
    },
  });

  let result = "";
  for await (const msg of q) {
    if (msg.type === "assistant") {
      for (const block of msg.message.content) {
        if (block.type === "text") {
          result += block.text;
        }
      }
    }
  }
  return result;
}

// Fast regex-only triage (no LLM needed)
function regexTriage(input: string): string[] {
  return SUSPICIOUS_PATTERNS
    .filter(({ pattern }) => pattern.test(input))
    .map(({ flag }) => flag);
}

// Combined single-query evaluation (1 LLM call instead of 3)
async function evaluateRequest(
  toolName: string,
  args: string[],
  stdin: string,
  cwd: string,
  preferences: string
): Promise<{
  summary: string;
  decision: "allow" | "deny" | "review";
  reasoning: string;
  denyMessage?: string;
}> {
  const text = await queryText(`You are a security policy evaluator for a developer's local machine.

Tool: ${toolName}
Working directory: ${cwd}
Arguments: ${JSON.stringify(args)}

Request details:
<request>
${stdin.slice(0, 3000)}
</request>

${preferences ? `Additional preferences:\n<preferences>\n${preferences}\n</preferences>` : ""}

CORE PRINCIPLE: Allow by default. Only flag genuinely dangerous operations.

ALWAYS ALLOW (no exceptions):
- Read operations on non-sensitive files (code, configs, docs, logs, temp files, etc.)
- Listing directories, searching, grepping
- Building, compiling, bundling code
- Running tests, linters, formatters
- Package management (npm, bun, pip, cargo, etc.) for project dependencies
- Development servers, watchers, hot reload
- Git operations (including push - user already authenticated)
- Mobile dev tools (Xcode, Android Studio, Capacitor, Gradle, etc.)
- File writes/edits within or near the project
- Running project scripts
- Reading/writing temp files (/tmp, /var/folders, etc.)

DENY if the action:
- Exposes secrets to the LLM (reading .env, credentials.json, *_secret*, *.pem, *.key, id_rsa, etc. WITHOUT obscuring values)
  → Use DENY_MESSAGE: "DO NOT EXPOSE SECRETS. USE ENV VARIABLE EXPANSION OR OBSCURE WITH sed 's/=.*/=***/'."
- Uses secret values inline (e.g., curl -H "Authorization: Bearer sk-...")
  → Use DENY_MESSAGE: "DO NOT EXPOSE SECRETS. USE ENV VARIABLE EXPANSION OR OBSCURE WITH sed 's/=.*/=***/'."
- Exfiltrates data (curl/wget POST-ing files to remote servers)
- Mass deletes outside project (rm -rf /, rm -rf ~, etc.)
- Modifies system config files (/etc/*, /usr/*, ~/.bashrc, ~/.zshrc, etc.)

REVIEW if the action:
- Installs global packages (npm -g, pip install --user, brew install, etc.)

Respond in this EXACT format:
SUMMARY: [1 sentence description of what this does]
DECISION: [allow|deny|review]
REASONING: [1 sentence explanation]
DENY_MESSAGE: [optional - only if DECISION is deny, the message to show]`);

  const summaryMatch = text.match(/SUMMARY:\s*(.+)/);
  const decisionMatch = text.match(/DECISION:\s*(\w+)/);
  const reasoningMatch = text.match(/REASONING:\s*(.+)/);
  const denyMessageMatch = text.match(/DENY_MESSAGE:\s*(.+)/);

  let decision = decisionMatch?.[1]?.toLowerCase() as "allow" | "deny" | "review";
  if (!["allow", "deny", "review"].includes(decision)) {
    decision = "review";
  }

  return {
    summary: summaryMatch?.[1] || "Unable to summarize",
    decision,
    reasoning: reasoningMatch?.[1] || "No reasoning provided",
    denyMessage: denyMessageMatch?.[1],
  };
}

function buildHookOutput(
  hookEventName: string,
  decision: "allow" | "deny" | "ask",
  reason: string
) {
  if (hookEventName === "PermissionRequest") {
    if (decision === "ask") {
      return {};
    }
    return {
      hookSpecificOutput: {
        hookEventName: "PermissionRequest",
        decision: {
          behavior: decision,
          message: reason,
        },
      },
    };
  }

  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
  };
}

function log(stage: string, message: string) {
  const timestamp = new Date().toISOString().slice(11, 23);
  console.error(`[${timestamp}] [${stage}] ${message}`);
}

function logRequest(req: EvalRequest) {
  console.error("\n" + "=".repeat(80));
  console.error(`[${new Date().toISOString().slice(11, 23)}] NEW REQUEST`);
  console.error("=".repeat(80));
  console.error(`Tool: ${req.toolName || "unknown"}`);
  console.error(`Hook: ${req.hookEventName}`);
  console.error(`CWD: ${req.cwd}`);
  console.error(`Mode: ${req.permissionMode}`);

  // Parse and display the actual request content
  try {
    const parsed = JSON.parse(req.stdin);
    if (parsed.tool_input) {
      console.error(`\nTool Input:`);
      const input = parsed.tool_input;
      if (typeof input === 'string') {
        console.error(`  ${input.slice(0, 500)}${input.length > 500 ? '...' : ''}`);
      } else {
        // For structured input (like Read, Grep, etc.)
        for (const [key, value] of Object.entries(input)) {
          const valStr = typeof value === 'string' ? value : JSON.stringify(value);
          console.error(`  ${key}: ${valStr.slice(0, 200)}${valStr.length > 200 ? '...' : ''}`);
        }
      }
    }
  } catch {
    // Not JSON or no tool_input
    if (req.stdin) {
      console.error(`\nStdin: ${req.stdin.slice(0, 300)}${req.stdin.length > 300 ? '...' : ''}`);
    }
  }
  console.error("-".repeat(80));
}

async function handleRequest(req: EvalRequest): Promise<EvalResponse> {
  const { args, stdin, cwd, hookEventName, permissionMode, toolName } = req;
  const inputText = `${args.join(" ")} ${stdin}`.trim();

  logRequest(req);

  // Fast regex triage (no LLM)
  const regexFlags = regexTriage(inputText);
  if (regexFlags.length > 0) {
    log("TRIAGE", `⚠️  Regex flags: ${regexFlags.join(", ")}`);
    log("DECISION", `? ASK (suspicious patterns)`);
    return {
      type: "result",
      triage: { promptInjectionScore: 0, regexFlags, reasoning: "Suspicious patterns detected" },
      explanation: { summary: "Flagged by regex", affectedPaths: [], relativeToProject: "N/A" },
      preferenceCheck: {
        violatedRules: [], matchedAllowedActions: [], requiresReview: ["Suspicious patterns"],
        decision: "review", reasoning: `Patterns: ${regexFlags.join(", ")}`,
      },
      hookOutput: buildHookOutput(hookEventName, "ask", `Suspicious patterns: ${regexFlags.join(", ")}`),
    };
  }

  // Load security preferences
  const homeDir = process.env.HOME || process.env.USERPROFILE || "~";
  let preferences = "";
  try {
    preferences = await readFile(`${cwd}/.claude/security-preferences.md`, "utf-8");
  } catch {
    try {
      preferences = await readFile(`${homeDir}/.claude/security-preferences.md`, "utf-8");
    } catch {}
  }

  // Single combined LLM evaluation
  log("EVAL", "evaluating request...");
  const result = await evaluateRequest(toolName, args, stdin, cwd, preferences);
  log("EVAL", `${result.summary}`);
  log("DECISION", `${result.decision === "allow" ? "✓" : result.decision === "deny" ? "✗" : "?"} ${result.decision.toUpperCase()} - ${result.reasoning}`);

  // Map decision
  let finalDecision: "allow" | "deny" | "ask" = {
    allow: "allow" as const,
    deny: "deny" as const,
    review: "ask" as const,
  }[result.decision];

  // In default permission mode, don't auto-allow edits
  const isEditTool = ["Edit", "Write", "NotebookEdit"].includes(toolName);
  if (finalDecision === "allow" && isEditTool && permissionMode === "default") {
    finalDecision = "ask";
  }

  const reason = result.denyMessage || result.reasoning;

  return {
    type: "result",
    triage: { promptInjectionScore: 0, regexFlags: [], reasoning: "passed" },
    explanation: { summary: result.summary, affectedPaths: [], relativeToProject: cwd },
    preferenceCheck: {
      violatedRules: [],
      matchedAllowedActions: [],
      requiresReview: [],
      decision: result.decision,
      reasoning: result.reasoning,
    },
    hookOutput: buildHookOutput(hookEventName, finalDecision, reason),
  };
}

async function startServer() {
  // Clean up existing socket
  try {
    await unlink(SOCKET_PATH);
  } catch {
    // Socket doesn't exist, that's fine
  }

  // Write PID file
  await Bun.write(PID_FILE, process.pid.toString());

  let requestCount = 0;
  const startTime = Date.now();

  const server = Bun.serve({
    unix: SOCKET_PATH,
    async fetch(req) {
      const url = new URL(req.url);

      // Health check endpoint
      if (req.method === "GET" && url.pathname === "/health") {
        return Response.json({
          status: "ok",
          uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
          requests_handled: requestCount,
          pid: process.pid,
        });
      }

      if (req.method !== "POST") {
        return new Response("Method not allowed", { status: 405 });
      }

      try {
        const body = await req.json() as EvalRequest;

        if (body.type !== "eval") {
          return Response.json({ type: "error", message: "Unknown request type" }, { status: 400 });
        }

        requestCount++;
        const result = await handleRequest(body);
        return Response.json(result);
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unknown error";
        return Response.json({ type: "error", message }, { status: 500 });
      }
    },
  });

  console.log(`Mother agent server listening on ${SOCKET_PATH}`);
  console.log(`PID: ${process.pid}`);

  // Handle shutdown
  process.on("SIGTERM", async () => {
    console.log("Shutting down...");
    server.stop();
    try {
      await unlink(SOCKET_PATH);
      await unlink(PID_FILE);
    } catch {}
    process.exit(0);
  });

  process.on("SIGINT", async () => {
    console.log("\nShutting down...");
    server.stop();
    try {
      await unlink(SOCKET_PATH);
      await unlink(PID_FILE);
    } catch {}
    process.exit(0);
  });
}

async function stopServer() {
  try {
    const pid = await readFile(PID_FILE, "utf-8");
    process.kill(parseInt(pid, 10), "SIGTERM");
    console.log(`Sent SIGTERM to process ${pid}`);
  } catch (error) {
    console.error("Could not stop server:", error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

// Main
const command = process.argv[2];
if (command === "stop") {
  await stopServer();
} else {
  await startServer();
}
