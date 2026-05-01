/**
 * Persistent Agent Server
 *
 * Runs as a background daemon and handles permission evaluation requests
 * over a Unix socket.
 *
 * Usage:
 *   bun agent-server.ts        # Start the server
 *   bun agent-server.ts stop   # Stop a running server
 */

import { readFile, unlink } from "fs/promises";
import { queryClaudeSubscription, queryEvalProvider, selectEvalProvider } from "./evaluator";
import { DEFAULT_INSTANCE_NAME, DEFAULT_PID_FILE, DEFAULT_SOCKET_PATH, SERVER_DIR } from "./server-identity";
import {
  type EvalRequest,
  type EvalResponse,
  regexTriage,
  buildHookOutput,
  buildEvalPrompt,
  parseEvalResponse,
  loadPreferences,
  applyModeLogic,
  buildDenyWithSuggestions,
  earlyBashCheck,
  PASSTHROUGH_TOOLS,
  extractPathsFromStdin,
  evaluateDeterministic,
} from "./shared";

const SOCKET_PATH = process.env.MOTHER_SOCKET || DEFAULT_SOCKET_PATH;
const PID_FILE = process.env.MOTHER_PID_FILE || DEFAULT_PID_FILE;

function log(stage: string, message: string) {
  const timestamp = new Date().toISOString().slice(11, 23);
  console.error(`[${timestamp}] [${stage}] ${message}`);
}

function logRequest(req: EvalRequest) {
  console.error("\n" + "=".repeat(80));
  console.error(`[${new Date().toISOString().slice(11, 23)}] NEW REQUEST`);
  console.error("=".repeat(80));
  console.error(`Tool: ${req.toolName || "unknown"}`);
  console.error(`Client: ${req.client}`);
  console.error(`Hook: ${req.hookEventName}`);
  console.error(`CWD: ${req.cwd}`);
  console.error(`Mode: ${req.permissionMode}`);

  try {
    const parsed = JSON.parse(req.stdin);
    if (parsed.tool_input) {
      console.error(`\nTool Input:`);
      const input = parsed.tool_input;
      if (typeof input === "string") {
        console.error(`  ${input.slice(0, 500)}${input.length > 500 ? "..." : ""}`);
      } else {
        for (const [key, value] of Object.entries(input)) {
          const valStr = typeof value === "string" ? value : JSON.stringify(value);
          console.error(`  ${key}: ${valStr.slice(0, 200)}${valStr.length > 200 ? "..." : ""}`);
        }
      }
    }
  } catch {
    if (req.stdin) {
      console.error(`\nStdin: ${req.stdin.slice(0, 300)}${req.stdin.length > 300 ? "..." : ""}`);
    }
  }
  console.error("-".repeat(80));
}

async function handleRequest(req: EvalRequest): Promise<EvalResponse> {
  const { args, stdin, cwd, client, hookEventName, permissionMode, toolName } = req;
  const inputText = `${args.join(" ")} ${stdin}`.trim();

  logRequest(req);

  // Pass-through tools Mother should never evaluate
  if (PASSTHROUGH_TOOLS.includes(toolName)) {
    log("DECISION", `✓ PASSTHROUGH (${toolName})`);
    return {
      type: "result",
      triage: { promptInjectionScore: 0, regexFlags: [], reasoning: "passthrough" },
      explanation: { summary: "Passthrough tool", affectedPaths: [], relativeToProject: cwd },
      preferenceCheck: { violatedRules: [], matchedAllowedActions: [], requiresReview: [], decision: "allow", reasoning: "passthrough" },
      hookOutput: {},
    };
  }

  // Stage 0: Deterministic rules engine (no LLM needed)
  const deterministic = evaluateDeterministic(stdin);
  if (deterministic) {
    const modeDecision = deterministic.decision === "ask" ? "review" as const
      : deterministic.decision === "deny" ? "deny" as const
      : "allow" as const;
    const modeResult = applyModeLogic(modeDecision, permissionMode, toolName, extractPathsFromStdin(stdin));
    let reason = modeResult.reason || deterministic.reason;
    if (modeResult.decision === "deny") {
      reason = buildDenyWithSuggestions(toolName, stdin, reason);
    }

    log("DECISION", `${modeResult.decision === "allow" ? "✓" : modeResult.decision === "deny" ? "✗" : "?"} ${modeResult.decision.toUpperCase()} (deterministic)`);
    return {
      type: "result",
      triage: { promptInjectionScore: 0, regexFlags: [], reasoning: "deterministic" },
      explanation: { summary: "Deterministic check", affectedPaths: extractPathsFromStdin(stdin), relativeToProject: cwd },
      preferenceCheck: { violatedRules: [], matchedAllowedActions: [], requiresReview: [], decision: modeDecision, reasoning: reason },
      hookOutput: buildHookOutput(hookEventName, modeResult.decision, reason),
    };
  }

  // Early deterministic Bash checks (no LLM needed)
  if (toolName === "Bash") {
    const early = earlyBashCheck(hookEventName, permissionMode, stdin);
    if (early) {
      const decision = (early as any)?.hookSpecificOutput?.permissionDecision ||
                       (early as any)?.hookSpecificOutput?.decision?.behavior || "allow";
      log("DECISION", `${decision === "allow" ? "✓" : "✗"} ${decision.toUpperCase()} (deterministic)`);
      return {
        type: "result",
        triage: { promptInjectionScore: 0, regexFlags: [], reasoning: "deterministic" },
        explanation: { summary: "Deterministic check", affectedPaths: [], relativeToProject: cwd },
        preferenceCheck: { violatedRules: [], matchedAllowedActions: [], requiresReview: [], decision: decision as any, reasoning: "deterministic" },
        hookOutput: early,
      };
    }
  }

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
  const preferences = await loadPreferences(cwd, client);

  // Single combined LLM evaluation
  log("EVAL", `evaluating request with ${selectEvalProvider(client)} provider...`);
  const prompt = buildEvalPrompt(toolName, args, stdin, cwd, preferences);
  const text = await queryEvalProvider(prompt, { client, cwd });
  const result = parseEvalResponse(text);
  log("EVAL", `${result.summary}`);
  log("DECISION", `${result.decision === "allow" ? "✓" : result.decision === "deny" ? "✗" : "?"} ${result.decision.toUpperCase()} - ${result.reasoning}`);

  // Apply mode-specific logic
  const modeResult = applyModeLogic(result.decision, permissionMode, toolName, extractPathsFromStdin(stdin));
  const finalDecision = modeResult.decision;

  // Build reason: prefer mode override reason, then deny message, then LLM reasoning
  let reason = modeResult.reason || result.denyMessage || result.reasoning;
  if (finalDecision === "deny") {
    reason = buildDenyWithSuggestions(toolName, stdin, reason);
  }

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

async function evaluateCompletion(
  lastMessage: string,
  criteria: string,
): Promise<{ satisfied: boolean; reason?: string }> {
  const text = await queryClaudeSubscription(`You are evaluating whether a task has been adequately completed.

Here is the assistant's final message:
<message>
${lastMessage.slice(0, 2000)}
</message>

Here are the user's completion criteria:
<criteria>
${criteria}
</criteria>

Based on the message, does it appear that ALL of the completion criteria have been satisfied?
Look for evidence that the criteria were addressed — explicit mentions of running checks, completing steps, etc.
If the message doesn't mention something required by the criteria, assume it wasn't done.

Respond in this EXACT format:
SATISFIED: [yes|no]
REASON: [if no, one sentence explaining what's missing]`);

  const satisfiedMatch = text.match(/SATISFIED:\s*(\w+)/i);
  const reasonMatch = text.match(/REASON:\s*(.+)/);

  const satisfied = satisfiedMatch?.[1]?.toLowerCase() === "yes";
  return {
    satisfied,
    reason: satisfied ? undefined : (reasonMatch?.[1] || "Custom completion criteria not met."),
  };
}

async function startServer() {
  try {
    await unlink(SOCKET_PATH);
  } catch {
    // Socket doesn't exist
  }

  await Bun.write(PID_FILE, process.pid.toString());

  let requestCount = 0;
  const startTime = Date.now();

  const server = Bun.serve({
    unix: SOCKET_PATH,
    async fetch(req) {
      const url = new URL(req.url);

      if (req.method === "GET" && url.pathname === "/health") {
        return Response.json({
          status: "ok",
          instance: DEFAULT_INSTANCE_NAME,
          server_dir: SERVER_DIR,
          socket_path: SOCKET_PATH,
          provider_mode: process.env.MOTHER_EVAL_PROVIDER || process.env.MOTHER_PROVIDER || "auto",
          uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
          requests_handled: requestCount,
          pid: process.pid,
        });
      }

      if (req.method !== "POST") {
        return new Response("Method not allowed", { status: 405 });
      }

      try {
        // Route by pathname
        if (url.pathname === "/eval-completion") {
          const body = await req.json() as { lastMessage: string; criteria: string };
          const result = await evaluateCompletion(body.lastMessage, body.criteria);
          return Response.json(result);
        }

        const body = (await req.json()) as EvalRequest;

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

  const shutdown = async () => {
    console.log("Shutting down...");
    server.stop();
    try {
      await unlink(SOCKET_PATH);
      await unlink(PID_FILE);
    } catch {}
    process.exit(0);
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
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

const command = process.argv[2];
if (command === "stop") {
  await stopServer();
} else {
  await startServer();
}
