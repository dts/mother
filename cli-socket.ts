/**
 * Socket-based CLI for Mother
 *
 * Connects to the agent-server over a Unix socket for fast permission evaluation.
 * Falls back to asking user if the server is not running.
 *
 * Usage:
 *   echo '{"hook_event_name":"PermissionRequest",...}' | bun cli-socket.ts
 *   bun cli-socket.ts status   # Check if server is running
 */

import { appendFile } from "fs/promises";

const SOCKET_PATH = process.env.MOTHER_SOCKET || "/tmp/mother.sock";

async function checkStatus() {
  try {
    const response = await fetch(`http://localhost/health`, {
      method: "GET",
      // @ts-ignore - Bun supports unix sockets in fetch
      unix: SOCKET_PATH,
    });
    const status = await response.json();
    console.log("Mother Agent Server Status:");
    console.log(`  Status: ${status.status}`);
    console.log(`  Uptime: ${status.uptime_seconds}s`);
    console.log(`  Requests: ${status.requests_handled}`);
    console.log(`  PID: ${status.pid}`);
    process.exit(0);
  } catch {
    console.log("Mother Agent Server: NOT RUNNING");
    console.log("Start with: bun run server");
    process.exit(1);
  }
}

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
  type: "result" | "error";
  message?: string;
  triage?: {
    promptInjectionScore: number;
    regexFlags: string[];
    reasoning: string;
  };
  explanation?: {
    summary: string;
    affectedPaths: string[];
    relativeToProject: string;
  };
  preferenceCheck?: {
    violatedRules: string[];
    matchedAllowedActions: string[];
    requiresReview: string[];
    decision: "allow" | "deny" | "review";
    reasoning: string;
  };
  hookOutput?: object;
}

async function sendToServer(request: EvalRequest): Promise<EvalResponse> {
  const response = await fetch(`http://localhost${SOCKET_PATH}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
    // @ts-ignore - Bun supports unix sockets in fetch
    unix: SOCKET_PATH,
  });

  return response.json();
}

async function main() {
  const args = process.argv.slice(2);

  // Handle status command
  if (args[0] === "status") {
    await checkStatus();
    return;
  }

  // Read stdin
  let stdinContent = "";
  const file = Bun.file("/dev/stdin");
  const stream = file.stream();
  const reader = stream.getReader();

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      stdinContent += new TextDecoder().decode(value);
    }
  } catch {
    // No stdin available
  }

  // Parse stdin to get hook context
  let hookEventName = "PreToolUse";
  let permissionMode = "default";
  let toolName = "";
  let cwd = process.cwd();

  try {
    const parsed = JSON.parse(stdinContent);
    hookEventName = parsed.hook_event_name || "PreToolUse";
    permissionMode = parsed.permission_mode || "default";
    toolName = parsed.tool_name || "";
    cwd = parsed.cwd || cwd;
  } catch {
    // Not JSON, use defaults
  }

  // Find git root
  try {
    const result = Bun.spawnSync(["git", "rev-parse", "--show-toplevel"], { cwd });
    if (result.exitCode === 0) {
      cwd = result.stdout.toString().trim();
    }
  } catch {
    // Not a git repo
  }

  const request: EvalRequest = {
    type: "eval",
    args,
    stdin: stdinContent,
    cwd,
    hookEventName,
    permissionMode,
    toolName,
  };

  try {
    console.error(`[mother] evaluating ${toolName || "request"}...`);
    const startTime = performance.now();
    const response = await sendToServer(request);
    const elapsed = performance.now() - startTime;

    if (response.type === "error") {
      console.error(`[mother] server error: ${response.message}`);
      console.error(`[mother] decision: ? PASSTHROUGH (server error)`);
      // Log the passthrough
      const logPath = `${import.meta.dir}/log.jsonl`;
      await appendFile(logPath, JSON.stringify({
        timestamp: new Date().toISOString(),
        toolName,
        hookEventName,
        cwd,
        passthrough: true,
        reason: `server error: ${response.message}`,
      }) + "\n");
      console.log(JSON.stringify({}));
      return;
    }

    // Log thought process to stderr
    if (response.triage) {
      const t = response.triage;
      console.error(`[mother] triage: score=${t.promptInjectionScore} flags=[${t.regexFlags.join(",")}]`);
    }
    if (response.explanation) {
      const e = response.explanation;
      console.error(`[mother] explain: ${e.summary}`);
    }
    if (response.preferenceCheck) {
      const p = response.preferenceCheck;
      const icon = p.decision === "allow" ? "✓" : p.decision === "deny" ? "✗" : "?";
      console.error(`[mother] decision: ${icon} ${p.decision.toUpperCase()} (${elapsed.toFixed(0)}ms)`);
      console.error(`[mother] reason: ${p.reasoning}`);
    }

    // Log the result to file
    const logEntry = {
      timestamp: new Date().toISOString(),
      elapsed_ms: elapsed.toFixed(2),
      args,
      stdin: stdinContent,
      cwd,
      ...response,
    };
    const logPath = `${import.meta.dir}/log.jsonl`;
    await appendFile(logPath, JSON.stringify(logEntry, null, 2) + "\n");

    // Output hook response to stdout (this is what Claude Code reads)
    console.log(JSON.stringify(response.hookOutput || {}));
  } catch (error) {
    // Server not running or connection failed
    const message = error instanceof Error ? error.message : "Unknown error";
    let reason: string;

    if (message.includes("ENOENT") || message.includes("ECONNREFUSED")) {
      reason = "server not running";
      console.error(`[mother] server not running`);
    } else {
      reason = `connection error: ${message}`;
      console.error(`[mother] ${reason}`);
    }

    console.error(`[mother] decision: ? PASSTHROUGH (${reason})`);

    // Log the passthrough
    const logPath = `${import.meta.dir}/log.jsonl`;
    await appendFile(logPath, JSON.stringify({
      timestamp: new Date().toISOString(),
      toolName,
      hookEventName,
      cwd,
      passthrough: true,
      reason,
    }) + "\n");

    console.log(JSON.stringify({}));
  }
}

main();
