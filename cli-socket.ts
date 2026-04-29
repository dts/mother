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
import { type EvalRequest, type EvalResponse, readStdin, parseHookContext, findGitRoot } from "./shared";

const SOCKET_PATH = process.env.MOTHER_SOCKET || "/tmp/mother.sock";
const TMUX_SESSION = "mother";
const SERVER_SCRIPT = `${import.meta.dir}/agent-server.ts`;

async function checkStatus() {
  try {
    const response = await fetch(`http://localhost/health`, {
      method: "GET",
      // @ts-ignore - Bun supports unix sockets in fetch
      unix: SOCKET_PATH,
    });
    const status = await response.json() as any;
    console.log("Mother Agent Server Status:");
    console.log(`  Status: ${status.status}`);
    console.log(`  Uptime: ${status.uptime_seconds}s`);
    console.log(`  Requests: ${status.requests_handled}`);
    console.log(`  PID: ${status.pid}`);
    process.exit(0);
  } catch {
    console.log("Mother Agent Server: NOT RUNNING");
    console.log(`Start with: tmux new-session -d -s ${TMUX_SESSION} bun ${SERVER_SCRIPT}`);
    process.exit(1);
  }
}

function isServerRunning(): boolean {
  try {
    const result = Bun.spawnSync(["tmux", "has-session", "-t", TMUX_SESSION]);
    return result.exitCode === 0;
  } catch {
    return false;
  }
}

function startServer(): void {
  Bun.spawnSync([
    "tmux", "new-session", "-d", "-s", TMUX_SESSION,
    "bun", SERVER_SCRIPT,
  ]);
}

async function waitForServer(maxWaitMs = 5000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    try {
      const response = await fetch(`http://localhost/health`, {
        method: "GET",
        // @ts-ignore - Bun supports unix sockets in fetch
        unix: SOCKET_PATH,
      });
      if (response.ok) return true;
    } catch {
      // Not ready yet
    }
    await Bun.sleep(200);
  }
  return false;
}

async function ensureServer(): Promise<boolean> {
  // Try a quick health check first
  try {
    const response = await fetch(`http://localhost/health`, {
      method: "GET",
      // @ts-ignore - Bun supports unix sockets in fetch
      unix: SOCKET_PATH,
    });
    if (response.ok) return true;
  } catch {
    // Server not responding
  }

  // Start it in tmux if not already running
  if (!isServerRunning()) {
    console.error(`[mother] server not running, starting in tmux session "${TMUX_SESSION}"...`);
    startServer();
  } else {
    console.error(`[mother] tmux session exists but server not responding, restarting...`);
    Bun.spawnSync(["tmux", "kill-session", "-t", TMUX_SESSION]);
    startServer();
  }

  return waitForServer();
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

  const stdinContent = await readStdin();
  const ctx = parseHookContext(stdinContent);
  const { hookEventName, permissionMode, toolName } = ctx;
  const cwd = findGitRoot(ctx.cwd);

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
      if (p.decision === "ask") {
        console.error('\x1b]99;muster;state=permission\x07');
      } else {
        console.error('\x1b]99;muster;state=busy\x07');
      }
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
    // Server not running or connection failed — try to auto-start
    const message = error instanceof Error ? error.message : "Unknown error";

    if (message.includes("ENOENT") || message.includes("ECONNREFUSED") || message.includes("typo in the url")) {
      const started = await ensureServer();
      if (started) {
        // Retry the request
        try {
          console.error(`[mother] server started, retrying...`);
          const startTime = performance.now();
          const response = await sendToServer(request);
          const elapsed = performance.now() - startTime;

          if (response.type === "error") {
            console.error(`[mother] server error on retry: ${response.message}`);
            console.log(JSON.stringify({}));
            return;
          }

          if (response.preferenceCheck) {
            const p = response.preferenceCheck;
            const icon = p.decision === "allow" ? "✓" : p.decision === "deny" ? "✗" : "?";
            console.error(`[mother] decision: ${icon} ${p.decision.toUpperCase()} (${elapsed.toFixed(0)}ms)`);
            if (p.decision === "ask") {
              console.error('\x1b]99;muster;state=permission\x07');
            } else {
              console.error('\x1b]99;muster;state=busy\x07');
            }
          }

          const logEntry = {
            timestamp: new Date().toISOString(),
            elapsed_ms: (performance.now() - startTime).toFixed(2),
            args,
            stdin: stdinContent,
            cwd,
            autoStarted: true,
            ...response,
          };
          const logPath = `${import.meta.dir}/log.jsonl`;
          await appendFile(logPath, JSON.stringify(logEntry, null, 2) + "\n");

          console.log(JSON.stringify(response.hookOutput || {}));
          return;
        } catch (retryError) {
          console.error(`[mother] retry failed: ${retryError instanceof Error ? retryError.message : retryError}`);
        }
      } else {
        console.error(`[mother] failed to start server`);
      }
    } else {
      console.error(`[mother] connection error: ${message}`);
    }

    console.error(`[mother] decision: ? PASSTHROUGH (server unavailable)`);
    const logPath = `${import.meta.dir}/log.jsonl`;
    await appendFile(logPath, JSON.stringify({
      timestamp: new Date().toISOString(),
      toolName,
      hookEventName,
      cwd,
      passthrough: true,
      reason: message,
    }) + "\n");

    console.log(JSON.stringify({}));
  }
}

main();
