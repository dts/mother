import { query } from "@anthropic-ai/claude-agent-sdk";
import { readFile, unlink } from "fs/promises";
import type { HookClient } from "./shared";

export type EvalProvider = "claude" | "codex";

export interface EvalProviderContext {
  client: HookClient;
  cwd: string;
}

export function selectEvalProvider(client: HookClient): EvalProvider {
  const configured = (process.env.MOTHER_EVAL_PROVIDER || process.env.MOTHER_PROVIDER || "auto").toLowerCase();
  if (configured === "claude" || configured === "anthropic") return "claude";
  if (configured === "codex" || configured === "openai") return "codex";
  return client === "codex" ? "codex" : "claude";
}

export async function queryEvalProvider(prompt: string, context: EvalProviderContext): Promise<string> {
  const provider = selectEvalProvider(context.client);
  if (provider === "codex") {
    return queryCodexSubscription(prompt, context.cwd);
  }
  return queryClaudeSubscription(prompt);
}

export async function queryClaudeSubscription(prompt: string): Promise<string> {
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

async function queryCodexSubscription(prompt: string, cwd: string): Promise<string> {
  const outputPath = `/tmp/mother-codex-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.txt`;
  const timeoutMs = Number(process.env.MOTHER_CODEX_TIMEOUT_MS || 120_000);
  const modelArgs = process.env.MOTHER_CODEX_MODEL ? ["--model", process.env.MOTHER_CODEX_MODEL] : [];

  const proc = Bun.spawn([
    "codex",
    "exec",
    "--ask-for-approval", "never",
    "--sandbox", "read-only",
    "--skip-git-repo-check",
    "--ephemeral",
    "--ignore-user-config",
    "--ignore-rules",
    "--disable", "codex_hooks",
    "--color", "never",
    "--output-last-message", outputPath,
    ...modelArgs,
    "-",
  ], {
    cwd,
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, NO_COLOR: "1" },
  });

  proc.stdin.write(prompt);
  proc.stdin.end();

  const timedOut = Symbol("timedOut");
  const timeout = new Promise<typeof timedOut>((resolve) => {
    setTimeout(() => {
      proc.kill();
      resolve(timedOut);
    }, timeoutMs);
  });

  const [exitCode, stdoutText, stderrText] = await Promise.all([
    Promise.race([proc.exited, timeout]),
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);

  try {
    if (exitCode === timedOut) {
      throw new Error(`codex exec timed out after ${timeoutMs}ms`);
    }
    if (exitCode !== 0) {
      const stderrSummary = stderrText.trim().split("\n").slice(-3).join("\n");
      throw new Error(`codex exec exited ${exitCode}${stderrSummary ? `: ${stderrSummary}` : ""}`);
    }

    return (await readFile(outputPath, "utf-8").catch(() => stdoutText)).trim();
  } finally {
    await unlink(outputPath).catch(() => {});
  }
}
