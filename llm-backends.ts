import { query } from "@anthropic-ai/claude-agent-sdk";
import { createAnthropic } from "@ai-sdk/anthropic";
import { gateway } from "@ai-sdk/gateway";
import { generateText } from "ai";
import { readFile, unlink } from "fs/promises";
import type { HookClient } from "./shared";

export type LlmBackendName =
  | "claude-subscription"
  | "codex-subscription"
  | "anthropic-api"
  | "openai-api"
  | "ai-gateway"
  | "local";

export interface LlmBackend {
  name: LlmBackendName;
  generateText(prompt: string): Promise<string>;
}

export interface LlmBackendContext {
  client: HookClient;
  cwd: string;
}

export function selectLlmBackend(client: HookClient): LlmBackendName {
  const configured = (process.env.MOTHER_LLM_BACKEND || process.env.MOTHER_EVAL_PROVIDER || process.env.MOTHER_PROVIDER || "auto").toLowerCase();
  if (configured === "auto") return client === "codex" ? "codex-subscription" : "claude-subscription";
  if (configured === "claude" || configured === "claude-code" || configured === "claude-sub") return "claude-subscription";
  if (configured === "codex" || configured === "chatgpt" || configured === "codex-sub") return "codex-subscription";
  if (configured === "anthropic" || configured === "anthropic-api") return "anthropic-api";
  if (configured === "openai" || configured === "openai-api") return "openai-api";
  if (configured === "gateway" || configured === "ai-gateway" || configured === "vercel") return "ai-gateway";
  if (configured === "local" || configured === "ollama" || configured === "openai-compatible") return "local";
  throw new Error(`Unknown MOTHER_LLM_BACKEND/MOTHER_EVAL_PROVIDER: ${configured}`);
}

export function createLlmBackend(context: LlmBackendContext): LlmBackend {
  const backend = selectLlmBackend(context.client);
  switch (backend) {
    case "claude-subscription":
      return { name: backend, generateText: queryClaudeSubscription };
    case "codex-subscription":
      return { name: backend, generateText: (prompt) => queryCodexSubscription(prompt, context.cwd) };
    case "anthropic-api":
      return { name: backend, generateText: queryAnthropicApi };
    case "openai-api":
      return { name: backend, generateText: queryOpenAiCompatibleApi };
    case "ai-gateway":
      return { name: backend, generateText: queryAiGateway };
    case "local":
      return { name: backend, generateText: queryLocalOpenAiCompatible };
  }
}

export async function queryClaudeSubscription(prompt: string): Promise<string> {
  const q = query({
    prompt,
    options: {
      model: process.env.MOTHER_CLAUDE_MODEL || "claude-haiku-4-5-20251001",
      maxTurns: 1,
      tools: [],
      persistSession: false,
    },
  });

  let result = "";
  for await (const msg of q) {
    if (msg.type === "assistant") {
      for (const block of msg.message.content) {
        if (block.type === "text") result += block.text;
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
    if (exitCode === timedOut) throw new Error(`codex exec timed out after ${timeoutMs}ms`);
    if (exitCode !== 0) {
      const stderrSummary = stderrText.trim().split("\n").slice(-3).join("\n");
      throw new Error(`codex exec exited ${exitCode}${stderrSummary ? `: ${stderrSummary}` : ""}`);
    }
    return (await readFile(outputPath, "utf-8").catch(() => stdoutText)).trim();
  } finally {
    await unlink(outputPath).catch(() => {});
  }
}

async function queryAnthropicApi(prompt: string): Promise<string> {
  const anthropic = createAnthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  const { text } = await generateText({
    model: anthropic(process.env.MOTHER_ANTHROPIC_MODEL || process.env.MOTHER_LLM_MODEL || "claude-haiku-4-5-20251001"),
    prompt,
  });
  return text;
}

async function queryAiGateway(prompt: string): Promise<string> {
  const { text } = await generateText({
    model: gateway(process.env.MOTHER_AI_GATEWAY_MODEL || process.env.MOTHER_LLM_MODEL || "openai/gpt-5.5"),
    prompt,
  });
  return text;
}

async function queryOpenAiCompatibleApi(prompt: string): Promise<string> {
  return queryOpenAiCompatible({
    apiKey: process.env.OPENAI_API_KEY,
    baseUrl: process.env.OPENAI_BASE_URL || "https://api.openai.com/v1",
    model: process.env.MOTHER_OPENAI_MODEL || process.env.MOTHER_LLM_MODEL || "gpt-5.5",
    prompt,
  });
}

async function queryLocalOpenAiCompatible(prompt: string): Promise<string> {
  return queryOpenAiCompatible({
    apiKey: process.env.MOTHER_LOCAL_API_KEY || "local",
    baseUrl: process.env.MOTHER_LOCAL_BASE_URL || "http://localhost:11434/v1",
    model: process.env.MOTHER_LOCAL_MODEL || process.env.MOTHER_LLM_MODEL || "llama3.1",
    prompt,
  });
}

async function queryOpenAiCompatible(args: {
  apiKey?: string;
  baseUrl: string;
  model: string;
  prompt: string;
}): Promise<string> {
  if (!args.apiKey) throw new Error("Missing API key for OpenAI-compatible backend");

  const response = await fetch(`${args.baseUrl.replace(/\/$/, "")}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${args.apiKey}`,
    },
    body: JSON.stringify({
      model: args.model,
      messages: [{ role: "user", content: args.prompt }],
      temperature: 0,
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`OpenAI-compatible backend failed ${response.status}: ${body.slice(0, 500)}`);
  }

  const json = await response.json() as any;
  const content = json?.choices?.[0]?.message?.content;
  if (typeof content !== "string") throw new Error("OpenAI-compatible backend returned no text content");
  return content;
}
