import { query } from "@anthropic-ai/claude-agent-sdk";
import { createAnthropic } from "@ai-sdk/anthropic";
import { gateway } from "@ai-sdk/gateway";
import { createVertex } from "@ai-sdk/google-vertex";
import { generateText } from "ai";
import { readFile, unlink } from "fs/promises";
import type { HookClient } from "./shared";

export type LlmBackendName =
  | "claude-subscription"
  | "codex-subscription"
  | "anthropic-api"
  | "openai-api"
  | "ai-gateway"
  | "google-vertex"
  | "google-adc"
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
  if (configured === "vertex" || configured === "google-vertex" || configured === "vertex-ai" || configured === "gemini" || configured === "google") return "google-vertex";
  if (configured === "adc" || configured === "google-adc" || configured === "vertex-adc" || configured === "gcloud") return "google-adc";
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
    case "google-vertex":
      return { name: backend, generateText: queryVertexAi };
    case "google-adc":
      return { name: backend, generateText: queryVertexAdc };
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

async function queryVertexAi(prompt: string): Promise<string> {
  const project = process.env.MOTHER_VERTEX_PROJECT || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;
  if (!project) throw new Error("Missing GCP project: set MOTHER_VERTEX_PROJECT or GOOGLE_CLOUD_PROJECT");
  const vertex = createVertex({
    project,
    location: process.env.MOTHER_VERTEX_LOCATION || process.env.GOOGLE_CLOUD_LOCATION || "us-central1",
  });
  const { text } = await generateText({
    model: vertex(process.env.MOTHER_VERTEX_MODEL || process.env.MOTHER_LLM_MODEL || "gemini-2.5-flash"),
    prompt,
  });
  return text;
}

/**
 * Vertex AI authenticated through Application Default Credentials.
 *
 * Distinct from the `google-vertex` backend: that one leans on whatever
 * credentials the SDK happens to discover, which silently picks up a service
 * account or a stale key. This one pins auth to ADC (`gcloud auth
 * application-default login`) with an explicit scope, and resolves the project
 * from ADC/gcloud config when it isn't set in the environment — so a machine
 * that can already run `gcloud` needs no extra configuration.
 */
let adcProjectCache: string | null | undefined;

async function detectAdcProject(): Promise<string | null> {
  if (adcProjectCache !== undefined) return adcProjectCache;

  // The ADC file records the quota project for user credentials.
  try {
    const path = process.env.GOOGLE_APPLICATION_CREDENTIALS
      || `${process.env.HOME}/.config/gcloud/application_default_credentials.json`;
    const json = JSON.parse(await readFile(path, "utf-8"));
    if (json.quota_project_id) return (adcProjectCache = json.quota_project_id);
  } catch {
    // Fall through to gcloud.
  }

  try {
    const proc = Bun.spawnSync(["gcloud", "config", "get-value", "project"]);
    const value = new TextDecoder().decode(proc.stdout).trim();
    if (proc.exitCode === 0 && value && value !== "(unset)") return (adcProjectCache = value);
  } catch {
    // No gcloud on PATH.
  }

  return (adcProjectCache = null);
}

async function queryVertexAdc(prompt: string): Promise<string> {
  const project = process.env.MOTHER_VERTEX_PROJECT
    || process.env.GOOGLE_CLOUD_PROJECT
    || process.env.GCLOUD_PROJECT
    || await detectAdcProject();
  if (!project) {
    throw new Error(
      "google-adc: no GCP project. Set MOTHER_VERTEX_PROJECT, or run `gcloud config set project <id>`.",
    );
  }

  const vertex = createVertex({
    project,
    location: process.env.MOTHER_VERTEX_LOCATION || process.env.GOOGLE_CLOUD_LOCATION || "us-central1",
    googleAuthOptions: {
      scopes: ["https://www.googleapis.com/auth/cloud-platform"],
    },
  });

  try {
    const { text } = await generateText({
      model: vertex(process.env.MOTHER_VERTEX_MODEL || process.env.MOTHER_LLM_MODEL || "gemini-2.5-flash"),
      prompt,
    });
    return text;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (/could not load the default credentials|invalid_grant|unable to detect a project|reauth/i.test(message)) {
      throw new Error(
        `google-adc: credentials are not usable (${message}). Run \`gcloud auth application-default login\`.`,
      );
    }
    throw error;
  }
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
