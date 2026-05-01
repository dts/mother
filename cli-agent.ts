/**
 * Agent SDK CLI for Mother
 *
 * Uses Claude Code Agent SDK (subscription-based, no API credits).
 * Standalone version — spawns a Claude Code subprocess per query.
 * For better performance, use agent-server.ts + cli-socket.ts instead.
 */

import { query } from "@anthropic-ai/claude-agent-sdk";
import { appendFile } from "fs/promises";
import { runAnalysisPipeline } from "./analysis-pipeline";
import {
  PASSTHROUGH_TOOLS,
  buildHookOutput,
  readStdin,
  parseHookContext,
  findGitRoot,
  loadPreferences,
  applyModeLogic,
  earlyBashCheck,
  buildDenyWithSuggestions,
  extractPathsFromStdin,
  evaluateDeterministic,
} from "./shared";

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

async function main() {
  const args = process.argv.slice(2);
  const stdinContent = await readStdin();
  const ctx = parseHookContext(stdinContent);
  let { client, hookEventName, permissionMode, toolName, cwd } = ctx;
  cwd = findGitRoot(cwd);

  if (PASSTHROUGH_TOOLS.includes(toolName)) {
    console.log(JSON.stringify({}));
    return;
  }

  const deterministic = evaluateDeterministic(stdinContent);
  if (deterministic) {
    const modeDecision = deterministic.decision === "ask" ? "review" as const
      : deterministic.decision === "deny" ? "deny" as const
      : "allow" as const;
    const modeResult = applyModeLogic(modeDecision, permissionMode, toolName, extractPathsFromStdin(stdinContent));
    let reason = modeResult.reason || deterministic.reason;
    if (modeResult.decision === "deny") {
      reason = buildDenyWithSuggestions(toolName, stdinContent, reason);
    }
    console.log(JSON.stringify(buildHookOutput(hookEventName, modeResult.decision, reason)));
    return;
  }

  if (toolName === "Bash") {
    const early = earlyBashCheck(hookEventName, permissionMode, stdinContent);
    if (early) {
      console.log(JSON.stringify(early));
      return;
    }
  }

  const preferences = await loadPreferences(cwd, client);
  const backend = { name: "claude-subscription" as const, generateText: queryText };
  const result = await runAnalysisPipeline(backend, { args, stdin: stdinContent, cwd, client, toolName, preferences });

  const modeResult = applyModeLogic(result.preferenceCheck.decision, permissionMode, toolName, extractPathsFromStdin(stdinContent));
  let reason = modeResult.reason || result.denyMessage || result.preferenceCheck.reasoning;
  if (modeResult.decision === "deny") {
    reason = buildDenyWithSuggestions(toolName, stdinContent, reason);
  }

  const hookOutput = buildHookOutput(hookEventName, modeResult.decision, reason);

  const logPath = `${import.meta.dir}/log.jsonl`;
  await appendFile(logPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    args, stdin: stdinContent, cwd,
    backend: backend.name,
    triage: result.triage,
    explanation: result.explanation,
    preferenceCheck: result.preferenceCheck,
    hookOutput,
  }, null, 2) + "\n");

  console.log(JSON.stringify(hookOutput));
}

main();
