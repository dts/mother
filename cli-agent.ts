/**
 * Agent SDK CLI for Mother
 *
 * Uses Claude Code Agent SDK (subscription-based, no API credits).
 * Standalone version — spawns a Claude Code subprocess per query.
 * For better performance, use agent-server.ts + cli-socket.ts instead.
 */

import { query } from "@anthropic-ai/claude-agent-sdk";
import { appendFile } from "fs/promises";
import {
  type AnalysisResult,
  PASSTHROUGH_TOOLS,
  regexTriage,
  buildHookOutput,
  buildEvalPrompt,
  parseEvalResponse,
  readStdin,
  parseHookContext,
  findGitRoot,
  loadPreferences,
  applyModeLogic,
  earlyBashCheck,
  buildDenyWithSuggestions,
  extractPathsFromStdin,
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
  let { hookEventName, permissionMode, toolName, cwd } = ctx;
  cwd = findGitRoot(cwd);

  if (PASSTHROUGH_TOOLS.includes(toolName)) {
    console.log(JSON.stringify({}));
    return;
  }

  if (toolName === "Bash") {
    const early = earlyBashCheck(hookEventName, permissionMode, stdinContent);
    if (early) {
      console.log(JSON.stringify(early));
      return;
    }
  }

  const inputText = `${args.join(" ")} ${stdinContent}`.trim();

  const regexFlags = regexTriage(inputText);
  if (regexFlags.length > 0) {
    const hookOutput = buildHookOutput(
      hookEventName,
      "ask",
      `Potential prompt injection: Suspicious patterns: ${regexFlags.join(", ")}`,
    );
    const logPath = `${import.meta.dir}/log.jsonl`;
    await appendFile(logPath, JSON.stringify({
      timestamp: new Date().toISOString(),
      args, stdin: stdinContent, cwd,
      triage: { promptInjectionScore: 0, regexFlags, reasoning: "Regex flags" },
      hookOutput,
    }, null, 2) + "\n");
    console.log(JSON.stringify(hookOutput));
    return;
  }

  const preferences = await loadPreferences(cwd);
  const prompt = buildEvalPrompt(toolName, args, stdinContent, cwd, preferences);
  const text = await queryText(prompt);
  const result = parseEvalResponse(text);

  const modeResult = applyModeLogic(result.decision, permissionMode, toolName, extractPathsFromStdin(stdinContent));
  let reason = modeResult.reason || result.denyMessage || result.reasoning;
  if (modeResult.decision === "deny") {
    reason = buildDenyWithSuggestions(toolName, stdinContent, reason);
  }

  const hookOutput = buildHookOutput(hookEventName, modeResult.decision, reason);

  const logPath = `${import.meta.dir}/log.jsonl`;
  await appendFile(logPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    args, stdin: stdinContent, cwd,
    triage: { promptInjectionScore: 0, regexFlags: [], reasoning: "passed" },
    explanation: { summary: result.summary, affectedPaths: [], relativeToProject: cwd },
    preferenceCheck: { violatedRules: [], matchedAllowedActions: [], requiresReview: [], decision: result.decision, reasoning: result.reasoning },
    hookOutput,
  }, null, 2) + "\n");

  console.log(JSON.stringify(hookOutput));
}

main();
