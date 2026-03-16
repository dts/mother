/**
 * Direct API CLI for Mother
 *
 * Uses @ai-sdk/anthropic for LLM evaluation. Requires ANTHROPIC_API_KEY.
 * This is the standalone version that doesn't need the agent server.
 */

import { generateText } from "ai";
import { createAnthropic } from "@ai-sdk/anthropic";
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

// Bun automatically loads .env files
const anthropic = createAnthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});
const haiku = anthropic("claude-haiku-4-5-20251001");

async function queryText(prompt: string): Promise<string> {
  const { text } = await generateText({ model: haiku, prompt });
  return text;
}

async function main() {
  const args = process.argv.slice(2);
  const stdinContent = await readStdin();
  const ctx = parseHookContext(stdinContent);
  let { hookEventName, permissionMode, toolName, cwd } = ctx;
  cwd = findGitRoot(cwd);

  // Pass through tools Mother should never evaluate
  if (PASSTHROUGH_TOOLS.includes(toolName)) {
    console.log(JSON.stringify({}));
    return;
  }

  // Early deterministic Bash checks
  if (toolName === "Bash") {
    const early = earlyBashCheck(hookEventName, permissionMode, stdinContent);
    if (early) {
      console.log(JSON.stringify(early));
      return;
    }
  }

  const inputText = `${args.join(" ")} ${stdinContent}`.trim();

  // Stage 1: Regex triage for prompt injection
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

  // Stage 2: LLM evaluation
  const preferences = await loadPreferences(cwd);
  const prompt = buildEvalPrompt(toolName, args, stdinContent, cwd, preferences);
  const text = await queryText(prompt);
  const result = parseEvalResponse(text);

  // Stage 3: Apply mode logic
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
