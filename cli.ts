/**
 * Direct API CLI for Mother
 *
 * Standalone version that doesn't need the agent server.
 */

import { appendFile } from "fs/promises";
import { runAnalysisPipeline } from "./analysis-pipeline";
import { createLlmBackend } from "./llm-backends";
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
import { notifyMuster } from "./muster";

async function main() {
  const args = process.argv.slice(2);
  const stdinContent = await readStdin();
  const ctx = parseHookContext(stdinContent);
  let { client, hookEventName, permissionMode, toolName, cwd } = ctx;
  cwd = findGitRoot(cwd);

  // Clear any stale "permission" state up front — by the time mother is
  // running, claude is actively trying to do something, so the dot should
  // not still say "needs human attention" from a previous turn.
  await notifyMuster("working");

  // Pass through tools Mother should never evaluate
  if (PASSTHROUGH_TOOLS.includes(toolName)) {
    console.log(JSON.stringify({}));
    return;
  }

  // Stage 0: Deterministic rules engine (no LLM needed)
  const deterministic = evaluateDeterministic(stdinContent);
  if (deterministic) {
    // Apply mode logic on top of deterministic decision
    const modeDecision = deterministic.decision === "ask" ? "review" as const
      : deterministic.decision === "deny" ? "deny" as const
      : "allow" as const;
    const modeResult = applyModeLogic(modeDecision, permissionMode, toolName, extractPathsFromStdin(stdinContent));
    let reason = modeResult.reason || deterministic.reason;
    if (modeResult.decision === "deny") {
      reason = buildDenyWithSuggestions(toolName, stdinContent, reason);
    }
    const hookOutput = buildHookOutput(hookEventName, modeResult.decision, reason);

    const logPath = `${import.meta.dir}/log.jsonl`;
    await appendFile(logPath, JSON.stringify({
      timestamp: new Date().toISOString(),
      tool: toolName, source: "deterministic",
      decision: modeResult.decision, reason,
      command: toolName === "Bash" ? stdinContent.match(/"command"\s*:\s*"([^"]+)"/)?.[1] : undefined,
    }) + "\n");

    await notifyMuster(
      modeResult.decision === "ask" ? "permission" : "working",
      reason,
    );

    console.log(JSON.stringify(hookOutput));
    return;
  }

  // Early deterministic Bash checks (legacy, for cases not covered above)
  if (toolName === "Bash") {
    const early = earlyBashCheck(hookEventName, permissionMode, stdinContent);
    if (early) {
      console.log(JSON.stringify(early));
      return;
    }
  }

  // Stage 1-3: LLM triage, explanation, and policy evaluation
  const preferences = await loadPreferences(cwd, client);
  const backend = createLlmBackend({ client, cwd });
  const result = await runAnalysisPipeline(backend, { args, stdin: stdinContent, cwd, client, toolName, preferences });

  // Stage 4: Apply mode logic
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

  await notifyMuster(
    modeResult.decision === "ask" ? "permission" : "working",
    reason,
  );

  console.log(JSON.stringify(hookOutput));
}

main();
