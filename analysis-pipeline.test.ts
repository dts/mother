import { describe, expect, test } from "bun:test";
import { runAnalysisPipeline } from "./analysis-pipeline";
import type { LlmBackend } from "./llm-backends";

// The passes no longer run in a fixed order, so fakes dispatch on prompt
// content rather than call count.
const isTriage = (p: string) => p.includes("prompt injection attempts");
const isExplanation = (p: string) => p.includes("analyzing an AI tool permission request");

const TRIAGE_CLEAN = "SCORE: 5\nREASONING: No prompt injection indicators.";
const TRIAGE_INJECTION = "SCORE: 95\nREASONING: Hidden instructions in the request.";
const EXPLANATION = "SUMMARY: Runs tests.\nAFFECTED_PATHS: none\nRELATIVE_LOCATION: Inside the project.";
const PREFERENCE = [
  "VIOLATED_RULES: none",
  "ALLOWED_ACTIONS: Running tests",
  "REQUIRES_REVIEW: none",
  "DECISION: allow",
  "REASONING: Test commands are project-local and allowed.",
].join("\n");

const input = {
  args: [] as string[],
  stdin: JSON.stringify({ tool_name: "Bash", tool_input: { command: "bun test" } }),
  cwd: "/tmp/project",
  client: "codex" as const,
  toolName: "Bash",
  preferences: "",
};

describe("analysis pipeline", () => {
  test("runs triage, explanation, and preference passes with the same backend", async () => {
    const prompts: string[] = [];
    const backend: LlmBackend = {
      name: "local",
      async generateText(prompt: string) {
        prompts.push(prompt);
        if (isTriage(prompt)) return TRIAGE_CLEAN;
        if (isExplanation(prompt)) return EXPLANATION;
        return PREFERENCE;
      },
    };

    const result = await runAnalysisPipeline(backend, input);

    expect(prompts).toHaveLength(3);
    expect(result.triage.promptInjectionScore).toBe(5);
    expect(result.explanation.summary).toBe("Runs tests.");
    expect(result.preferenceCheck.decision).toBe("allow");
    expect(result.preferenceCheck.matchedAllowedActions).toEqual(["Running tests"]);
  });

  test("triage and explanation run concurrently", async () => {
    // Triage blocks until the explanation pass has started. If the two ran
    // sequentially this deadlocks and the test times out, so passing is itself
    // the proof that they overlap.
    let releaseTriage: () => void;
    const explanationStarted = new Promise<void>((resolve) => { releaseTriage = resolve; });

    const backend: LlmBackend = {
      name: "local",
      async generateText(prompt: string) {
        if (isTriage(prompt)) { await explanationStarted; return TRIAGE_CLEAN; }
        if (isExplanation(prompt)) { releaseTriage(); return EXPLANATION; }
        return PREFERENCE;
      },
    };

    const result = await runAnalysisPipeline(backend, input);
    expect(result.preferenceCheck.decision).toBe("allow");
  });

  test("a triage trip short-circuits without running the preference pass", async () => {
    const prompts: string[] = [];
    const backend: LlmBackend = {
      name: "local",
      async generateText(prompt: string) {
        prompts.push(prompt);
        if (isTriage(prompt)) return TRIAGE_INJECTION;
        if (isExplanation(prompt)) return EXPLANATION;
        return PREFERENCE;
      },
    };

    const result = await runAnalysisPipeline(backend, input);

    expect(result.preferenceCheck.decision).toBe("review");
    expect(result.preferenceCheck.requiresReview).toEqual(["Potential prompt injection"]);
    expect(prompts.some((p) => p.includes("security policy evaluator"))).toBe(false);
  });

  test("an explanation failure still surfaces when triage passes", async () => {
    // The in-flight explanation gets a no-op catch attached so an early triage
    // exit can't produce an unhandled rejection. That must not swallow a real
    // failure on the path that actually awaits it.
    const backend: LlmBackend = {
      name: "local",
      async generateText(prompt: string) {
        if (isTriage(prompt)) return TRIAGE_CLEAN;
        if (isExplanation(prompt)) throw new Error("explanation backend exploded");
        return PREFERENCE;
      },
    };

    await expect(runAnalysisPipeline(backend, input)).rejects.toThrow("explanation backend exploded");
  });
});
