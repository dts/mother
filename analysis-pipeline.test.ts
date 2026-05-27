import { describe, expect, test } from "bun:test";
import { describeBranchSpecificScripts, runAnalysisPipeline } from "./analysis-pipeline";
import type { LlmBackend } from "./llm-backends";

describe("analysis pipeline", () => {
  test("runs triage, explanation, and preference passes with the same backend", async () => {
    const prompts: string[] = [];
    const backend: LlmBackend = {
      name: "local",
      async generateText(prompt: string) {
        prompts.push(prompt);
        if (prompts.length === 1) {
          return "SCORE: 5\nREASONING: No prompt injection indicators.";
        }
        if (prompts.length === 2) {
          return "SUMMARY: Runs tests.\nAFFECTED_PATHS: none\nRELATIVE_LOCATION: Inside the project.";
        }
        return [
          "VIOLATED_RULES: none",
          "ALLOWED_ACTIONS: Running tests",
          "REQUIRES_REVIEW: none",
          "DECISION: allow",
          "REASONING: Test commands are project-local and allowed.",
        ].join("\n");
      },
    };

    const result = await runAnalysisPipeline(backend, {
      args: [],
      stdin: JSON.stringify({ tool_name: "Bash", tool_input: { command: "bun test" } }),
      cwd: "/tmp/project",
      client: "codex",
      toolName: "Bash",
      preferences: "",
    });

    expect(prompts).toHaveLength(3);
    expect(result.triage.promptInjectionScore).toBe(5);
    expect(result.explanation.summary).toBe("Runs tests.");
    expect(result.preferenceCheck.decision).toBe("allow");
    expect(result.preferenceCheck.matchedAllowedActions).toEqual(["Running tests"]);
    expect(prompts[1]).toContain("Repository context:");
    expect(prompts[2]).toContain("If the request could execute or rely on a script file");
  });

  test("reports when no upstream main/master ref is available", () => {
    const tempDir = `/tmp/mother-no-upstream-${Date.now()}`;

    expect(describeBranchSpecificScripts(tempDir)).toBe(
      "Repository context: No local upstream main/master ref was found for branch comparison.",
    );
  });
});
