import { afterEach, describe, expect, test } from "bun:test";
import { selectLlmBackend } from "./llm-backends";
import {
  applyModeLogic,
  buildHookOutput,
  evaluateDeterministic,
  extractPathsFromStdin,
  parseHookContext,
} from "./shared";

const originalBackend = process.env.MOTHER_LLM_BACKEND;
const originalProvider = process.env.MOTHER_EVAL_PROVIDER;
const originalLegacyProvider = process.env.MOTHER_PROVIDER;

afterEach(() => {
  if (originalBackend === undefined) {
    delete process.env.MOTHER_LLM_BACKEND;
  } else {
    process.env.MOTHER_LLM_BACKEND = originalBackend;
  }
  if (originalProvider === undefined) {
    delete process.env.MOTHER_EVAL_PROVIDER;
  } else {
    process.env.MOTHER_EVAL_PROVIDER = originalProvider;
  }
  if (originalLegacyProvider === undefined) {
    delete process.env.MOTHER_PROVIDER;
  } else {
    process.env.MOTHER_PROVIDER = originalLegacyProvider;
  }
});

describe("Codex hook normalization", () => {
  test("detects Codex PermissionRequest payloads", () => {
    const ctx = parseHookContext(JSON.stringify({
      turn_id: "turn_123",
      hook_event_name: "PermissionRequest",
      tool_name: "Bash",
      tool_input: {
        command: "git push origin feature",
        description: "Run outside sandbox",
      },
      cwd: "/tmp/project",
    }));

    expect(ctx).toEqual({
      client: "codex",
      hookEventName: "PermissionRequest",
      permissionMode: "codex",
      toolName: "Bash",
      cwd: "/tmp/project",
    });
  });

  test("treats apply_patch as a Codex write tool", () => {
    const ctx = parseHookContext(JSON.stringify({
      hook_event_name: "PermissionRequest",
      tool_name: "apply_patch",
      tool_input: {
        command: "*** Begin Patch\n*** Update File: README.md\n@@\n test\n*** End Patch",
      },
    }));

    expect(ctx.client).toBe("codex");
    expect(ctx.permissionMode).toBe("codex");
    expect(extractPathsFromStdin(JSON.stringify({
      tool_input: {
        command: "*** Begin Patch\n*** Update File: README.md\n*** End Patch",
      },
    }))).toContain("README.md");
  });

  test("normalizes Codex exec_command payloads", () => {
    const stdin = JSON.stringify({
      turn_id: "turn_456",
      hook_event_name: "PermissionRequest",
      tool_name: "exec_command",
      tool_input: {
        cmd: "GIT_EDITOR=true git rebase --continue",
        description: "Continue the rebase after resolving conflicts.",
      },
      cwd: "/tmp/project",
    });

    const ctx = parseHookContext(stdin);
    expect(ctx).toEqual({
      client: "codex",
      hookEventName: "PermissionRequest",
      permissionMode: "codex",
      toolName: "Bash",
      cwd: "/tmp/project",
    });
    expect(evaluateDeterministic(stdin)).toEqual({
      decision: "allow",
      reason: "All command parts matched safe patterns",
    });
  });

  test("deterministic checks support cmd and still deny force pushes", () => {
    const stdin = JSON.stringify({
      tool_name: "exec_command",
      tool_input: { cmd: "git push --force origin feature" },
    });

    expect(evaluateDeterministic(stdin)).toEqual({
      decision: "deny",
      reason: "Force push is ALWAYS blocked.",
    });
  });

  test("allows local amend commits", () => {
    const stdin = JSON.stringify({
      tool_name: "Bash",
      tool_input: { command: "git commit --amend --no-edit" },
    });

    expect(evaluateDeterministic(stdin)).toEqual({
      decision: "allow",
      reason: "All command parts matched safe patterns",
    });
  });

  test("extracts paths from Codex cmd input", () => {
    const paths = extractPathsFromStdin(JSON.stringify({
      tool_input: { cmd: "sed -n '1,20p' ./src/index.ts" },
    }));

    expect(paths).toContain("./src/index.ts");
  });

  test("codex mode maps policy decisions directly to PermissionRequest output", () => {
    const modeResult = applyModeLogic("allow", "codex", "apply_patch", ["README.md"]);
    const hookOutput = buildHookOutput("PermissionRequest", modeResult.decision, "ok");

    expect(modeResult).toEqual({ decision: "allow" });
    expect(hookOutput).toEqual({
      hookSpecificOutput: {
        hookEventName: "PermissionRequest",
        decision: { behavior: "allow" },
      },
    });
  });
});

describe("evaluator provider selection", () => {
  test("auto mode uses Codex for Codex clients", () => {
    delete process.env.MOTHER_LLM_BACKEND;
    delete process.env.MOTHER_EVAL_PROVIDER;
    delete process.env.MOTHER_PROVIDER;
    expect(selectLlmBackend("codex")).toBe("codex-subscription");
    expect(selectLlmBackend("claude")).toBe("claude-subscription");
  });

  test("explicit provider override wins", () => {
    process.env.MOTHER_LLM_BACKEND = "claude";
    expect(selectLlmBackend("codex")).toBe("claude-subscription");

    process.env.MOTHER_LLM_BACKEND = "codex";
    expect(selectLlmBackend("claude")).toBe("codex-subscription");
  });

  test("supports API and local backends", () => {
    process.env.MOTHER_LLM_BACKEND = "anthropic-api";
    expect(selectLlmBackend("codex")).toBe("anthropic-api");
    process.env.MOTHER_LLM_BACKEND = "openai-api";
    expect(selectLlmBackend("claude")).toBe("openai-api");
    process.env.MOTHER_LLM_BACKEND = "local";
    expect(selectLlmBackend("claude")).toBe("local");
  });
});
