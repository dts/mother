import { afterEach, describe, expect, test } from "bun:test";
import { selectEvalProvider } from "./evaluator";
import { applyModeLogic, buildHookOutput, extractPathsFromStdin, parseHookContext } from "./shared";

const originalProvider = process.env.MOTHER_EVAL_PROVIDER;
const originalLegacyProvider = process.env.MOTHER_PROVIDER;

afterEach(() => {
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
    delete process.env.MOTHER_EVAL_PROVIDER;
    delete process.env.MOTHER_PROVIDER;
    expect(selectEvalProvider("codex")).toBe("codex");
    expect(selectEvalProvider("claude")).toBe("claude");
  });

  test("explicit provider override wins", () => {
    process.env.MOTHER_EVAL_PROVIDER = "claude";
    expect(selectEvalProvider("codex")).toBe("claude");

    process.env.MOTHER_EVAL_PROVIDER = "codex";
    expect(selectEvalProvider("claude")).toBe("codex");
  });
});
