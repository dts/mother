import { afterEach, describe, expect, test } from "bun:test";
import { selectLlmBackend } from "./llm-backends";
import {
  applyModeLogic,
  buildHookOutput,
  buildDenyWithSuggestions,
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

describe("auto permission mode", () => {
  const ctxForMode = (mode: string) => parseHookContext(JSON.stringify({
    hook_event_name: "PermissionRequest",
    permission_mode: mode,
    tool_name: "Bash",
    tool_input: { command: "ls -la" },
    cwd: "/tmp/project",
  }));

  test("treats Claude's auto mode as acceptEdits, not default", () => {
    expect(ctxForMode("auto").permissionMode).toBe("acceptEdits");
    expect(ctxForMode("autoAccept").permissionMode).toBe("acceptEdits");
  });

  test("auto mode auto-approves review decisions like acceptEdits", () => {
    // The regression: under "default" a review becomes an "ask", so the user
    // gets prompted for everything the LLM is merely unsure about.
    expect(applyModeLogic("review", "default", "Bash").decision).toBe("ask");
    expect(applyModeLogic("review", ctxForMode("auto").permissionMode, "Bash").decision).toBe("allow");
  });

  test("unrecognized modes stay conservative", () => {
    expect(ctxForMode("someFutureMode").permissionMode).toBe("default");
  });
});

describe("evaluator provider selection", () => {
  test("selects the Google ADC backend", () => {
    process.env.MOTHER_LLM_BACKEND = "google-adc";
    expect(selectLlmBackend("claude")).toBe("google-adc");
    process.env.MOTHER_LLM_BACKEND = "adc";
    expect(selectLlmBackend("claude")).toBe("google-adc");
  });

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

describe("deny suggestions", () => {
  const stdinFor = (command: string) => JSON.stringify({ tool_name: "Bash", tool_input: { command } });

  test("suggestions follow the denial reason, not stray words in the command", () => {
    // Observed live: grepping for the word "secret" while denied for git clean
    // came back with secret-handling advice attached to a deletion denial.
    const out = buildDenyWithSuggestions(
      "Bash",
      stdinFor("grep -rn 'secret' . ; git clean -fd"),
      "git clean -f removes untracked files irreversibly.",
    );
    expect(out).toContain("git clean -f removes untracked files irreversibly.");
    expect(out).not.toContain("env variable expansion");
    expect(out).not.toContain("--token");
  });

  test("a secrets denial still gets secrets advice", () => {
    const out = buildDenyWithSuggestions(
      "Bash",
      stdinFor("cat .env"),
      "Writing to secrets/credential files is not allowed.",
    );
    expect(out).toContain("env variable expansion");
  });

  test("a deletion denial does not recommend the thing it just blocked", () => {
    const out = buildDenyWithSuggestions(
      "Bash",
      stdinFor("git clean -fdx"),
      "git clean -f removes untracked files irreversibly.",
    );
    expect(out).not.toContain("Use git clean -fd");
  });
});
