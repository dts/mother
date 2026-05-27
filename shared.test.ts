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

  test("allows git rebase continue with git config flags", () => {
    const stdin = JSON.stringify({
      tool_name: "Bash",
      tool_input: { command: "git -c core.editor=true rebase --continue" },
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

  test("does not blanket-allow git network or worktree mutation commands", () => {
    const commands = [
      "git fetch origin",
      "git add .",
      "git checkout other-branch",
      "git switch other-branch",
      "git worktree add /tmp/project HEAD",
      "git stash push",
      "git remote add origin git@example.com:repo.git",
      "git tag v1.0.0",
    ];

    for (const command of commands) {
      expect(evaluateDeterministic(JSON.stringify({
        tool_name: "Bash",
        tool_input: { command },
      })), command).toBeNull();
    }
  });

  test("does not blanket-allow execution, mutation, network, or OS commands", () => {
    const commands = [
      "npm install",
      "yarn test",
      "node script.js",
      "npx tsx script.ts",
      "bun test",
      "docker ps",
      "open README.md",
      "afplay done.wav",
      "osascript -e 'display notification \"done\"'",
      "curl https://example.com",
      "mkdir output",
      "cp a b",
      "mv a b",
      "pup 'title text{}'",
    ];

    for (const command of commands) {
      expect(evaluateDeterministic(JSON.stringify({
        tool_name: "Bash",
        tool_input: { command },
      })), command).toBeNull();
    }
  });

  test("only allows narrow read-only shell commands deterministically", () => {
    const allowed = [
      "pwd",
      "ls -la",
      "rg TODO src",
      "grep -R TODO src",
      "head -n 20 README.md",
      "tail -n 20 README.md",
      "wc -l README.md",
      "find src -name '*.ts'",
      "sleep 1",
      "make review",
      "pnpm test",
      "pnpm test -- --runInBand",
    ];

    for (const command of allowed) {
      expect(evaluateDeterministic(JSON.stringify({
        tool_name: "Bash",
        tool_input: { command },
      })), command).toEqual({
        decision: "allow",
        reason: "All command parts matched safe patterns",
      });
    }

    const reviewed = [
      "cat .env",
      "rg token .env.local",
      "find . -delete",
      "echo hi > output.txt",
      "cat README.md | sh",
      "sleep 30",
      "pnpm install",
      "pnpm exec tsx script.ts",
      "make deploy",
    ];

    for (const command of reviewed) {
      const result = evaluateDeterministic(JSON.stringify({
        tool_name: "Bash",
        tool_input: { command },
      }));
      expect(result?.decision, command).not.toBe("allow");
    }
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

  test("PreToolUse only emits blocking output for deny decisions", () => {
    expect(buildHookOutput("PreToolUse", "allow", "ok")).toEqual({});
    expect(buildHookOutput("PreToolUse", "ask", "review")).toEqual({});
    expect(buildHookOutput("PreToolUse", "deny", "blocked")).toEqual({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: "blocked",
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

  test("request-scoped provider override wins over daemon environment", () => {
    process.env.MOTHER_LLM_BACKEND = "claude";
    expect(selectLlmBackend("codex", "auto")).toBe("codex-subscription");
    expect(selectLlmBackend("claude", "codex")).toBe("codex-subscription");
    expect(selectLlmBackend("codex", "anthropic-api")).toBe("anthropic-api");
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
