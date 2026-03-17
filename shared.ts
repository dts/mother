import { readFile } from "fs/promises";

// --- Types ---

export interface Triage {
  promptInjectionScore: number;
  regexFlags: string[];
  reasoning: string;
}

export interface Explanation {
  summary: string;
  affectedPaths: string[];
  relativeToProject: string;
}

export interface PreferenceCheck {
  violatedRules: string[];
  matchedAllowedActions: string[];
  requiresReview: string[];
  decision: "allow" | "deny" | "review";
  reasoning: string;
}

export interface AnalysisResult {
  timestamp: string;
  args: string[];
  stdin: string;
  cwd: string;
  triage: Triage;
  explanation: Explanation;
  preferenceCheck: PreferenceCheck;
}

export interface EvalRequest {
  type: "eval";
  args: string[];
  stdin: string;
  cwd: string;
  hookEventName: string;
  permissionMode: string;
  toolName: string;
}

export interface EvalResponse {
  type: "result" | "error";
  message?: string;
  triage?: Triage;
  explanation?: Explanation;
  preferenceCheck?: PreferenceCheck;
  hookOutput?: object;
}

export interface EvalResult {
  summary: string;
  decision: "allow" | "deny" | "review";
  reasoning: string;
  denyMessage?: string;
}

// --- Constants ---

export const SUSPICIOUS_PATTERNS = [
  { pattern: /\]\]\s*\[\[/i, flag: "bracket-injection" },
  { pattern: /<\/?system>/i, flag: "xml-system-tag" },
  { pattern: /<\/?system-prompt>/i, flag: "xml-system-tag" },
  { pattern: /<\/?assistant>/i, flag: "xml-role-tag" },
  { pattern: /<\/?human>/i, flag: "xml-role-tag" },
  { pattern: /<\/?user>/i, flag: "xml-role-tag" },
  { pattern: /---\s*(END|BEGIN)\s+(SYSTEM|USER|ASSISTANT)/i, flag: "fake-delimiter" },
];

export const READ_ONLY_TOOLS = ["Read", "Glob", "Grep", "LS", "WebFetch", "WebSearch", "Task", "TodoRead"];
export const WRITE_TOOLS = ["Edit", "Write", "NotebookEdit"];
export const PASSTHROUGH_TOOLS = ["AskUserQuestion"];

// --- Shared prompt for LLM evaluation ---

export function buildEvalPrompt(
  toolName: string,
  args: string[],
  stdin: string,
  cwd: string,
  preferences: string
): string {
  return `You are a security policy evaluator for a developer's local machine.

Tool: ${toolName}
Working directory: ${cwd}
Arguments: ${JSON.stringify(args)}

Request details:
<request>
${stdin.slice(0, 3000)}
</request>

${preferences ? `Additional preferences:\n<preferences>\n${preferences}\n</preferences>` : ""}

CORE PRINCIPLE: Allow by default. Only flag genuinely dangerous operations.

ALWAYS ALLOW (no exceptions):
- Read operations on non-sensitive files (code, configs, docs, logs, temp files, etc.)
- Listing directories, searching, grepping
- Building, compiling, bundling code
- Running tests, linters, formatters
- Package management (npm, bun, pip, cargo, etc.) for project dependencies
- Development servers, watchers, hot reload
- Git operations (including push - user already authenticated)
- Mobile dev tools (Xcode, Android Studio, Capacitor, Gradle, etc.)
- File writes/edits within or near the project
- Running project scripts
- Reading/writing temp files (/tmp, /var/folders, etc.)

DENY if the action:
- Exposes secrets to the LLM (reading .env, credentials.json, *_secret*, *.pem, *.key, id_rsa, etc. WITHOUT obscuring values)
  → Use DENY_MESSAGE: "DO NOT EXPOSE SECRETS. USE ENV VARIABLE EXPANSION OR OBSCURE WITH sed 's/=.*/=***/'."
- Uses secret values inline (e.g., curl -H "Authorization: Bearer sk-...")
  → Use DENY_MESSAGE: "DO NOT EXPOSE SECRETS. USE ENV VARIABLE EXPANSION OR OBSCURE WITH sed 's/=.*/=***/'."
- Exfiltrates data (curl/wget POST-ing files to remote servers)
- Mass deletes outside project (rm -rf /, rm -rf ~, etc.)
- Modifies system config files (/etc/*, /usr/*, ~/.bashrc, ~/.zshrc, etc.)

REVIEW if the action:
- Installs global packages (npm -g, pip install --user, brew install, etc.)

Respond in this EXACT format:
SUMMARY: [1 sentence description of what this does]
DECISION: [allow|deny|review]
REASONING: [1 sentence explanation]
DENY_MESSAGE: [optional - only if DECISION is deny, the message to show]`;
}

export function parseEvalResponse(text: string): EvalResult {
  const summaryMatch = text.match(/SUMMARY:\s*(.+)/);
  const decisionMatch = text.match(/DECISION:\s*(\w+)/);
  const reasoningMatch = text.match(/REASONING:\s*(.+)/);
  const denyMessageMatch = text.match(/DENY_MESSAGE:\s*(.+)/);

  let decision = decisionMatch?.[1]?.toLowerCase() as "allow" | "deny" | "review";
  if (!["allow", "deny", "review"].includes(decision)) {
    decision = "review";
  }

  return {
    summary: summaryMatch?.[1] || "Unable to summarize",
    decision,
    reasoning: reasoningMatch?.[1] || "No reasoning provided",
    denyMessage: denyMessageMatch?.[1],
  };
}

// --- Shared functions ---

export function regexTriage(input: string): string[] {
  return SUSPICIOUS_PATTERNS
    .filter(({ pattern }) => pattern.test(input))
    .map(({ flag }) => flag);
}

export function buildHookOutput(
  hookEventName: string,
  decision: "allow" | "deny" | "ask",
  reason: string
) {
  if (hookEventName === "PermissionRequest") {
    if (decision === "ask") {
      return {};
    }
    return {
      hookSpecificOutput: {
        hookEventName: "PermissionRequest",
        decision: {
          behavior: decision,
          message: reason,
        },
      },
    };
  }

  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
  };
}

export async function readStdin(): Promise<string> {
  let content = "";
  const file = Bun.file("/dev/stdin");
  const stream = file.stream();
  const reader = stream.getReader();

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      content += new TextDecoder().decode(value);
    }
  } catch {
    // No stdin available
  }
  return content;
}

export function parseHookContext(stdinContent: string): {
  hookEventName: string;
  permissionMode: string;
  toolName: string;
  cwd: string;
} {
  let hookEventName = "PreToolUse";
  let permissionMode = "default";
  let toolName = "";
  let cwd = process.cwd();

  try {
    const parsed = JSON.parse(stdinContent);
    hookEventName = parsed.hook_event_name || "PreToolUse";
    const rawMode = parsed.permission_mode || "default";
    if (rawMode === "plan" || rawMode === "planMode") {
      permissionMode = "plan";
    } else if (rawMode === "acceptEdits" || rawMode === "acceptAllEdits") {
      permissionMode = "acceptEdits";
    } else {
      permissionMode = "default";
    }
    toolName = parsed.tool_name || "";
    cwd = parsed.cwd || cwd;
  } catch {
    // Not JSON, use defaults
  }
  return { hookEventName, permissionMode, toolName, cwd };
}

export function findGitRoot(cwd: string): string {
  try {
    const result = Bun.spawnSync(["git", "rev-parse", "--show-toplevel"], { cwd });
    if (result.exitCode === 0) {
      return result.stdout.toString().trim();
    }
  } catch {
    // Not a git repo
  }
  return cwd;
}

export async function loadPreferences(cwd: string): Promise<string> {
  const homeDir = process.env.HOME || process.env.USERPROFILE || "~";
  try {
    return await readFile(`${cwd}/.claude/security-preferences.md`, "utf-8");
  } catch {
    try {
      return await readFile(`${homeDir}/.claude/security-preferences.md`, "utf-8");
    } catch {
      return "";
    }
  }
}

/**
 * Extract file paths from tool_input in the stdin JSON.
 */
export function extractPathsFromStdin(stdin: string): string[] {
  try {
    const parsed = JSON.parse(stdin);
    const input = parsed.tool_input;
    if (!input) return [];
    const paths: string[] = [];
    if (input.file_path) paths.push(input.file_path);
    if (input.path) paths.push(input.path);
    if (input.command) {
      // Extract paths from bash commands (best effort)
      const matches = input.command.match(/(?:^|\s)(\/\S+|\.\/\S+|\.\.\S+)/g);
      if (matches) paths.push(...matches.map((m: string) => m.trim()));
    }
    return paths;
  } catch {
    return [];
  }
}

/**
 * Apply mode-specific logic to map a policy decision to a final hook decision.
 *
 * - acceptEdits: review → allow (user opted into autonomy)
 * - plan: reads/investigation → allow, real code writes → deny, plan doc writes → allow
 * - default: write-tool allow → ask (conservative)
 */
export function applyModeLogic(
  policyDecision: "allow" | "deny" | "review",
  permissionMode: string,
  toolName: string,
  affectedPaths?: string[],
): { decision: "allow" | "deny" | "ask"; reason?: string } {
  let finalDecision: "allow" | "deny" | "ask" = {
    allow: "allow" as const,
    deny: "deny" as const,
    review: "ask" as const,
  }[policyDecision];

  const isReadOnly = READ_ONLY_TOOLS.includes(toolName);
  const isWrite = WRITE_TOOLS.includes(toolName);

  if (permissionMode === "plan" || permissionMode === "planMode") {
    if (toolName === "ExitPlanMode") {
      return { decision: "deny", reason: "Cannot exit plan mode automatically." };
    }
    if (isReadOnly) {
      return { decision: "allow" };
    }
    if (isWrite) {
      const paths = affectedPaths || [];
      const isPlanningDoc = paths.some(
        (p) =>
          p.toLowerCase().includes("plan") ||
          p.endsWith(".plan.md") ||
          p.endsWith(".plan") ||
          p.includes("/plans/") ||
          p.includes("/planning/")
      );
      if (isPlanningDoc) {
        return { decision: "allow" };
      }
      return {
        decision: "deny",
        reason: "Plan mode: writing real code is not allowed. Write to a plan document (e.g., plan.md, *.plan.md, plans/) instead, or ask the user to exit plan mode.",
      };
    }
    if (toolName === "Bash") {
      // Allow read-only bash commands in plan mode, deny writes
      // The LLM policy decision is the best signal here — if it said allow, trust it
      if (policyDecision === "allow") {
        return { decision: "allow" };
      }
      return {
        decision: "deny",
        reason: "Plan mode: only investigation commands (read, search, list, git log) are allowed. Modifying commands are blocked — ask the user to exit plan mode first.",
      };
    }
    // Other tools in plan mode: trust allow, block the rest
    if (finalDecision === "allow") {
      return { decision: "allow" };
    }
    return {
      decision: "deny",
      reason: "Plan mode: only investigation and planning are allowed. Ask the user to exit plan mode to take action.",
    };
  }

  if (permissionMode === "acceptEdits" || permissionMode === "acceptAllEdits") {
    // User opted into autonomy — convert "review" to "allow".
    // Only genuine "deny" decisions (secrets, exfiltration, mass delete) should block.
    if (finalDecision === "ask") {
      finalDecision = "allow";
    }
    return { decision: finalDecision };
  }

  // Default mode: conservative
  if (finalDecision === "allow" && isWrite) {
    finalDecision = "ask";
  }
  return { decision: finalDecision };
}

/**
 * Enhance deny messages with actionable technique suggestions.
 */
export function buildDenyWithSuggestions(toolName: string, stdin: string, baseReason: string): string {
  const suggestions: string[] = [];
  const lower = stdin.toLowerCase();

  // Secret exposure
  if (lower.includes(".env") || lower.includes("credential") || lower.includes("secret") ||
      lower.includes("id_rsa") || lower.includes("id_ed25519") || lower.includes(".pem") ||
      lower.includes(".key") || lower.includes("_key") || lower.includes("_secret")) {
    suggestions.push(
      "Use env variable expansion ($VAR) instead of reading secret files directly.",
      "If you need to verify a secret exists, use: test -f <path> or wc -l < <path>.",
      "To pass secrets to commands, use: command --token \"$ENV_VAR\" (not the literal value).",
      "To inspect secret structure without exposing values: sed 's/=.*/=***/' <file>",
    );
  }

  // Complex compound commands
  if (lower.includes("&&") && (lower.includes("|") || lower.includes("xargs"))) {
    suggestions.push(
      "Break this into separate, simpler commands instead of chaining with && and pipes.",
      "Use the Agent/Task tool to run independent steps as subagents.",
    );
  }

  // Operations outside project
  if (lower.includes("/etc/") || lower.includes("/usr/") || lower.includes("bashrc") || lower.includes("zshrc")) {
    suggestions.push(
      "Use project-local config files instead of modifying system files.",
      "Write to /tmp/ or the project directory for temporary files.",
    );
  }

  // Mass delete
  if ((lower.includes("rm ") || lower.includes("rm\t")) && (lower.includes(" -rf") || lower.includes(" -r "))) {
    suggestions.push(
      "Scope deletions to the project directory.",
      "Use git clean -fd for cleaning untracked files within the repo.",
    );
  }

  if (suggestions.length > 0) {
    return `${baseReason}\n\nInstead, try:\n- ${suggestions.join("\n- ")}`;
  }
  return baseReason;
}

/**
 * Deterministic early checks for Bash commands that don't need the LLM.
 * Returns a hook output if handled, or null to continue to LLM evaluation.
 */
export function earlyBashCheck(
  hookEventName: string,
  permissionMode: string,
  stdinContent: string,
): object | null {
  const commandMatch = stdinContent.match(/"command"\s*:\s*"([^"]+)"/);
  const command = commandMatch?.[1] || "";

  // Deny xargs in acceptEdits mode
  if (permissionMode === "acceptEdits" && command.includes("xargs")) {
    return buildHookOutput(
      hookEventName,
      "deny",
      "xargs pipelines are not allowed. Use the Task tool with subagents to parallelize work instead.",
    );
  }

  // Allow read-only gh/glab commands deterministically (skip LLM)
  // Covers: gh pr view/list/checks/diff, gh issue view/list, gh api (GET), gh run view/list/watch, etc.
  const GH_READ_ONLY = /\b(gh|glab)\s+(pr\s+(view|list|checks|diff|status|ready)|issue\s+(view|list|status)|run\s+(view|list|watch)|repo\s+view|api)\b/;
  const GH_DESTRUCTIVE = /\b(gh|glab)\s+(pr\s+(close|delete|merge)|issue\s+(close|delete)|repo\s+delete|release\s+delete)/;
  const GH_WRITE_METHOD = /--method\s+(POST|PUT|DELETE|PATCH)|-X\s+(POST|PUT|DELETE|PATCH)/i;

  if (GH_READ_ONLY.test(command) && !GH_DESTRUCTIVE.test(command) && !GH_WRITE_METHOD.test(command)) {
    return buildHookOutput(hookEventName, "allow", "Read-only gh/glab command");
  }

  return null;
}
