/**
 * Stop Hook Handler
 *
 * Runs when Claude finishes responding. Two layers of checks:
 *
 * 1. Practical checks (high priority, deterministic):
 *    - Tests/lint/format/types actually ran (verified via transcript)
 *    - No uncommitted changes to tracked files
 *    - Commits pushed to PR (if on feature branch)
 *    - User-defined completion criteria (LLM-verified)
 *
 * 2. Status summary (lower priority, LLM-verified):
 *    - Final message includes a useful status paragraph
 *
 * Usage: Configure as a Stop hook in settings.json
 */

import { readFile } from "fs/promises";
import { readStdin, findGitRoot } from "./shared";

const SOCKET_PATH = process.env.MOTHER_SOCKET || "/tmp/mother.sock";

interface StopHookInput {
  session_id: string;
  transcript_path: string;
  cwd: string;
  permission_mode: string;
  hook_event_name: string;
  stop_hook_active: boolean;
  last_assistant_message: string;
}

// --- Transcript analysis ---

interface TranscriptEntry {
  type: string;
  message?: {
    role?: string;
    content?: any;
  };
  tool_name?: string;
  tool_input?: any;
  tool_result?: any;
}

/**
 * Read the transcript and extract all Bash commands that were actually executed.
 */
async function getExecutedCommands(transcriptPath: string): Promise<string[]> {
  const commands: string[] = [];
  try {
    const content = await readFile(transcriptPath, "utf-8");
    for (const line of content.split("\n")) {
      if (!line.trim()) continue;
      try {
        const entry = JSON.parse(line);
        // Look for Bash tool calls in assistant messages
        if (entry.type === "assistant" && entry.message?.content) {
          for (const block of entry.message.content) {
            if (block.type === "tool_use" && block.name === "Bash" && block.input?.command) {
              commands.push(block.input.command);
            }
          }
        }
      } catch {
        // Skip unparseable lines
      }
    }
  } catch {
    // Transcript not readable
  }
  return commands;
}

/**
 * Check if any executed command matches patterns for a given check type.
 */
function commandsInclude(commands: string[], patterns: RegExp[]): boolean {
  return commands.some((cmd) => patterns.some((p) => p.test(cmd)));
}

// Patterns for detecting actual test/lint/format/typecheck runs
const TEST_PATTERNS = [
  /\b(bun|npm|yarn|pnpm|make)\s+(run\s+)?(test|spec)/i,
  /\bpytest\b/i,
  /\bcargo\s+test\b/i,
  /\bgo\s+test\b/i,
  /\bjest\b/i,
  /\bvitest\b/i,
  /\bmocha\b/i,
];

const LINT_PATTERNS = [
  /\b(bun|npm|yarn|pnpm|make)\s+(run\s+)?lint/i,
  /\beslint\b/i,
  /\bbiome\s+(check|lint)\b/i,
  /\bruff\s+(check|lint)\b/i,
  /\bgolangci-lint\b/i,
  /\brubocop\b/i,
  /\bclippy\b/i,
];

const FORMAT_PATTERNS = [
  /\b(bun|npm|yarn|pnpm|make)\s+(run\s+)?(format|prettier)/i,
  /\bprettier\b/i,
  /\bbiome\s+format\b/i,
  /\bruff\s+format\b/i,
  /\bgofmt\b/i,
  /\brushfmt\b/i,
  /\bblack\b/i,
];

const TYPECHECK_PATTERNS = [
  /\b(bun|npm|yarn|pnpm|make)\s+(run\s+)?(typecheck|type-check|tsc|check:types)/i,
  /\btsc\b(?!\s+--init)/i,
  /\bmypy\b/i,
  /\bpyright\b/i,
];

// --- Git context ---

function getGitContext(cwd: string) {
  let hasCodeChanges = false;
  let hasUnpushedCommits = false;
  let isOnBranch = false;
  let branchName = "main";

  try {
    const status = Bun.spawnSync(["git", "status", "--porcelain", "-uno"], { cwd });
    hasCodeChanges = status.stdout.toString().trim().length > 0;

    const branch = Bun.spawnSync(["git", "rev-parse", "--abbrev-ref", "HEAD"], { cwd });
    branchName = branch.stdout.toString().trim();
    isOnBranch = branchName !== "main" && branchName !== "master" && branchName !== "HEAD";

    const unpushed = Bun.spawnSync(
      ["git", "log", "--oneline", `origin/${branchName}..HEAD`],
      { cwd },
    );
    hasUnpushedCommits = unpushed.exitCode === 0 && unpushed.stdout.toString().trim().length > 0;
  } catch {}

  return { hasCodeChanges, hasUnpushedCommits, isOnBranch, branchName };
}

// --- Project scripts detection ---

function getProjectScripts(cwd: string) {
  let hasTests = false;
  let hasLint = false;
  let hasFormat = false;
  let hasTypeCheck = false;

  try {
    const pkg = JSON.parse(Bun.spawnSync(["cat", "package.json"], { cwd }).stdout.toString());
    const scripts = pkg.scripts || {};
    hasTests = !!(scripts.test || scripts["test:unit"] || scripts["test:integration"]);
    hasLint = !!(scripts.lint || scripts["lint:fix"]);
    hasFormat = !!(scripts.format || scripts.prettier || scripts["format:check"]);
    hasTypeCheck = !!(scripts.typecheck || scripts["type-check"] || scripts.tsc || scripts["check:types"]);
  } catch {}

  try {
    const makefile = Bun.spawnSync(["cat", "Makefile"], { cwd }).stdout.toString();
    if (!hasTests && /^test:/m.test(makefile)) hasTests = true;
    if (!hasLint && /^lint:/m.test(makefile)) hasLint = true;
    if (!hasFormat && /^format:/m.test(makefile)) hasFormat = true;
    if (!hasTypeCheck && /^typecheck:/m.test(makefile)) hasTypeCheck = true;
  } catch {}

  return { hasTests, hasLint, hasFormat, hasTypeCheck };
}

// --- Completion signals ---

const COMPLETION_SIGNALS = [
  /(?:i'?ve|i have) (?:completed|finished|done|made all|implemented|fixed|resolved)/i,
  /(?:all|everything) (?:is |has been )?(?:done|complete|ready|finished|fixed)/i,
  /(?:changes|updates|fixes) (?:are |have been )?(?:ready|complete|done|pushed|committed)/i,
  /(?:let me know|feel free) (?:if|to)/i,
  /that should (?:be|do) it/i,
  /(?:here'?s|here is) (?:a |the )?summary/i,
];

function looksLikeCompletion(message: string): boolean {
  return COMPLETION_SIGNALS.some((re) => re.test(message));
}

// --- Custom completion criteria (LLM-based) ---

async function loadCompletionCriteria(cwd: string): Promise<string> {
  const homeDir = process.env.HOME || process.env.USERPROFILE || "~";
  for (const path of [
    `${cwd}/.claude/completion-criteria.md`,
    `${homeDir}/.claude/completion-criteria.md`,
  ]) {
    try {
      return await readFile(path, "utf-8");
    } catch {}
  }
  return "";
}

async function evaluateCustomCriteria(
  lastMessage: string,
  criteria: string,
): Promise<string | null> {
  try {
    const response = await fetch(`http://localhost/eval-completion`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ lastMessage: lastMessage.slice(0, 2000), criteria }),
      // @ts-ignore
      unix: SOCKET_PATH,
    });
    if (!response.ok) return null;
    const result = (await response.json()) as { satisfied: boolean; reason?: string };
    if (!result.satisfied) {
      return result.reason || "Custom completion criteria not met.";
    }
  } catch {
    // Server not available, skip
  }
  return null;
}

// --- Status summary check (LLM-based) ---

async function evaluateStatusSummary(lastMessage: string): Promise<string | null> {
  try {
    const response = await fetch(`http://localhost/eval-completion`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        lastMessage: lastMessage.slice(0, 2000),
        criteria: `The message must end with a clear status paragraph that covers:
1. What was accomplished (brief)
2. Whether there's a blocking decision the user needs to make
3. Whether the task is done, or if the agent needs more direction / has a next step

A good status summary helps someone scanning a dashboard of many running agents understand what this one is doing at a glance. It does NOT need to be labeled "Status:" — it just needs to convey that information clearly in the final paragraph.

Short factual answers to questions (e.g., "The file is at src/foo.ts") do NOT need a status summary — only substantive work sessions do.`,
      }),
      // @ts-ignore
      unix: SOCKET_PATH,
    });
    if (!response.ok) return null;
    const result = (await response.json()) as { satisfied: boolean; reason?: string };
    if (!result.satisfied) {
      return "Before stopping, please end with a short status paragraph: what was done, whether there's a decision needed, and whether you're done or need more direction.";
    }
  } catch {
    // Server not available, skip
  }
  return null;
}

// --- Main ---

async function main() {
  const stdinContent = await readStdin();

  let input: StopHookInput;
  try {
    input = JSON.parse(stdinContent);
  } catch {
    process.exit(0);
  }

  // Prevent infinite loops: if we already blocked once, let it stop
  if (input.stop_hook_active) {
    process.exit(0);
  }

  const lastMessage = input.last_assistant_message || "";

  // Only check on messages that look like task completion
  if (!looksLikeCompletion(lastMessage)) {
    process.exit(0);
  }

  const cwd = findGitRoot(input.cwd);
  const commands = await getExecutedCommands(input.transcript_path);
  const scripts = getProjectScripts(cwd);
  const gitCtx = getGitContext(cwd);

  // --- Layer 1: Practical checks (high priority) ---
  const practicalFailures: string[] = [];

  if (scripts.hasTests && !commandsInclude(commands, TEST_PATTERNS)) {
    practicalFailures.push("Tests haven't been run. Run the project's test suite to verify changes.");
  }
  if (scripts.hasLint && !commandsInclude(commands, LINT_PATTERNS)) {
    practicalFailures.push("Linting hasn't been run. Run the linter to catch issues.");
  }
  if (scripts.hasFormat && !commandsInclude(commands, FORMAT_PATTERNS)) {
    practicalFailures.push("Formatter hasn't been run. Run the formatter for consistent style.");
  }
  if (scripts.hasTypeCheck && !commandsInclude(commands, TYPECHECK_PATTERNS)) {
    practicalFailures.push("Type checking hasn't been run. Run the type checker.");
  }
  if (gitCtx.hasCodeChanges) {
    practicalFailures.push("There are uncommitted changes to tracked files. Commit your work.");
  }
  if (gitCtx.hasUnpushedCommits && gitCtx.isOnBranch) {
    practicalFailures.push(
      `Unpushed commits on '${gitCtx.branchName}'. Push and ensure a PR exists.`,
    );
  }

  // If practical checks fail, block immediately — don't bother with summary yet
  if (practicalFailures.length > 0) {
    console.log(JSON.stringify({
      decision: "block",
      reason: `Before finishing, complete these items:\n\n${practicalFailures.map((f) => `- ${f}`).join("\n")}`,
    }));
    return;
  }

  // --- Layer 1b: Custom completion criteria (LLM-based) ---
  const completionCriteria = await loadCompletionCriteria(cwd);
  if (completionCriteria) {
    const customFailure = await evaluateCustomCriteria(lastMessage, completionCriteria);
    if (customFailure) {
      console.log(JSON.stringify({
        decision: "block",
        reason: `Before finishing:\n\n- ${customFailure}`,
      }));
      return;
    }
  }

  // --- Layer 2: Status summary (lower priority) ---
  const summaryFailure = await evaluateStatusSummary(lastMessage);
  if (summaryFailure) {
    console.log(JSON.stringify({
      decision: "block",
      reason: summaryFailure,
    }));
    return;
  }

  // All checks passed
  process.exit(0);
}

main();
