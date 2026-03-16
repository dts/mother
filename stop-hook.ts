/**
 * Stop Hook Handler
 *
 * Runs when Claude finishes responding. Checks whether the task was
 * adequately completed against default expectations and user-defined
 * completion criteria.
 *
 * Default checks:
 * - Tests/lint/format/types have been run (if applicable)
 * - Changes pushed to a PR (if relevant)
 * - User-defined completion criteria satisfied
 *
 * Usage: Configure as a Stop hook in settings.json
 */

import { readFile } from "fs/promises";
import { readStdin, findGitRoot, loadPreferences } from "./shared";

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

interface CompletionCheck {
  name: string;
  check: (ctx: CheckContext) => string | null; // returns reason to block, or null if ok
}

interface CheckContext {
  input: StopHookInput;
  cwd: string;
  lastMessage: string;
  completionCriteria: string;
  hasCodeChanges: boolean;
  hasUnpushedCommits: boolean;
  isOnBranch: boolean;
  branchName: string;
}

// Load user-defined completion criteria
async function loadCompletionCriteria(cwd: string): Promise<string> {
  const homeDir = process.env.HOME || process.env.USERPROFILE || "~";
  // Check repo-specific first, then global
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

// Gather git context
function getGitContext(cwd: string): {
  hasCodeChanges: boolean;
  hasUnpushedCommits: boolean;
  isOnBranch: boolean;
  branchName: string;
} {
  let hasCodeChanges = false;
  let hasUnpushedCommits = false;
  let isOnBranch = false;
  let branchName = "main";

  try {
    // Check for uncommitted changes
    const status = Bun.spawnSync(["git", "status", "--porcelain"], { cwd });
    hasCodeChanges = status.stdout.toString().trim().length > 0;

    // Get current branch
    const branch = Bun.spawnSync(["git", "rev-parse", "--abbrev-ref", "HEAD"], { cwd });
    branchName = branch.stdout.toString().trim();
    isOnBranch = branchName !== "main" && branchName !== "master" && branchName !== "HEAD";

    // Check for unpushed commits
    const unpushed = Bun.spawnSync(
      ["git", "log", "--oneline", `origin/${branchName}..HEAD`],
      { cwd },
    );
    hasUnpushedCommits = unpushed.exitCode === 0 && unpushed.stdout.toString().trim().length > 0;
  } catch {
    // Not a git repo or other error
  }

  return { hasCodeChanges, hasUnpushedCommits, isOnBranch, branchName };
}

// Check if the project has test/lint/format/type-check scripts
function getProjectScripts(cwd: string): {
  hasTests: boolean;
  hasLint: boolean;
  hasFormat: boolean;
  hasTypeCheck: boolean;
} {
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

  // Also check for Makefile targets
  try {
    const makefile = Bun.spawnSync(["cat", "Makefile"], { cwd }).stdout.toString();
    if (!hasTests && /^test:/m.test(makefile)) hasTests = true;
    if (!hasLint && /^lint:/m.test(makefile)) hasLint = true;
    if (!hasFormat && /^format:/m.test(makefile)) hasFormat = true;
    if (!hasTypeCheck && /^typecheck:/m.test(makefile)) hasTypeCheck = true;
  } catch {}

  return { hasTests, hasLint, hasFormat, hasTypeCheck };
}

// Signal words that suggest the assistant believes the task is done
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

// Check if the message mentions running specific verification steps
function mentionsRunning(message: string, keyword: string): boolean {
  const patterns = [
    new RegExp(`(?:ran|running|run|passed|executed)\\s+.*${keyword}`, "i"),
    new RegExp(`${keyword}.*(?:passed|succeeded|clean|no errors|no issues|✓|✅)`, "i"),
    new RegExp(`(?:bun|npm|yarn|pnpm|make)\\s+(?:run\\s+)?${keyword}`, "i"),
  ];
  return patterns.some((re) => re.test(message));
}

// Default completion checks
const DEFAULT_CHECKS: CompletionCheck[] = [
  {
    name: "tests",
    check: (ctx) => {
      const scripts = getProjectScripts(ctx.cwd);
      if (!scripts.hasTests) return null; // no tests configured
      if (mentionsRunning(ctx.lastMessage, "test")) return null;
      return "Tests haven't been run. Run the project's test suite to verify your changes don't break anything.";
    },
  },
  {
    name: "lint",
    check: (ctx) => {
      const scripts = getProjectScripts(ctx.cwd);
      if (!scripts.hasLint) return null;
      if (mentionsRunning(ctx.lastMessage, "lint")) return null;
      return "Linting hasn't been run. Run the linter to catch style issues.";
    },
  },
  {
    name: "typecheck",
    check: (ctx) => {
      const scripts = getProjectScripts(ctx.cwd);
      if (!scripts.hasTypeCheck) return null;
      if (mentionsRunning(ctx.lastMessage, "type")) return null;
      return "Type checking hasn't been run. Run the type checker to verify type safety.";
    },
  },
  {
    name: "uncommitted-changes",
    check: (ctx) => {
      if (!ctx.hasCodeChanges) return null;
      return "There are uncommitted changes. Commit your work before finishing.";
    },
  },
  {
    name: "unpushed-commits",
    check: (ctx) => {
      if (!ctx.hasUnpushedCommits) return null;
      if (!ctx.isOnBranch) return null; // on main, don't nag about pushing
      return `There are unpushed commits on branch '${ctx.branchName}'. Push your changes and ensure a PR exists.`;
    },
  },
];

// Use the server for LLM-based completion criteria evaluation
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
    const result = await response.json() as { satisfied: boolean; reason?: string };
    if (!result.satisfied) {
      return result.reason || "Custom completion criteria not met.";
    }
  } catch {
    // Server not available, skip custom criteria check
  }
  return null;
}

async function main() {
  const stdinContent = await readStdin();

  let input: StopHookInput;
  try {
    input = JSON.parse(stdinContent);
  } catch {
    // Can't parse input, allow stop
    process.exit(0);
  }

  // Prevent infinite loops: if we already blocked once, let it stop
  if (input.stop_hook_active) {
    process.exit(0);
  }

  const lastMessage = input.last_assistant_message || "";

  // Only check completion on messages that look like they're wrapping up
  if (!looksLikeCompletion(lastMessage)) {
    process.exit(0);
  }

  const cwd = findGitRoot(input.cwd);
  const gitCtx = getGitContext(cwd);
  const completionCriteria = await loadCompletionCriteria(cwd);

  const ctx: CheckContext = {
    input,
    cwd,
    lastMessage,
    completionCriteria,
    ...gitCtx,
  };

  // Run default checks
  const failures: string[] = [];
  for (const check of DEFAULT_CHECKS) {
    const reason = check.check(ctx);
    if (reason) {
      failures.push(reason);
    }
  }

  // Run custom criteria if defined (LLM-based)
  if (completionCriteria) {
    const customFailure = await evaluateCustomCriteria(lastMessage, completionCriteria);
    if (customFailure) {
      failures.push(customFailure);
    }
  }

  if (failures.length === 0) {
    // All checks passed, allow stop
    process.exit(0);
  }

  // Block the stop and tell Claude what's still needed
  const reason = `Before finishing, please complete these remaining items:\n\n${failures.map((f) => `- ${f}`).join("\n")}`;

  console.log(JSON.stringify({
    decision: "block",
    reason,
  }));
}

main();
