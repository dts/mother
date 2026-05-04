# mother

*"Mother, may I execute `rm -rf /`?"*

A permission evaluation system for Claude Code hooks. Analyzes tool requests through a multi-stage pipeline to automatically allow, deny, or flag operations for manual review. If you're watching in Claude Code, you can approve/deny before it answers (i.e. it's async), but if you're heads down somewhere else, it'll keep a lot of things going without your intervention.

```
❯ please delete ~/file-to-delete

⏺ Bash(rm ~/file-to-delete)
  ⎿  Error: This is a permission request to delete a file located in the user's
     home directory using the rm (remove) command. | Outside the current project
     directory, targeting the home directory of the user | The action attempts to
     delete a file in the home directory, which directly violates the security
     preference against deleting files outside the current working directory.
  ⎿  Denied by PermissionRequest hook
```

```
❯ delete file-to-delete

⏺ Bash(rm file-to-delete)
  ⎿  (No content)
  ⎿  Allowed by PermissionRequest hook

⏺ Done. The file has been deleted.
```

## How it works

Mother runs the same analysis pipeline for Claude and Codex requests. The LLM backend is pluggable, but the logical passes stay the same:

1. **Triage** - Detects prompt injection attempts via regex patterns and LLM analysis. Only flags linguistic manipulation (fake system prompts, instruction overrides), not dangerous operations.

2. **Explanation** - Summarizes what the operation does and where it operates relative to the project directory.

3. **Preference Check** - Evaluates against rules in `security-preferences.md` to decide: allow, deny, or require review.

The default backend mode is `auto`: Claude requests use the Claude Code subscription backend, and Codex requests use the Codex subscription backend.

## Setup

```bash
# Install dependencies
bun install

# Optional: add API keys if you want API-backed LLM evaluation instead of subscriptions.
# Subscription-backed Claude/Codex modes do not need these.
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
echo "OPENAI_API_KEY=sk-..." >> .env

# Install the wrapper globally (update path to your mother directory)
mkdir -p ~/.bin
echo '#!/usr/bin/env bash' > ~/.bin/mother
echo 'exec bun /path/to/mother/cli-socket.ts "$@"' >> ~/.bin/mother
chmod +x ~/.bin/mother

# Ensure ~/.bin is in your PATH

# Copy the security preferences to ~/.claude
mkdir -p ~/.claude
cp security-preferences.example.md ~/.claude/security-preferences.md
```

## Claude Code Integration

Add to `~/.claude/settings.json` or `.claude/settings.json`:

```json
{
  "hooks": {
    "PermissionRequest": [
      {
        "matcher": "Bash|Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "MOTHER_LLM_BACKEND=claude ~/.bin/mother"
          }
        ]
      }
    ]
  }
}
```

**Why PermissionRequest only?** Claude Code has its own allow list in `settings.json` (e.g., `Bash(git status)`, `Bash(bd *)`). By using only `PermissionRequest`, Claude Code's built-in permissions are respected first. Mother only intercepts when Claude Code would normally prompt you for permission, giving you two layers of control:

1. **Claude Code's allow list** - Fast, no LLM call, for commands you always trust
2. **Mother's security preferences** - LLM-evaluated rules for everything else

## Codex Integration

Mother also understands Codex hook payloads. When the incoming payload looks like Codex (`turn_id`, `apply_patch`, or Codex's approval `description` field), Mother switches to `codex` mode:

- `PermissionRequest` allow -> Codex approval is granted
- `PermissionRequest` deny -> Codex approval is rejected
- `review`/`ask` -> Mother returns `{}` so Codex shows its normal approval prompt

Add to `~/.codex/config.toml` or `<repo>/.codex/config.toml`:

```toml
[features]
codex_hooks = true

[[hooks.PermissionRequest]]
matcher = "^(Bash|exec_command|apply_patch|mcp__.*)$"

[[hooks.PermissionRequest.hooks]]
type = "command"
command = "MOTHER_LLM_BACKEND=codex ~/.bin/mother"
timeout = 120
statusMessage = "Checking approval request"
```

The command should point at a wrapper that runs this checkout's socket CLI:

```bash
mkdir -p ~/.bin
echo '#!/usr/bin/env bash' > ~/.bin/mother
echo 'exec bun /path/to/mother/cli-socket.ts "$@"' >> ~/.bin/mother
chmod +x ~/.bin/mother
```

If your existing `~/.bin/mother` already points at the correct `cli-socket.ts`, no separate wrapper is needed.

Restart Codex after changing `~/.codex/config.toml`; hook config is loaded when the Codex process starts. Mother only receives `PermissionRequest` events, so sandbox-allowed tool calls can appear in Codex logs without corresponding Mother log entries. If Codex asks you directly for approval, check that the active config still includes `codex_hooks = true` and the `exec_command` matcher.

The socket daemon uses a checkout-specific default instance name and socket path, so two Mother checkouts do not fight over `/tmp/mother.sock` or the same tmux session. One daemon can handle Claude and Codex requests together: `mother-socket` sends the requested backend with each evaluation request, and the server selects the LLM backend per request. Override `MOTHER_SOCKET` or `MOTHER_TMUX_SESSION` only if you intentionally want a shared daemon identity.

`MOTHER_LLM_BACKEND=codex` makes the Mother server evaluate ambiguous requests with `@openai/codex-sdk`, using your logged-in Codex subscription. The SDK-backed evaluator runs in a read-only sandbox with approval policy `never` and disables `codex_hooks` through Codex config overrides to avoid recursive hook calls.

## LLM Backends

Mother's analysis pipeline accepts any backend that can answer text prompts. Configure it with `MOTHER_LLM_BACKEND`:

- `auto` (default): Codex requests use `codex-subscription`; Claude requests use `claude-subscription`.
- `codex` / `codex-subscription`: uses `@openai/codex-sdk` and your logged-in Codex/ChatGPT subscription.
- `claude` / `claude-subscription`: uses Claude Code Agent SDK and your Claude Code subscription.
- `anthropic-api`: uses Vercel AI SDK with `@ai-sdk/anthropic`; requires `ANTHROPIC_API_KEY`.
- `openai-api`: uses `OPENAI_API_KEY` against an OpenAI-compatible `/v1/chat/completions` endpoint.
- `ai-gateway`: uses Vercel AI Gateway through `@ai-sdk/gateway`; requires the gateway's normal auth.
- `local`: uses an OpenAI-compatible local endpoint, defaulting to `http://localhost:11434/v1`.

With the socket CLI, `MOTHER_LLM_BACKEND` is request-scoped. For example, a Codex hook can run `MOTHER_LLM_BACKEND=codex ~/.bin/mother` while a Claude hook runs `MOTHER_LLM_BACKEND=claude ~/.bin/mother`; both talk to the same checkout daemon. If no request-specific backend is set, `auto` chooses by client. `MOTHER_SERVER_LLM_BACKEND` only sets the daemon's fallback default for requests that do not carry a backend.

Model/backend environment variables:

- `MOTHER_LLM_MODEL`: generic model override for API, gateway, and local modes.
- `MOTHER_SERVER_LLM_BACKEND`: fallback backend for the socket daemon when a request does not specify `MOTHER_LLM_BACKEND`; defaults to `auto`.
- `MOTHER_ANTHROPIC_MODEL`: Anthropic API model override.
- `MOTHER_OPENAI_MODEL`: OpenAI API model override.
- `OPENAI_BASE_URL`: optional OpenAI-compatible API base URL for `openai-api`.
- `MOTHER_LOCAL_BASE_URL`: local OpenAI-compatible base URL, default `http://localhost:11434/v1`.
- `MOTHER_LOCAL_MODEL`: local model override.
- `MOTHER_CODEX_MODEL`: optional model override for the SDK-backed Codex evaluator.
- `MOTHER_CODEX_TIMEOUT_MS`: optional timeout, default `120000`.

## Security Preferences

Mother looks for security preferences in client-specific order:

For Codex requests:
1. **Repo-specific Codex**: `.codex/security-preferences.md` (in your project's git root)
2. **Global Codex**: `~/.codex/security-preferences.md`
3. **Repo-specific Claude fallback**: `.claude/security-preferences.md`
4. **Global Claude fallback**: `~/.claude/security-preferences.md`

For Claude requests, the `.claude` locations are checked first and `.codex` is only a fallback. If none exists, Mother uses the permissive fallback: allow project-local operations and review everything else.

This lets you have strict global defaults while relaxing rules for specific projects (e.g., allowing `git push` in a trusted repo).

Edit `~/.claude/security-preferences.md` for global rules, or create `.claude/security-preferences.md` in a repo for project-specific overrides. Default policy:

**Forbidden:**
- Pushing to web (POST requests, git push)
- Deleting files outside project directory
- Modifying system files
- Accessing secrets/credentials

**Allowed:**
- Read/write within project directory
- Running tests, local dev servers
- Git operations that don't push
- Installing local dependencies

**Requires Review:**
- Network requests (even GET)
- File operations outside project
- Creating executables

## Output Format

Mother outputs JSON that Claude Code understands:

```json
// For PreToolUse hooks
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow" | "deny" | "ask",
    "permissionDecisionReason": "..."
  }
}

// For PermissionRequest hooks
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "allow" | "deny",
      "message": "..." // present for denials
    }
  }
}
```

## Logging

All requests are logged to `log.jsonl` with full analysis details including:
- Triage score and reasoning
- Explanation summary and affected paths
- Preference check decision and matched rules
- Exact hook output returned

## Running Evals

```bash
bun eval.ts           # Run all 65 test cases
bun eval.ts triage    # Just triage stage (33 cases)
bun eval.ts explanation
bun eval.ts preference
```

Test cases cover:
- Safe operations (file reads, npm commands, git status)
- Prompt injection attacks (system tags, instruction overrides, jailbreaks)
- Edge cases (legitimate "system" in filenames, code comments)
- Policy decisions (allow/deny/review scenarios)

## Files

- `cli.ts` - Main analysis pipeline
- `eval.ts` - LLM-as-judge evaluation suite
- `security-preferences.example.md` - Example security rules (copy to `~/.claude/security-preferences.md`)
- `log.jsonl` - Request log (gitignored)
- `.env` - API key (gitignored)
