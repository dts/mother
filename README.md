# mother

*"Mother, may I execute `rm -rf /`?"*

A permission evaluation system for Claude Code hooks. Analyzes tool requests through a multi-stage pipeline to automatically allow, deny, or flag operations for manual review. If you're watching in claude code, you can approve/deny before it answers (i.e. it's async), but if you're heads down somewhere else, it'll keep a lot of things going without your intervention.

## How it works

Mother runs a 3-stage analysis pipeline using Claude Haiku:

1. **Triage** - Detects prompt injection attempts via regex patterns and LLM analysis. Only flags linguistic manipulation (fake system prompts, instruction overrides), not dangerous operations.

2. **Explanation** - Summarizes what the operation does and where it operates relative to the project directory.

3. **Preference Check** - Evaluates against rules in `security-preferences.md` to decide: allow, deny, or require review.

## Setup

```bash
# Install dependencies
bun install

# Add your Anthropic API key
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# Install the wrapper globally (update path to your mother directory)
mkdir -p ~/.bin
echo '#!/usr/bin/env bash' > ~/.bin/mother
echo 'exec bun /path/to/mother/cli.ts "$@"' >> ~/.bin/mother
chmod +x ~/.bin/mother

# Ensure ~/.bin is in your PATH
```

## Claude Code Integration

Add to `~/.claude/settings.json` or `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "~/.bin/mother"
          }
        ]
      }
    ],
    "PermissionRequest": [
      {
        "matcher": "Bash|Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "~/.bin/mother"
          }
        ]
      }
    ]
  }
}
```

## Security Preferences

Edit `security-preferences.md` to customize rules. Default policy:

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
      "message": "..."
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
- `security-preferences.md` - Customizable security rules
- `log.jsonl` - Request log (gitignored)
- `.env` - API key (gitignored)
