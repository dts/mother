# Security Preferences

## Forbidden Actions
- No pushing information to the web (curl POST, fetch POST, git push, etc.)
- No deleting files outside the current working directory
- No modifying system files (/etc, /usr, ~/.bashrc, ~/.zshrc, etc.)
- No installing global packages or modifying PATH
- No accessing or exfiltrating environment variables containing secrets
- No running commands with sudo or elevated privileges
- No modifying SSH keys or credentials

## Allowed Actions
- Reading files within the project directory
- Writing files within the project directory
- Running local dev servers
- Installing project-local dependencies
- Running tests
- Git operations that don't push (status, diff, add, commit, log)
- Read-only kubectl commands (get, describe, logs, top, explain, api-resources, config view)
- gh CLI commands (pr create, pr view, pr list, pr checkout, pr merge, issue create, issue view, issue list, repo view, api)
- gh pr creation and updates are always allowed

## Requires Review
- Any network requests (even GET)
- File operations outside the current directory
- Executing shell commands with user-provided arguments
- Creating new executable files
- kubectl commands that modify state (apply, delete, create, patch, edit, scale, rollout, exec)
- Destructive gh commands (repo delete, pr close, issue close, release delete)
