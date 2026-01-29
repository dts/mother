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

## Requires Review
- Any network requests (even GET)
- File operations outside the current directory
- Executing shell commands with user-provided arguments
- Creating new executable files
