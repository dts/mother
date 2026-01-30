# Security Preferences

## Forbidden Actions
- None - prefer asking over blocking

## Allowed Actions
- Reading files within the project directory
- Writing files within the project directory
- Running local dev servers
- Installing project-local dependencies
- Running tests
- Git operations that don't push (status, diff, add, commit, log)
- Read-only kubectl commands (get, describe, logs, top, explain, api-resources, config view)
- Production Kubernetes is READ-ONLY - no apply, delete, exec, or modifications
- gh CLI commands (pr create, pr view, pr list, pr checkout, pr merge, issue create, issue view, issue list, repo view, api)
- gh pr creation and updates are always allowed
- npm/bun/yarn package info commands (npm view, npm info, npm search, bun pm, yarn info)
- Docker commands for local development (docker run, docker build, docker compose)
- Installing global packages INSIDE local Docker containers (isolated environments are safe)
- Supabase local commands (supabase init, start, stop, status, db reset, db push, db diff, functions serve, gen types, migration)
- Supabase read-only remote commands (supabase projects list, functions list, secrets list, db remote commit, db diff --linked, orgs list, branches list)
- iOS development tools (xcodebuild, xcrun, xcode-select, simctl, instruments, codesign, altool, notarytool)
- Android development tools (adb, emulator, avdmanager, sdkmanager, gradle, gradlew, bundletool, apksigner)
- Reading/writing /tmp and /private/tmp directories (temporary files)
- Reading ~/.claude/projects/<current-project>/ directory (Claude's session data for the active project only, not other projects)
- Reading and writing ~/.maestro directory (Maestro mobile testing config/flows)
- Running Maestro commands with Java/environment setup (mobile UI testing)

## Requires Review (ask user first)
- Editing Claude settings (~/.claude/settings.json) - ask, don't block
- Pushing to remote (git push, curl POST, fetch POST, etc.)
- Deleting files outside the current working directory
- Modifying system files (/etc, /usr, ~/.bashrc, ~/.zshrc, etc.)
- Accessing environment variables that may contain secrets
- Running sudo commands
- Modifying SSH keys or credentials
- Network requests not covered by allowed actions above
- File operations outside the current directory
- Executing shell commands with user-provided arguments
- Creating new executable files
- kubectl commands that modify state (apply, delete, create, patch, edit, scale, rollout, exec)
- Destructive gh commands (repo delete, pr close, issue close, release delete)
- Installing system dependencies (npm install -g, brew install, apt-get install, pip install --user, etc.)
- Supabase remote write commands (supabase db push --linked, functions deploy, secrets set, link, projects create, branches create/delete)
