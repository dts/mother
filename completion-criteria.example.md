# Completion Criteria

These are checked when Claude signals it's done with a task. If any aren't met, Claude is asked to continue.

## Default Checks (always active, no config needed)
- Tests have been run (if the project has a test script)
- Linter has been run (if the project has a lint script)
- Type checker has been run (if the project has a typecheck script)
- No uncommitted changes remain
- Commits are pushed and PR exists (if on a feature branch)

## Custom Criteria (add your own below)

<!-- Examples:
- Verify that all new API endpoints have corresponding test cases
- Ensure database migrations are reversible
- Check that error messages are user-friendly, not stack traces
- Confirm that new features are behind feature flags
- Make sure CHANGELOG.md is updated for user-facing changes
-->
