# Literate code

Applies to new code and to code that is substantially rewritten, in any language. Existing
code moves to it when it next changes substantially, not ahead of that.

This is the same standard in every repository Daniel works on (it started in CareSola, as
`docs/standards/literate-code.md`, DECISIONS B54). Change it there and copy it here, so the
copies stay the same.

The test: someone who reads only the top-level function (a script's `main`, a handler, a
component's setup, a job, a test) can say what the code does, in order, without reading
further.

The gold standard is that each step reads as a sentence: a subject, a verb, an object, and
modifiers that make it specific. The subject is often implied (the script, or the value a
method is called on). `db.end()`: the database ends. `requireYes(questionFor(users))`:
require a yes to the question for these users. `withStagingOwnerDb(owner, …)`: with
staging's database, as its owner. `upsertCrmUserRows(tx, users)`: upsert the CRM users' rows.

## Rules

1. **The top-level function is a list of steps.** Each line is one step, a call to a
   function named for what it does, in the order it happens. Branches and early returns
   are allowed when they are steps too ("stop unless `--write`").
2. **Name a step for what it does, not how, as a verb and its object.** `dryRun(db, users)`,
   not `rolledBack(db, (tx) => seed(tx, users))`; `withStagingOwnerDb(owner, work)`, not
   `new pg.Client(...)`, `connect()` and `end()`. Add modifiers until the name is specific:
   `listStagingCrmUsers`, not `listUsers`; `upsertCrmUserRows`, not `upsert`. A value is a
   noun phrase (`plan`, `olderLogins`), a predicate reads as a claim (`isYes`,
   `wantsToWrite`).
3. **A name is true.** It claims only what the code does. `sayNothingWritten`, not
   `sayNothingChanged`, when nothing was compared. `upsertCrmUserRows`, not `seed`, when it
   upserts.
4. **One level of detail per function.** Parsing, formatting, SQL and retries go in the
   named helpers. A function that calls steps doesn't also build strings or queries.
5. **Handle a stop condition once.** The step that finds it throws; the top level handles
   it in one place. No `try`/`catch` or `if (…) { log; return 1 }` around each step.
   Cleanup (`finally`, C's `goto cleanup`) stays where it is needed.
6. **Results are named for what they hold.** `plan`, `result`, `login`, never `r` or `w`. A
   one-letter name is for a loop index or a short lambda's argument.
7. **Short lines in step functions.** A long template literal or a nested ternary in the
   control flow becomes a named helper (`questionFor(users)`).
8. **Comments say what the code can't.** A constraint, an order that matters, a decision
   and where it is recorded. Not a restatement of the next line. A top-level function with
   branches gets one line stating its plan:
   `// Dry run by default. --write runs the same dry run, asks y/N, then writes.`
9. **The language's idiom wins.** C keeps status codes and `goto cleanup`; Erlang's steps
   are function clauses and `case` pipelines; Swift and Kotlin keep `guard`/early return;
   a Vue component's `<script setup>` reads as its steps like any other function. Shell
   stays a few commands in a row; logic that branches, loops or parses goes to a real
   language.

## Example

A script that writes users to a staging database:

```ts
// Dry run by default. --write runs the same dry run, asks y/N, then writes.
// The dry run and the write each get their own connection: none is open
// while the question waits.
async function main(): Promise<void> {
  const users = listStagingCrmUsers()
  const owner = readOwnerUrl()
  printPlan(owner.host, users, await withStagingOwnerDb(owner, (db) => dryRun(db, users)))
  if (!wantsToWrite()) return sayNothingWritten('DRY RUN. Run again with --write to write them.')
  await requireYes(questionFor(users))
  printDone(await withStagingOwnerDb(owner, (db) => writeRows(db, users)))
}
```

## Elsewhere

Code that reads as its steps, worth looking at for the shape (not the details):

- **C:** Lua's `lua.c`, `pmain`: open the libraries, handle the arguments, run the script,
  then the REPL, each a named call. Redis's `ae.c`, `aeMain` and `aeProcessEvents`: the
  event loop as named phases.
- **Python:** requests' `sessions.py`, `Session.request`: build a `Request`, prepare it,
  merge the environment's settings, send.
- **Go:** `encoding/json`'s `Marshal`: get an encoder, encode, copy the bytes out.
- **Erlang:** an OTP `gen_server` whose `handle_call` clauses each match one message and
  hand it to one named function.
