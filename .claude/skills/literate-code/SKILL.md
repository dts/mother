---
name: literate-code
description: Write new or rewritten code so its top-level function reads as its steps, with true names. Use when writing a new script, handler, component or module, or substantially rewriting one, in any language in this repo.
---

# Literate code

The standard is `docs/standards/literate-code.md`. Read it before writing.

1. **Write the top-level function first**, as the steps in order, each a call to a function
   that doesn't exist yet. Read each line aloud as a sentence: subject (often implied), verb,
   object, and modifiers for specificity. Read the whole function back: does it say what the
   code does?
2. **Check each name against what its body will do.** It claims no more and no less
   (`sayNothingWritten`, not `sayNothingChanged`).
3. **Write the helpers**, each at one level of detail. Stop conditions throw; the top level
   handles them once.
4. **Before calling it done**, reread every new or rewritten function against the
   standard's test: from the top-level function alone, can you say what the code does, in
   order? Then run the repo's review as usual.
