# Status Summary at Stop: Approaches

## Problem

When Claude stops, it's hard to tell at a glance what the actual state is — is it done? Blocked? Waiting for a decision? Looking at the "board" of running sessions, you want a quick paragraph for each one.

## Approach 1: Stop Hook Blocks Until Summary Present

**How it works**: The Stop hook checks `last_assistant_message` for a structured status block (e.g., lines starting with `Status:`, `Needs decision:`, `Next steps:`). If missing, block with reason: "Please end with a brief status summary including: current status, whether a decision is needed, and what comes next."

**Pros**: Simple, no LLM needed, deterministic. Claude learns quickly after one bounce.
**Cons**: Pattern matching can be fragile. Claude might produce a formulaic status that isn't genuinely useful. Only fires at Stop, not during intermediate pauses.

## Approach 2: CLAUDE.md Instruction + Stop Hook Enforcement

**How it works**: Add a rule to CLAUDE.md (global or per-project): "When finishing a task, always end with a status paragraph covering: (1) what was done, (2) whether there's a blocking decision, (3) whether you're done or need more direction." The Stop hook then uses an LLM call to verify the summary is present and adequate.

**Pros**: CLAUDE.md instruction means Claude proactively includes the summary. LLM-based check catches low-quality summaries. Works across all modes.
**Cons**: Extra LLM call per stop. CLAUDE.md instructions can be forgotten as context compacts.

## Approach 3: Stop Hook Injects Status Template via Block Reason

**How it works**: The Stop hook ALWAYS blocks the first stop attempt (unless `stop_hook_active` is true) with a structured reason like: "Before stopping, provide a status summary:\n\n**Status**: [what was accomplished]\n**Blocking?**: [yes/no — if yes, what decision is needed]\n**Next**: [done / needs more direction / specific next step]"

When `stop_hook_active` is true (second attempt), allow it — the message Claude just produced IS the status summary.

**Pros**: Guarantees a status summary every time. No LLM needed. Template ensures consistent structure. Dead simple.
**Cons**: Adds one extra round-trip to every stop (Claude has to respond once more). Could feel annoying for quick Q&A interactions.

## Recommendation

**Approach 3** is the most reliable. It's deterministic, needs no LLM, and produces consistent output. The one-extra-turn cost is worth it for the visibility it gives you.

Mitigate the annoyance factor by only triggering on "substantive" sessions — skip the status block if the conversation has fewer than N tool calls or the last message is very short (quick answer to a question).

Optionally combine with **Approach 2** (CLAUDE.md instruction) as a nudge so Claude often includes it naturally, reducing how often the hook has to bounce.
