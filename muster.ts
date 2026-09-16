/**
 * Push status updates to the Muster app by writing the same key=value
 * file format the bundled `muster` shell script writes. Reimplemented
 * here so mother doesn't have a runtime dependency on Muster being
 * installed.
 *
 * Fails safe in every direction:
 *   - neither $MUSTER_CHECKOUT nor $MUSTER_TERMINAL set → no-op (outside Muster)
 *   - File IO failure → swallowed (a hook crash is worse than a stale dot)
 *   - Never throws
 */

import { createHash } from "crypto";
import { homedir } from "os";
import { mkdir, writeFile, rename, readFile } from "fs/promises";
import { join } from "path";

export type MusterState = "idle" | "working" | "permission";

const DEFAULT_SESSIONS_DIR = join(
  homedir(),
  "Library/Application Support/Muster/sessions",
);

function sessionsDir(): string {
  return process.env.MUSTER_SESSIONS_DIR || DEFAULT_SESSIONS_DIR;
}

function checkoutKey(checkout: string): string {
  return createHash("sha256").update(checkout).digest("hex").slice(0, 16);
}

function sanitize(s: string): string {
  // Status records are newline-delimited; strip newlines from values.
  return s.replace(/[\r\n]+/g, " ");
}

async function readExistingTitle(file: string): Promise<string | undefined> {
  try {
    const text = await readFile(file, "utf8");
    for (const line of text.split("\n")) {
      const eq = line.indexOf("=");
      if (eq < 0) continue;
      if (line.slice(0, eq) === "title") return line.slice(eq + 1);
    }
  } catch {
    // No existing file — that's fine.
  }
  return undefined;
}

export async function notifyMuster(
  state: MusterState,
  message?: string,
): Promise<void> {
  // Muster launches repo sessions with MUSTER_CHECKOUT but terminal sessions
  // with only MUSTER_TERMINAL. Both are keyed the same way on Muster's side
  // (sha256 of the path, stored under `checkout=`), so falling back keeps the
  // dot working in terminals instead of silently doing nothing there.
  const checkout = process.env.MUSTER_CHECKOUT || process.env.MUSTER_TERMINAL;
  if (!checkout) return;

  try {
    const dir = sessionsDir();
    await mkdir(dir, { recursive: true });

    const file = join(dir, `${checkoutKey(checkout)}.txt`);
    const tmp = `${file}.tmp.${process.pid}`;

    const title = await readExistingTitle(file);

    const lines: string[] = [`checkout=${sanitize(checkout)}`, `state=${state}`];
    if (message) lines.push(`message=${sanitize(message)}`);
    if (title) lines.push(`title=${sanitize(title)}`);
    lines.push(`updated_at=${new Date().toISOString()}`);

    await writeFile(tmp, lines.join("\n") + "\n");
    await rename(tmp, file);
  } catch {
    // Never break the hook over a status update.
  }
}
