import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "crypto";
import { mkdtemp, readFile, rm, readdir } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { notifyMuster } from "./muster";

const saved = {
  dir: process.env.MUSTER_SESSIONS_DIR,
  checkout: process.env.MUSTER_CHECKOUT,
  terminal: process.env.MUSTER_TERMINAL,
};
let dir: string;

const keyFor = (p: string) => createHash("sha256").update(p).digest("hex").slice(0, 16);
const readState = async (p: string) => readFile(join(dir, `${keyFor(p)}.txt`), "utf8");

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "mother-muster-test-"));
  process.env.MUSTER_SESSIONS_DIR = dir;
  delete process.env.MUSTER_CHECKOUT;
  delete process.env.MUSTER_TERMINAL;
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
  for (const [k, v] of [["MUSTER_SESSIONS_DIR", saved.dir], ["MUSTER_CHECKOUT", saved.checkout], ["MUSTER_TERMINAL", saved.terminal]] as const) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
});

describe("muster status notifications", () => {
  test("writes state for a checkout session", async () => {
    process.env.MUSTER_CHECKOUT = "/tmp/fake-checkout";
    await notifyMuster("permission", "needs review");
    const text = await readState("/tmp/fake-checkout");
    expect(text).toContain("state=permission");
    expect(text).toContain("checkout=/tmp/fake-checkout");
  });

  test("writes state for a terminal session", async () => {
    // Muster launches terminal sessions with MUSTER_TERMINAL and no
    // MUSTER_CHECKOUT, so these used to no-op and the dot never lit.
    process.env.MUSTER_TERMINAL = "/Users/dts/code";
    await notifyMuster("permission", "needs review");
    const text = await readState("/Users/dts/code");
    expect(text).toContain("state=permission");
    expect(text).toContain("checkout=/Users/dts/code");
  });

  test("prefers the checkout when both are set", async () => {
    process.env.MUSTER_CHECKOUT = "/tmp/co";
    process.env.MUSTER_TERMINAL = "/tmp/term";
    await notifyMuster("working");
    expect(await readState("/tmp/co")).toContain("checkout=/tmp/co");
    expect(await readdir(dir)).toHaveLength(1);
  });

  test("stays a no-op outside any Muster session", async () => {
    await notifyMuster("permission", "needs review");
    expect(await readdir(dir)).toHaveLength(0);
  });
});
