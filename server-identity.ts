import { createHash } from "crypto";
import { tmpdir } from "os";

const instanceHash = createHash("sha1").update(import.meta.dir).digest("hex").slice(0, 10);
const tempDir = tmpdir();
const configuredProvider = (process.env.MOTHER_LLM_BACKEND || process.env.MOTHER_EVAL_PROVIDER || process.env.MOTHER_PROVIDER || "auto").toLowerCase();
const providerSlug = configuredProvider === "anthropic"
  ? "claude"
  : configuredProvider === "openai"
    ? "codex"
    : configuredProvider.replace(/[^a-z0-9_-]/g, "-");

export const DEFAULT_PROVIDER_MODE = providerSlug || "auto";
export const DEFAULT_INSTANCE_NAME = `mother-${instanceHash}-${DEFAULT_PROVIDER_MODE}`;
export const DEFAULT_SOCKET_PATH = `${tempDir}/${DEFAULT_INSTANCE_NAME}.sock`;
export const DEFAULT_PID_FILE = `${tempDir}/${DEFAULT_INSTANCE_NAME}.pid`;
export const SERVER_DIR = import.meta.dir;
