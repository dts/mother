import { createHash } from "crypto";
import { tmpdir } from "os";

const instanceHash = createHash("sha1").update(import.meta.dir).digest("hex").slice(0, 10);
const tempDir = tmpdir();

export const DEFAULT_PROVIDER_MODE = "auto";
export const DEFAULT_INSTANCE_NAME = `mother-${instanceHash}`;
export const DEFAULT_SOCKET_PATH = `${tempDir}/${DEFAULT_INSTANCE_NAME}.sock`;
export const DEFAULT_PID_FILE = `${tempDir}/${DEFAULT_INSTANCE_NAME}.pid`;
export const SERVER_DIR = import.meta.dir;
