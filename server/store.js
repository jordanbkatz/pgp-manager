import {
  mkdir,
  readFile,
  writeFile,
  rename,
  chmod,
  unlink,
} from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";

// Mutations are serialized; atomic replacement keeps interrupted writes from damaging the vault.
export async function createStore(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
  const file = path.join(directory, "keys.json");
  let keys;
  try {
    keys = JSON.parse(await readFile(file, "utf8"));
    if (!Array.isArray(keys) || keys.some((key) => !key.id || !key.publicKey)) {
      throw new Error(
        "The local key vault is invalid. Restore data/keys.json from a backup.",
      );
    }
    await chmod(file, 0o600);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    keys = [];
    await writeFile(file, "[]\n", { mode: 0o600, flag: "wx" });
  }
  let pending = Promise.resolve();
  return {
    all: () => structuredClone(keys),
    get: (id) => structuredClone(keys.find((key) => key.id === id)),
    mutate(operation) {
      const result = pending.then(async () => {
        const next = structuredClone(keys);
        const value = await operation(next);
        const temporary = `${file}.${randomUUID()}.tmp`;
        try {
          await writeFile(temporary, `${JSON.stringify(next, null, 2)}\n`, {
            mode: 0o600,
            flag: "wx",
          });
          await rename(temporary, file);
        } finally {
          await unlink(temporary).catch(() => {});
        }
        keys = next;
        return value;
      });
      pending = result.catch(() => {});
      return result;
    },
  };
}
