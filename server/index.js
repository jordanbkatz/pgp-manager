import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { createApp } from "./app.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const port = Number(process.env.PORT || 3419);
const app = await createApp({
  dataDirectory: process.env.PGP_DATA_DIR || path.join(root, "data"),
});
let vite;
if (process.argv.includes("--dev")) {
  const { createServer } = await import("vite");
  vite = await createServer({
    root,
    server: { middlewareMode: true, ws: { port: 3420, host: "127.0.0.1" } },
    appType: "spa",
  });
  app.use(vite.middlewares);
} else {
  app.use((req, res, next) => {
    res.set(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    );
    next();
  });
  app.use(express.static(path.join(root, "dist")));
  app.get("/{*path}", (req, res) =>
    res.sendFile(path.join(root, "dist", "index.html")),
  );
}
const server = app.listen(port, "127.0.0.1", () =>
  console.log(`PGP Manager is ready at http://127.0.0.1:${port}`),
);
server.on("error", (error) => {
  console.error(error.message);
  process.exit(1);
});
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, async () => {
    if (vite) await vite.close();
    server.close(() => process.exit(0));
  });
