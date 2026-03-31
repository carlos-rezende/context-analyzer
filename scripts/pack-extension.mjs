/**
 * Cria um .zip do conteúdo de `dist/` na raiz do projeto (upload Chrome Web Store).
 * Requer build prévio: pnpm run build
 */
import { readFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// dirname(import.meta.url) = pasta scripts/; dirname disso = raiz do projeto
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const distDir = join(root, "dist");

if (!existsSync(distDir)) {
  console.error("Pasta dist/ não encontrada. Execute: pnpm run build");
  process.exit(1);
}

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const version = pkg.version;
const zipName = `context-analyzer-v${version}.zip`;
const outPath = join(root, zipName);

const r = spawnSync("tar", ["-a", "-c", "-f", outPath, "-C", "dist", "."], {
  cwd: root,
  stdio: "inherit",
  shell: false,
});

if (r.status !== 0) {
  process.exit(r.status ?? 1);
}

console.log(`Criado: ${zipName}`);
