/**
 * Redimensiona e comprime o ícone da extensão (PNG).
 * Uso: pnpm run optimize:icon
 */
import { readFileSync, writeFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const target = join(root, "public", "icons", "context-analyzer.png");

const MAX_EDGE = 512;

const before = statSync(target).size;
const buf = readFileSync(target);

const meta = await sharp(buf).metadata();
const w = meta.width ?? MAX_EDGE;
const h = meta.height ?? MAX_EDGE;
const needsResize = w > MAX_EDGE || h > MAX_EDGE;

let pipeline = sharp(buf);
if (needsResize) {
  pipeline = pipeline.resize(MAX_EDGE, MAX_EDGE, {
    fit: "inside",
    withoutEnlargement: true,
  });
}

const out = await pipeline
  .png({
    compressionLevel: 9,
    adaptiveFiltering: true,
    effort: 10,
  })
  .toBuffer();

writeFileSync(target, out);

const after = statSync(target).size;
const pct = before > 0 ? Math.round((1 - after / before) * 100) : 0;
console.log(
  `context-analyzer.png: ${before} → ${after} bytes (~${pct}% menor, max ${MAX_EDGE}px)`,
);
