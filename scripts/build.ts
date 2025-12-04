import { $, Glob } from "bun";
import path from "path";

const glob = new Glob("*.c");
const falcon_dir = path.join(__dirname, "..", "falcon");
const srcFiles = [];

for (const file of glob.scanSync(falcon_dir)) {
  srcFiles.push(file);
}

const exportedFunctions = [
  "falcon_det1024_sign_compressed",
  "falcon_det1024_verify_compressed",
  "shake256_init_prng_from_seed",
  "falcon_det1024_keygen",
  "malloc",
  "free",
]
  .map((f) => `"_${f}"`)
  .join(", ");

process.chdir(falcon_dir);

const args = [
  "-O3",
  ["-s", "WASM=1"],
  ["-s", `EXPORTED_FUNCTIONS=[${exportedFunctions}]`],
  ["-s", `EXPORTED_RUNTIME_METHODS=["HEAPU8", "HEAPU32"]`],
  ["-s", "STACK_SIZE=262144"],
  ["-s", "MODULARIZE=1"],
  ["-s", "EXPORT_ES6=1"],
  ["-s", "ENVIRONMENT=web,worker"],
  ["-o", "../src/falcon_wasm.js"],
].flat();

await $`emcc ${srcFiles} ${args}`;
