import { spawnSync } from "child_process";
import { readdirSync, renameSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
process.chdir(resolve(scriptDir, "../falcon"));
const srcFiles = [];

for (const file of readdirSync(".")) {
  if (file.endsWith(".c")) {
    srcFiles.push(file);
  }
}

const exportedFunctions = [
  "falcon_det1024_sign_compressed",
  "falcon_det1024_verify_compressed",
  "shake256_init_prng_from_seed",
  "falcon_det1024_keygen",
  "malloc",
  "free",
]
  .map((f) => `_${f}`)
  .join(",");

const emccArgs = [
  "-O3",
  "-s", "WASM=1",
  "-s", `EXPORTED_FUNCTIONS=[${exportedFunctions}]`,
  "-s", "EXPORTED_RUNTIME_METHODS=[HEAPU8,HEAPU32]",
  "-s", "STACK_SIZE=262144",
  "-s", "MODULARIZE=1",
  "-s", "EXPORT_ES6=1",
  "-s", "ENVIRONMENT=web,worker",
  "-s", "WASM_ASYNC_COMPILATION=1",
  "-s", "DYNAMIC_EXECUTION=0",
  "-o", "falcon_wasm.js",
  ...srcFiles,
];

const dockerArgs = [
  "run", "--rm",
  "-v", `.:/src`,
  "-u", `${process.getuid?.() || 1000}:${process.getgid?.() || 1000}`,
  "-w", "/src",
  "emscripten/emsdk:5.0.7",
  "emcc",
  ...emccArgs,
];

console.log(`Running docker ${dockerArgs.join(" ")}`);
const result = spawnSync("docker", dockerArgs, { stdio: 'inherit' });

if (result.error) {
  throw new Error(`Failed to run Docker: ${result.error.message}. Make sure Docker is installed and running.`);
}

if (result.status !== 0) {
  throw new Error(`Docker command failed with exit code ${result.status}. Check that the emscripten/emsdk:5.0.7 image is available and emcc compilation succeeded.`);
}

renameSync("falcon_wasm.js", "../src/falcon_wasm.js")
renameSync("falcon_wasm.wasm", "../src/falcon_wasm.wasm")
