import { spawnSync } from "child_process";
import { readdirSync, renameSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";

function run(cmd: string, args: string[]) {
  console.debug(`+${cmd} ${args.join(" ")}`);
  const result = spawnSync(cmd, args, { stdio: 'inherit' });
  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    throw new Error(`${cmd} exited with status code ${result.status}`);
  }

  return result;
}

const scriptDir = dirname(fileURLToPath(import.meta.url));

const emsdkBin = resolve(scriptDir, "../emsdk/emsdk");
const emsdkVersion = "5.0.7";

run("git", ["submodule", "update", "--init", "--recursive"]);
run(emsdkBin, ["install", emsdkVersion]);
run(emsdkBin, ["activate", emsdkVersion]);

try {
  process.chdir(resolve(scriptDir, "../falcon"));
} catch (error) {
  throw new Error(
    "Failed to enter the falcon directory. Make sure the falcon submodule is initialized: git submodule update --init"
  );
}

const srcFiles = [];

for (const file of readdirSync(".")) {
  if (file.endsWith(".c")) {
    srcFiles.push(file);
  }
}

srcFiles.sort();

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

const emccBin = resolve(scriptDir, "../emsdk/upstream/emscripten/emcc");
run(emccBin, emccArgs);

try {
  renameSync("falcon_wasm.js", "../src/falcon_wasm.js");
  renameSync("falcon_wasm.wasm", "../src/falcon_wasm.wasm");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  throw new Error(`Failed to move output files: ${message}. emcc may have succeeded but did not generate the expected falcon_wasm.js and falcon_wasm.wasm files.`);
}
