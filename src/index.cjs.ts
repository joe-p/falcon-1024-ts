// CommonJS entry point.
//
// CommonJS cannot contain top-level `await`, so this build uses the synchronous
// Emscripten glue (`WASM_ASYNC_COMPILATION=0`, with the factory's `async`
// keyword stripped by the build). CJS only runs under Node, which — unlike a
// browser main thread — places no size limit on synchronous WASM compilation.
// The WASM is embedded in the glue (SINGLE_FILE), so nothing is fetched.
import createModule from "./falcon_wasm_sync.js";
import { makeApi } from "./falcon-core";

const module = createModule();
const api = makeApi(module);

export const generateKey = api.generateKey;
export const signCompressed = api.signCompressed;
export const verifyCompressed = api.verifyCompressed;

export {
  FALCON_DET1024_PUBKEY_SIZE,
  FALCON_DET1024_PRIVKEY_SIZE,
  FALCON_DET1024_SIG_COMPRESSED_MAXSIZE,
  KeygenError,
  SigningError,
  VerificationError,
} from "./falcon-core";
export type { FalconApi } from "./falcon-core";
