import createModule from "./falcon_wasm.js";

type FalconModule = any;

// Constants from deterministic.h and falcon.h
const FALCON_DET1024_LOGN = 10;

function falconPrivKeySize(logn: number): number {
  if (logn <= 3) {
    return (3 << logn) + 1;
  }
  return ((10 - (logn >> 1)) << (logn - 2)) + (1 << logn) + 1;
}

function falconPubKeySize(logn: number): number {
  if (logn <= 1) {
    return 4 + 1;
  }
  return (7 << (logn - 2)) + 1;
}

function falconSigCompressedMaxSize(logn: number): number {
  const value = (11 << logn) + (101 >> (10 - logn));
  return ((value + 7) >> 3) + 41;
}

export const FALCON_DET1024_PUBKEY_SIZE = falconPubKeySize(FALCON_DET1024_LOGN);
export const FALCON_DET1024_PRIVKEY_SIZE =
  falconPrivKeySize(FALCON_DET1024_LOGN);
export const FALCON_DET1024_SIG_COMPRESSED_MAXSIZE =
  falconSigCompressedMaxSize(FALCON_DET1024_LOGN) - 40 + 1;

const SHAKE256_CONTEXT_SIZE = 26 * 8;

const module: FalconModule = await createModule();

class FalconError extends Error {
  constructor(context: number | string) {
    if (typeof context === "string") {
      super(context);
      return;
    }

    if (context === -1) {
      super("OS random number generator failure");
    } else if (context === -2) {
      super("buffer too small");
    } else if (context === -3) {
      super("invalid format");
    } else if (context === -4) {
      super("bad signature");
    } else if (context === -5) {
      super("bad argument");
    } else if (context === -6) {
      super("internal error");
    } else {
      super(`unknown error code ${context}`);
    }
  }
}

class WasmPtr {
  ptr: number;
  name: string;
  size: number;

  constructor(name: string, size: number) {
    this.ptr = 0;
    this.name = name;
    this.size = size;
  }
}

/** Given the list of WasmPtr, allocates memory for each, runs the function, and frees the memory. This should be the ONLY function that _malloc and _free are called */
function withWasmAllocations<T>(variables: WasmPtr[], fn: () => T): T {
  try {
    for (const v of variables.filter((v) => v.size > 0)) {
      try {
        v.ptr = module._malloc(v.size);
      } catch (e) {
        throw new FalconError(`Failed to allocate memory for ${v.name}`);
      }
    }

    return fn();
  } finally {
    for (const v of variables) {
      if (v.ptr !== undefined && v.ptr !== 0) {
        try {
          module._free(v.ptr);
        } catch (e) {
          console.error(`Failed to free memory for ${v.name} (${v.ptr}):`, e);
        }
      }
    }
  }
}

export class KeygenError extends FalconError {
  constructor(context: number | string) {
    super(context);
    this.name = "KeygenError";
  }
}

export class SigningError extends FalconError {
  constructor(context: number | string) {
    super(context);
    this.name = "SigningError";
  }
}

export class VerificationError extends FalconError {
  constructor(context: number | string) {
    super(context);
    this.name = "VerificaitonError";
  }
}

/**
 * Generates a Falcon public/private key pair from the given seed.
 * @param seed - Optional seed bytes. If not provided, a random 48-byte seed will be generated.
 * @returns An object containing the publicKey and privateKey as Uint8Arrays.
 */
export function generateKey(seed?: Uint8Array): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  if (!seed || seed.length === 0) {
    seed = new Uint8Array(48);
    crypto.getRandomValues(seed);
  }
  const seedLen = seed.length;

  const rng = new WasmPtr("rng", SHAKE256_CONTEXT_SIZE);
  const seedAlloc = new WasmPtr("seed", seedLen);
  const privateKeyAlloc = new WasmPtr(
    "privateKey",
    FALCON_DET1024_PRIVKEY_SIZE,
  );
  const publicKeyAlloc = new WasmPtr("publicKey", FALCON_DET1024_PUBKEY_SIZE);

  return withWasmAllocations(
    [rng, seedAlloc, privateKeyAlloc, publicKeyAlloc],
    () => {
      module.HEAPU8.set(seed, seedAlloc.ptr);
      module._shake256_init_prng_from_seed(rng.ptr, seedAlloc.ptr, seedLen);

      const result = module._falcon_det1024_keygen(
        rng.ptr,
        privateKeyAlloc.ptr,
        publicKeyAlloc.ptr,
      );

      const publicKey = new Uint8Array(
        module.HEAPU8.buffer,
        publicKeyAlloc.ptr,
        FALCON_DET1024_PUBKEY_SIZE,
      ).slice();

      const privateKey = new Uint8Array(
        module.HEAPU8.buffer,
        privateKeyAlloc.ptr,
        FALCON_DET1024_PRIVKEY_SIZE,
      ).slice();

      if (result !== 0) {
        throw new KeygenError(result);
      }

      return { publicKey, privateKey };
    },
  );
}

/**
 * Signs a message with the given private key using compressed format.
 * @param privateKey - The private key (FALCON_DET1024_PRIVKEY_SIZE bytes).
 * @param message - The message to sign.
 * @returns The compressed signature as a Uint8Array.
 */
export function signCompressed(
  privateKey: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  if (privateKey.length !== FALCON_DET1024_PRIVKEY_SIZE) {
    throw new SigningError(
      `Invalid private key length: ${privateKey.length}. Expected ${FALCON_DET1024_PRIVKEY_SIZE}.`,
    );
  }

  const msgLen = message.length;

  const sigAlloc = new WasmPtr("sig", FALCON_DET1024_SIG_COMPRESSED_MAXSIZE);
  const sigLenAlloc = new WasmPtr("sigLen", 4); // size_t pointer
  const privateKeyAlloc = new WasmPtr(
    "privateKey",
    FALCON_DET1024_PRIVKEY_SIZE,
  );
  const msgAlloc = new WasmPtr("msg", msgLen);

  const allocations = [sigAlloc, sigLenAlloc, privateKeyAlloc, msgAlloc];

  return withWasmAllocations(allocations, () => {
    module.HEAPU8.set(privateKey, privateKeyAlloc.ptr);

    const msgPtr = msgAlloc.ptr;
    if (msgLen > 0) {
      module.HEAPU8.set(message, msgPtr);
    }

    const result = module._falcon_det1024_sign_compressed(
      sigAlloc.ptr,
      sigLenAlloc.ptr,
      privateKeyAlloc.ptr,
      msgPtr,
      msgLen,
    );

    const sigLen = module.HEAPU32[sigLenAlloc.ptr >> 2];

    const signature = new Uint8Array(
      module.HEAPU8.buffer,
      sigAlloc.ptr,
      sigLen,
    ).slice();

    if (result !== 0) {
      throw new SigningError(result);
    }

    return signature;
  });
}

/**
 * Verifies a compressed signature against a message and public key.
 * @param publicKey - The public key (FALCON_DET1024_PUBKEY_SIZE bytes).
 * @param signature - The compressed signature.
 * @param message - The original message.
 * @returns true if the signature is valid.
 * @throws VerifyError if verification fails.
 */
export function verifyCompressed(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): boolean {
  if (publicKey.length !== FALCON_DET1024_PUBKEY_SIZE) {
    throw new VerificationError(
      `Invalid public key length: ${publicKey.length}. Expected ${FALCON_DET1024_PUBKEY_SIZE}.`,
    );
  }

  if (signature.length === 0) {
    throw new VerificationError("Empty signature");
  }

  if (signature.length > FALCON_DET1024_SIG_COMPRESSED_MAXSIZE) {
    throw new VerificationError(
      `Invalid signature length: ${signature.length}. Maximum is ${FALCON_DET1024_SIG_COMPRESSED_MAXSIZE}.`,
    );
  }

  const msgLen = message.length;

  const sigAlloc = new WasmPtr("sig", signature.length);
  const publicKeyAlloc = new WasmPtr("publicKey", FALCON_DET1024_PUBKEY_SIZE);
  const msgAlloc = new WasmPtr("msg", msgLen);

  const allocations = [sigAlloc, publicKeyAlloc, msgAlloc];

  return withWasmAllocations(allocations, () => {
    module.HEAPU8.set(signature, sigAlloc.ptr);
    module.HEAPU8.set(publicKey, publicKeyAlloc.ptr);

    const msgPtr = msgAlloc.ptr;
    if (msgLen > 0) {
      module.HEAPU8.set(message, msgPtr);
    }

    const result = module._falcon_det1024_verify_compressed(
      sigAlloc.ptr,
      signature.length,
      publicKeyAlloc.ptr,
      msgPtr,
      msgLen,
    );

    if (result !== 0) {
      throw new VerificationError(result);
    }

    return true;
  });
}
