# The engine: cavemanloverboy/vanity at 4e0f88d

Our GPUs search with [`cavemanloverboy/vanity`](https://github.com/cavemanloverboy/vanity) v0.9.1, pinned to commit [`4e0f88d60f16f4e5336b2d688c119dd96173834e`](https://github.com/cavemanloverboy/vanity/tree/4e0f88d60f16f4e5336b2d688c119dd96173834e). It's open source under Apache-2.0. Our build fetches exactly that commit, stops if the checkout differs, and compiles it with `cargo build --locked`, so every Rust dependency matches the upstream lockfile.

Vanity generators fail in one classic way: weak seeds. In 2022 the Ethereum generator Profanity was found to seed its search with only 32 bits of randomness, which let attackers recompute keys and drain wallets. So the first thing we checked is where this engine's randomness comes from, and then every path a key takes.

## What we checked

- **Seeds come from the operating system's cryptographic random generator.** [`new_gpu_seed`](https://github.com/cavemanloverboy/vanity/blob/4e0f88d60f16f4e5336b2d688c119dd96173834e/src/main.rs#L1837) draws a fresh `rand::random::<[u8; 32]>()` for every run and hashes it with the GPU's ID. The lockfile pins `rand` 0.8.5, `rand_chacha` 0.3.1 and `getrandom` 0.2.15: a ChaCha generator seeded by the OS. No timestamps, counters or small integers.
- **The GPU makes standard Solana keys.** The [CUDA kernel](https://github.com/cavemanloverboy/vanity/blob/4e0f88d60f16f4e5336b2d688c119dd96173834e/kernels/vanity_keypair.cu#L297) hashes that 256-bit run seed with each thread's index into a 32-byte Ed25519 seed, expands it with SHA-512, applies standard Ed25519 clamping and computes the public key. Each thread's next candidate seed is the upper half of its previous SHA-512 digest.
- **Every winning key is checked twice.** The [Rust result path](https://github.com/cavemanloverboy/vanity/blob/4e0f88d60f16f4e5336b2d688c119dd96173834e/src/main.rs#L1330) recomputes the key with `ed25519-dalek` and rechecks the pattern. Then our worker checks it again with a separate library (libsodium via PyNaCl), makes a test signature and checks your word ([`grinder.verify_keypair`](worker/grinder.py)).
- **Keys go to one owner-only file and nowhere else.** [`save_keypair`](https://github.com/cavemanloverboy/vanity/blob/4e0f88d60f16f4e5336b2d688c119dd96173834e/src/main.rs#L1668) writes the standard 64-byte keypair array to `<address>.json` with mode 0600. Our worker points it at a fresh directory on a RAM disk for each job and deletes the directory as soon as it has read the key.
- **No network code in the engine we build.** Solana RPC and deployment code sit behind the crate's `deploy` feature. We build only the `gpu` feature and run only `grind-keypair`: no RPC URL, wallet, funding or transactions. The worker process around it only receives jobs and returns sealed results.
- **No downloaded binaries in the build.** The [build script](https://github.com/cavemanloverboy/vanity/blob/4e0f88d60f16f4e5336b2d688c119dd96173834e/build.rs) compiles the CUDA sources in the repository.

## How we run it

- **One key per fresh run.** Because each candidate seed follows from the one before it, anyone who saw one seed could compute the later candidates in that thread's chain. So the worker runs the engine as a fresh process with a fresh random seed for every job and takes exactly one result from it. Your key never shares a chain with anyone else's.
- **One release binary, pinned by hash.** Our release build refuses any engine binary whose SHA-256 isn't `a37ff180487d7babf250d4fc2871d36c48173b5a196511a664a19288c14ed0f1`.

## Tests

The pinned engine passes its 15 upstream CPU tests, including comparisons against `ed25519-dalek`. On real GPU searches, our worker independently verified every key and signature the engine returned.

This is our own review of the code paths that create and handle keys, not a third-party audit.
