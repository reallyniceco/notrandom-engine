# How notrandom.fun protects your key

This is the code that handles your private key at [notrandom.fun](https://notrandom.fun), published so you can see exactly what happens to it. It isn't an open-source product. It's here so you, or anyone you trust (a developer friend, an auditor or an AI assistant), can read it and confirm we don't keep your key.

## How your key stays yours

1. **Your browser makes a lock.** Before you pay, it creates an RSA-3072 key pair for your order. It sends us the public half (the lock) and keeps the private half (the key) on your device.
2. **Our GPU finds your address and seals it on the spot.** The worker runs the open-source [`vanity`](https://github.com/cavemanloverboy/vanity) engine on a RAM disk, checks the key it finds with a second library, and encrypts it with your lock before anything leaves the machine.
3. **Only your browser can open it.** Our servers only ever hold the sealed copy. Your browser opens it, checks it, and hands you your key.

## What's here

| Path | What it is |
| --- | --- |
| [`worker/secure_worker.py`](worker/secure_worker.py), [`worker/grinder.py`](worker/grinder.py) | The code our GPUs run on your key, byte for byte, with its tests. About 300 lines. |
| [`verify/notrandom_verify.py`](verify/notrandom_verify.py) | Checks your order on your own computer, using your recovery file |
| [PROTOCOL.md](PROTOCOL.md) | Every step and field, and what each party ever holds |
| [ENGINE-REVIEW.md](ENGINE-REVIEW.md) | How the engine makes keys, and what we checked |

We update `worker/` with every release, so it always matches what our GPUs run.

## Check it yourself

### 1. Read the worker

Start with [`secure_worker.py`](worker/secure_worker.py):

- `validate_recipient` accepts only a public RSA key (3072 or 4096 bits). Hand it a private key and it refuses the job.
- `handle_secure_job` seals the key with your lock (RSA-OAEP-256 + AES-256-GCM) and returns only that sealed copy, plus attempt counts and timing.

Then [`grinder.py`](worker/grinder.py): `grind` runs the engine in a fresh directory on a RAM disk, keeps its console output in a private temporary file, re-verifies each key with libsodium and deletes the directory once it has read the key.

To run the tests (Python 3.12):

```sh
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes -r worker/requirements.txt
.venv/bin/pip install pytest==9.1.1
.venv/bin/python -m pytest
```

### 2. Check the engine

The worker runs [`cavemanloverboy/vanity`](https://github.com/cavemanloverboy/vanity/tree/4e0f88d60f16f4e5336b2d688c119dd96173834e), pinned to one reviewed commit. [ENGINE-REVIEW.md](ENGINE-REVIEW.md) covers where its randomness comes from (the operating system's cryptographic generator) and every path a key takes.

### 3. Check your own order

You need two files:

- **Your recovery file.** At checkout, click **Download recovery file**.
- **Your order.** Once your order completes, open notrandom.fun with your browser's developer tools on the **Network** tab. Find the request to `orders/<your order ID>`, copy its response and save it as `order.json`.

Then, in [`verify/`](verify/) (Python 3.10 or later):

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.txt
.venv/bin/python notrandom_verify.py ~/Downloads/notrandom-order-….json order.json
```

```text
✓ Order 9f1c…: this file holds your RSA-3072 lock and the key that opens it.
✓ The order's request hash and key ID match this file.
✓ Our API stored your lock and your request, unchanged.
✓ The result is sealed to your lock, and nothing altered it.
✓ Inside: a private key that produces its address and signs for it.
✓ The address starts with 'NoTR4nd'.

Your address: NoTR4nd…
```

The verifier never touches the network. We wrote it separately from the website, and its only dependency is the [`cryptography`](https://cryptography.io) package, so it's a second, independent check. Add `--save-keypair wallet.json` to also save your wallet as a Solana CLI keypair file that only you can read: you can recover your key without our website.

### 4. Check what the website can talk to

```sh
curl -sI https://notrandom.fun | grep -i content-security-policy
```

Your browser enforces that policy on every notrandom.fun page. It lets the page load code only from notrandom.fun and Cloudflare's Turnstile bot check, and connect only to notrandom.fun and the public Solana RPC. In the **Network** tab you can watch your order go out: the `X-Recipient-Key` header carries your lock, and no request ever carries its key.

## What you're trusting

- **The GPU, briefly.** Whoever makes a key holds it at that moment; that's true of every service that generates keys for you. Our worker holds yours in RAM only until it checks and seals it, and this is the code that does it.
- **That we run this code.** Our GPUs run `secure_worker.py` and `grinder.py` exactly as they are here, with these dependency versions and the engine binary pinned by SHA-256 ([ENGINE-REVIEW.md](ENGINE-REVIEW.md)).
- **The website.** It runs in your browser: step 4 shows everything it can reach, and step 3 checks its work.

## Licence

You may read and run this code, test it, and use it to check your orders. It's licensed under the [PolyForm Shield License 1.0.0](LICENSE.md), which doesn't allow using it for a competing service. The engine, `cavemanloverboy/vanity`, is Apache-2.0 and isn't part of this repository.
