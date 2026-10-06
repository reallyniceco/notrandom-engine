# notrandom-v1

How notrandom.fun makes your vanity key and gets it to you so that only your browser can open it. This is the exact protocol the website, our API and the GPU worker speak. [`verify/notrandom_verify.py`](verify/notrandom_verify.py) implements the customer's side of it in about 300 lines.

## The three parties

| Party | Runs | Holds |
| --- | --- | --- |
| **Your browser** | the notrandom.fun page | your lock and its key, your recovery file, and in the end your wallet key |
| **Our API** | `https://notrandom.fun/api` | your order, your lock (public half only) and, once found, your **sealed** result |
| **GPU worker** | [`worker/`](worker/) on our GPUs | your lock, the search, and your new key until it seals it |

"Lock" means an RSA public key and "key" means its private half. Anyone can seal something with your lock; only your key opens it.

## 1. Before you pay: your browser makes a lock

For every order, your browser creates, with its own cryptographic random number generator:

| Value | What it is | Sent to us? |
| --- | --- | --- |
| `id` | a random UUID for the order | yes |
| `token` | 32 random bytes, base64url (43 characters); proves the order is yours | yes, as `Authorization: Bearer`. The API stores only its SHA-256 hash |
| `recipient` | your lock: an RSA-OAEP-256 public key, 3072 bits, as `{"kty":"RSA","n":"…","e":"AQAB"}` | yes |
| `private_jwk` | the key to your lock | **never** |

It saves all of this as your **recovery record**: in this browser's local storage, and as a file when you click **Download recovery file**. The record also holds your request, the request hash and the lock's ID (below). Your browser never sends the recovery record or `private_jwk` anywhere.

### Request hash and key ID

Two values tie everything that follows to this exact order and this exact lock:

```text
recipient_thumbprint = base64url(SHA-256('{"e":"AQAB","kty":"RSA","n":"<n>"}'))     (RFC 7638)
request_hash         = hex(SHA-256(JSON.stringify({ request, recipient })))
```

`request` has exactly seven fields in this order: `input`, `case_sensitive`, `estimated_time`, `estimated_cost`, `rush`, `type`, `buyer`. `recipient` has `kty`, `n`, `e` in that order. Numbers use JavaScript's `JSON.stringify` formatting; the verifier reproduces it exactly.

## 2. Creating the order

Your browser sends `POST /api/v1/wallet` (or `/v1/coin`) with the seven request fields as the body and these headers:

| Header | Value |
| --- | --- |
| `X-Request-Id` | `id` |
| `Authorization` | `Bearer <token>` |
| `X-Recipient-Key` | standard Base64 of the `recipient` JSON: your lock |
| `X-Turnstile-Token` | a bot check for this order |

The API accepts only a public RSA key of 3072 or 4096 bits with exponent 65537, and test-encrypts to it before saving the order. It computes `request_hash` and `recipient_thumbprint` itself and returns both on every order read, so your browser (and the verifier) can confirm we saved your lock, not another one.

Payment follows: one SOL transfer from your wallet, which your browser checks before your wallet signs it. The GPU search starts only after Solana finalizes that payment.

## 3. The GPU worker finds your address and seals the key

The API sends each GPU job exactly these six fields, and [`secure_worker.handle_secure_job`](worker/secure_worker.py) rejects anything else before it searches:

```json
{
  "protocol": "notrandom-v1",
  "order_id": "<id>",
  "recipient_jwk": { "kty": "RSA", "n": "<n>", "e": "AQAB" },
  "request_hash": "<request_hash>",
  "shard": 0,
  "request": { "prefix": "<word>", "suffix": "", "case_insensitive": true, "count": 1,
               "max_seconds": <time limit>, "gpus": 1, "cpu_threads": 1 }
}
```

Every job does the same thing:

1. **Accepts only a lock.** `validate_recipient` requires exactly `kty`, `n` and `e`, so a private key or anything extra is refused, and checks the key is RSA 3072 or 4096 bits with `e = 65537`.
2. **Searches in RAM.** `grind` runs the pinned [`cavemanloverboy/vanity`](https://github.com/cavemanloverboy/vanity/tree/4e0f88d60f16f4e5336b2d688c119dd96173834e) engine (`grind-keypair`, one result) in a fresh directory on a RAM disk (`/dev/shm`), with owner-only permissions. Its console output goes to a private temporary file, and only attempt counts and known error types ever leave it. The worker process runs with core dumps turned off, so a crash can't write memory to disk.
3. **Checks the key independently.** `verify_keypair` re-derives the public key from the 32-byte seed with libsodium (PyNaCl), checks it against the address and your word, and makes a test signature. The engine already checked it once; this is a second implementation.
4. **Deletes the key file.** The search directory disappears as soon as the key has been read.
5. **Seals the key with your lock.** It encrypts this JSON:

   ```json
   { "protocol": "notrandom-v1", "order_id": "<id>", "request_hash": "<request_hash>",
     "request": { "...": "the job's request" }, "public_key": "<address>", "keypair": [64 bytes] }
   ```

   as a compact JWE ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516)): a fresh AES-256-GCM key encrypts the JSON, and RSA-OAEP-256 with your lock wraps that AES key. The protected header is exactly `{"alg":"RSA-OAEP-256","enc":"A256GCM","typ":"notrandom-result+jwe","kid":"<recipient_thumbprint>"}`.
6. **Returns only the sealed copy.** The job's output is attempt counts, timing and this envelope:

   ```json
   { "protocol": "notrandom-v1", "order_id": "<id>", "public_key": "<address>",
     "recipient_thumbprint": "<recipient_thumbprint>", "jwe": "<compact JWE>" }
   ```

   The worker then zeroes the key bytes it kept and discards the plaintext. `keypair` never appears in the output, and the worker's tests assert that.

`keypair` is 64 bytes: the 32-byte Ed25519 seed followed by the 32-byte public key, the standard Solana CLI keypair format. Its Base58 encoding is what Phantom, Solflare and Backpack import. For a coin order it is the mint key, and your browser signs the pump.fun launch with it locally.

## 4. Our API delivers the sealed copy

The API stores the envelope with your order and returns it as `result` on `GET /api/v1/orders/{id}` to anyone holding the order's bearer token. It deletes results seven days after completion. The API never has your lock's key, so it can't open the envelope. Nothing between the GPU and your browser ever carries more than the envelope.

## 5. Your browser opens and checks it

[`notrandom_verify.py`](verify/notrandom_verify.py) accepts a result only if every check below passes. Your browser runs checks 2–7 before it shows you anything.

1. The order's `request_hash` and `recipient_thumbprint` equal the ones in your recovery record: the API holds your request and your lock.
2. The envelope's `protocol`, `order_id` and `recipient_thumbprint` match your order.
3. The JWE header is exactly the one above, with `kid` equal to your lock's ID, and nothing else.
4. Your key unwraps the AES key, and AES-GCM authenticates the whole message, so any change to the ciphertext or header fails.
5. Inside, `protocol`, `order_id` and `request_hash` match your order, and `public_key` matches the envelope.
6. The seed re-derives exactly the 32-byte public key stored after it, whose Base58 is the address.
7. The address starts with your word (ignoring case unless you chose case-sensitive).

The verifier also makes a test signature with the key, and checks that your recovery file's key really opens its lock.

## What each party ever holds

| | Your browser | Our servers | GPU worker |
| --- | --- | --- | --- |
| Your lock's key (`private_jwk`) | ✓ | never | never |
| Your wallet or mint key | ✓ once opened | sealed copy only | in RAM, until it seals it |
| Your address | ✓ | ✓ | ✓ |
| Your order token | ✓ | SHA-256 hash only | never |
