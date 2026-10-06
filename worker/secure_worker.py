"""Encrypt each verified result before it leaves the trusted GPU worker.

This is encrypted delivery, NOT confidential computing. The GPU and Python
process possess the seed. API/result storage receive only JWE ciphertext.
"""

import base64
import json
import re
import uuid

from jwcrypto import jwe, jwk

from grinder import grind, validate_input

PROTOCOL = "notrandom-v1"


def validate_recipient(value):
    if not isinstance(value, dict) or set(value) != {"kty", "n", "e"}:
        raise ValueError("recipient must contain only public RSA fields")
    if value["kty"] != "RSA" or value["e"] != "AQAB":
        raise ValueError("RSA-OAEP-256 recipient with exponent 65537 required")
    if not isinstance(value["n"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{512,684}", value["n"]):
        raise ValueError("invalid RSA modulus")
    modulus = base64.urlsafe_b64decode(value["n"] + "=" * (-len(value["n"]) % 4))
    if len(modulus) not in (384, 512) or int.from_bytes(modulus, "big").bit_length() not in (3072, 4096):
        raise ValueError("RSA key must be 3072 or 4096 bits")
    key = jwk.JWK(**value)
    return key, key.thumbprint()


def handle_secure_job(job):
    data = job.get("input") if isinstance(job, dict) else None
    if not isinstance(data, dict) or set(data) != {
        "protocol",
        "order_id",
        "recipient_jwk",
        "request",
        "shard",
        "request_hash",
    }:
        raise ValueError("invalid secure worker request")
    if data["protocol"] != PROTOCOL:
        raise ValueError("unsupported protocol")
    if not isinstance(data["order_id"], str) or str(uuid.UUID(data["order_id"])) != data["order_id"]:
        raise ValueError("invalid order id")
    # Match the API's safe-integer shard IDs. Fleet size is enforced by the
    # coordinator; each worker still accepts exactly one GPU and one result.
    if type(data["shard"]) is not int or not 0 <= data["shard"] <= 2**53 - 1:
        raise ValueError("invalid shard")
    if not isinstance(data["request_hash"], str) or not re.fullmatch(r"[0-9a-f]{64}", data["request_hash"]):
        raise ValueError("invalid request binding")
    recipient, thumbprint = validate_recipient(data["recipient_jwk"])
    request = validate_input(data["request"])
    if request["count"] != 1 or request["gpus"] != 1 or request["cpu_threads"] != 1 or request["suffix"]:
        raise ValueError("this worker accepts one prefix-only result per GPU")
    result = grind(request)
    wallets = result.pop("wallets")
    envelope = None
    if wallets:
        wallet = wallets[0]
        payload = json.dumps(
            {
                "protocol": PROTOCOL,
                "order_id": data["order_id"],
                "request_hash": data["request_hash"],
                "request": request,
                "public_key": wallet["public_key"],
                "keypair": wallet["keypair"],
            },
            separators=(",", ":"),
        ).encode()
        protected = {
            "alg": "RSA-OAEP-256",
            "enc": "A256GCM",
            "typ": "notrandom-result+jwe",
            "kid": thumbprint,
        }
        encrypted = jwe.JWE(payload, protected=protected, algs=["RSA-OAEP-256", "A256GCM"])
        encrypted.add_recipient(recipient)
        envelope = {
            "protocol": PROTOCOL,
            "order_id": data["order_id"],
            "public_key": wallet["public_key"],
            "recipient_thumbprint": thumbprint,
            "jwe": encrypted.serialize(compact=True),
        }
        # Best effort only: Python and the GPU do not promise verifiable erasure.
        for wallet in wallets:
            wallet["keypair"][:] = [0] * 64
        del payload, encrypted, wallets
    return {
        **result,
        "protocol": PROTOCOL,
        "order_id": data["order_id"],
        "shard": data["shard"],
        "result": envelope,
    }
